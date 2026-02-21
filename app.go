package main

import (
	"container/heap"
	"context"
	"fmt" // اضافه شده برای مدیریت ارورها
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// ----- CONFIG -----

type Config struct {
	MongoURI       string
	DBName         string
	JWTSecret      []byte
	Port           string
	WorkerCount    int
	JobWaitSeconds time.Duration
	AdminUsernames []string
	AdminEnvUser   string
	AdminEnvPass   string
}

var cfg Config
var mongoClient *mongo.Client
var db *mongo.Database

func loadConfig() {
	_ = godotenv.Load() // نادیده گرفتن ارور برای محیط‌هایی که فایل .env ندارند

	cfg.MongoURI = os.Getenv("MONGO_URI")
	if cfg.MongoURI == "" {
		log.Println("WARNING: MONGO_URI is missing")
	}
	cfg.JWTSecret = []byte(os.Getenv("JWT_SECRET_KEY"))
	if len(cfg.JWTSecret) == 0 {
		log.Println("WARNING: JWT_SECRET_KEY is missing, generic fallback used (NOT SAFE FOR PROD)")
		cfg.JWTSecret = []byte("default-insecure-secret")
	}

	cfg.DBName = os.Getenv("MONGO_DBNAME")
	if cfg.DBName == "" {
		cfg.DBName = "twomanga"
	}

	cfg.Port = os.Getenv("PORT")
	if cfg.Port == "" {
		cfg.Port = "5001"
	}

	wc, _ := strconv.Atoi(os.Getenv("WORKER_COUNT"))
	if wc <= 0 {
		wc = 4
	}
	cfg.WorkerCount = wc

	ws, _ := strconv.ParseFloat(os.Getenv("JOB_WAIT_SECONDS"), 64)
	if ws == 0 {
		ws = 8.0
	}
	cfg.JobWaitSeconds = time.Duration(ws * float64(time.Second))

	admins := os.Getenv("ADMIN_USERNAMES")
	cfg.AdminUsernames = []string{}
	for _, u := range strings.Split(admins, ",") {
		if t := strings.TrimSpace(u); t != "" {
			cfg.AdminUsernames = append(cfg.AdminUsernames, strings.ToLower(t))
		}
	}
	cfg.AdminEnvUser = strings.ToLower(os.Getenv("ADMIN_USERNAME"))
	cfg.AdminEnvPass = os.Getenv("ADMIN_PASSWORD")
}

// ----- DATABASE -----

func connectDB() {
	// افزایش تایم‌اوت اتصال برای سرورهای کند
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if cfg.MongoURI == "" {
		log.Fatal("Fatal: MongoURI is empty. Cannot connect to database.")
	}

	clientOptions := options.Client().ApplyURI(cfg.MongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Failed to create Mongo client: %v", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("MongoDB Ping Failed (Check network/credentials): %v", err)
	}

	mongoClient = client
	db = client.Database(cfg.DBName)
	log.Printf("Connected to MongoDB: %s", cfg.DBName)
}

// ----- MODELS -----

type User struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username       string             `bson:"username" json:"username"`
	Password       string             `bson:"password" json:"-"`
	Role           string             `bson:"role" json:"role"`
	SessionSalt    string             `bson:"session_salt" json:"-"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	TotalPurchases int                `bson:"total_purchases" json:"total_purchases"`
	ExpiryDate     *time.Time         `bson:"expiryDate,omitempty" json:"expiryDate,omitempty"`
}

type Coupon struct {
	ID        primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Code      string               `bson:"code" json:"code"`
	BonusDays int                  `bson:"bonus_days" json:"bonus_days"`
	MaxUses   *int                 `bson:"max_uses" json:"max_uses"`
	Uses      int                  `bson:"uses" json:"uses"`
	UsedBy    []primitive.ObjectID `bson:"used_by" json:"used_by"`
	ExpiresAt *time.Time           `bson:"expires_at" json:"expires_at"`
	CreatedAt time.Time            `bson:"created_at" json:"created_at"`
}

type Transaction struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID       primitive.ObjectID `bson:"user_id" json:"user_id"`
	Username     string             `bson:"username" json:"username"`
	TxHash       string             `bson:"tx_hash" json:"tx_hash"`
	Days         int                `bson:"days" json:"days"`
	Status       string             `bson:"status" json:"status"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	ProcessedAt  *time.Time         `bson:"processed_at,omitempty" json:"processed_at,omitempty"`
	ApprovedBy   string             `bson:"approved_by,omitempty" json:"approved_by,omitempty"`
	RejectedAt   *time.Time         `bson:"rejected_at,omitempty" json:"rejected_at,omitempty"`
	RejectedBy   string             `bson:"rejected_by,omitempty" json:"rejected_by,omitempty"`
	RejectReason string             `bson:"reject_reason,omitempty" json:"reject_reason,omitempty"`
}

// ----- UTILS -----

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ----- WORKER ENGINE (Safety Refactor) -----

type JobResult struct {
	Data interface{}
	Err  error
	Code int
}

type Job struct {
	Priority   int
	Sequence   int64
	Func       func() (interface{}, int, error)
	ResultChan chan JobResult
}

type PriorityQueue []*Job

func (pq PriorityQueue) Len() int { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool {
	if pq[i].Priority != pq[j].Priority {
		return pq[i].Priority > pq[j].Priority
	}
	return pq[i].Sequence < pq[j].Sequence
}
func (pq PriorityQueue) Swap(i, j int)       { pq[i], pq[j] = pq[j], pq[i] }
func (pq *PriorityQueue) Push(x interface{}) { *pq = append(*pq, x.(*Job)) }
func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

var (
	jobQueue   = make(PriorityQueue, 0)
	queueLock  sync.Mutex
	jobSignal  = make(chan struct{}, 1000)
	shutdownCh = make(chan struct{})
)

// safeExecWrap executes the task with panic recovery
func safeExecWrap(task func() (interface{}, int, error)) (data interface{}, code int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("PANIC in worker: %v", r)
			code = 500
			log.Printf("[CRITICAL] Worker Panic: %v", r)
		}
	}()
	return task()
}

func SubmitJob(priority int, task func() (interface{}, int, error), wait bool) (interface{}, int, error) {
	resChan := make(chan JobResult, 1)
	job := &Job{
		Priority:   priority,
		Sequence:   time.Now().UnixNano(),
		Func:       task,
		ResultChan: resChan,
	}

	queueLock.Lock()
	heap.Push(&jobQueue, job)
	queueLock.Unlock()

	select {
	case jobSignal <- struct{}{}:
	default:
		// Signal buffer full, worker will catch up
	}

	if !wait {
		return map[string]interface{}{"queued": true, "job_id": job.Sequence}, 202, nil
	}

	// Wait with timeout
	select {
	case res := <-resChan:
		return res.Data, res.Code, res.Err
	case <-time.After(cfg.JobWaitSeconds):
		return map[string]string{"msg": "Processing queued due to load (timeout)"}, 202, nil
	}
}

func startWorkers(count int) {
	for i := 0; i < count; i++ {
		go func(id int) {
			log.Printf("Worker-%d started", id)
			for {
				select {
				case <-shutdownCh:
					return
				case <-jobSignal:
					queueLock.Lock()
					if jobQueue.Len() == 0 {
						queueLock.Unlock()
						continue
					}
					// Double check nil or heap issues (safe with standard library but good to be sure)
					rawItem := heap.Pop(&jobQueue)
					queueLock.Unlock()

					if rawItem == nil {
						continue
					}
					item := rawItem.(*Job)

					// Execute safely (Recovery logic applied here)
					data, code, err := safeExecWrap(item.Func)

					if err != nil && data == nil {
						data = map[string]string{"msg": "Processing Error", "detail": err.Error()}
						if code == 0 {
							code = 500
						}
					}
					
					// Avoid blocking if receiver abandoned channel
					select {
					case item.ResultChan <- JobResult{Data: data, Code: code, Err: err}:
					default:
					}
					close(item.ResultChan)
				}
			}
		}(i)
	}
}

// ----- BUSINESS LOGIC -----

func logicApplyPayment(userIDStr string, couponCode, txHash string, daysReq int) (interface{}, int, error) {
	// استفاده از Context مجزا برای عملیات DB که طولانی می‌شود
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userOID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		return map[string]string{"msg": "Invalid user ID"}, 400, nil
	}

	// بررسی وجود db
	if db == nil {
		return nil, 500, fmt.Errorf("Database connection lost")
	}

	var user User
	err = db.Collection("users").FindOne(ctx, bson.M{"_id": userOID}).Decode(&user)
	if err != nil {
		return map[string]string{"msg": "User not found"}, 404, err
	}

	if couponCode != "" {
		couponColl := db.Collection("coupons")
		var cp Coupon

		err := couponColl.FindOne(ctx, bson.M{"code": couponCode}).Decode(&cp)
		if err != nil {
			return map[string]string{"msg": "Invalid coupon code"}, 400, nil
		}

		now := time.Now().UTC()
		if cp.ExpiresAt != nil && cp.ExpiresAt.Before(now) {
			// کوپن منقضی شده
			couponColl.DeleteOne(ctx, bson.M{"_id": cp.ID})
			return map[string]string{"msg": "Coupon expired"}, 400, nil
		}
		if cp.MaxUses != nil && cp.Uses >= *cp.MaxUses {
			couponColl.DeleteOne(ctx, bson.M{"_id": cp.ID})
			return map[string]string{"msg": "Coupon limits reached"}, 400, nil
		}
		
		// اطمینان از مقداردهی شدن UsedBy برای جلوگیری از پنیک در حلقه
		if cp.UsedBy == nil {
			cp.UsedBy = []primitive.ObjectID{}
		}

		for _, uID := range cp.UsedBy {
			if uID == userOID {
				return map[string]string{"msg": "You have already used this coupon"}, 400, nil
			}
		}

		// Optimistic locking
		filter := bson.M{
			"_id":     cp.ID,
			"uses":    cp.Uses, 
			"used_by": bson.M{"$ne": userOID},
		}
		update := bson.M{
			"$inc":  bson.M{"uses": 1},
			"$push": bson.M{"used_by": userOID},
		}

		var updatedCp Coupon
		err = couponColl.FindOneAndUpdate(ctx, filter, update, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&updatedCp)
		if err != nil {
			return map[string]string{"msg": "Coupon unavailable or usage conflict"}, 409, nil
		}

		startPoint := now
		if user.ExpiryDate != nil && user.ExpiryDate.After(now) {
			startPoint = *user.ExpiryDate
		}
		newExpiry := startPoint.Add(time.Duration(cp.BonusDays) * 24 * time.Hour)

		_, err = db.Collection("users").UpdateOne(ctx, bson.M{"_id": userOID}, bson.M{
			"$set": bson.M{"expiryDate": newExpiry},
			"$inc": bson.M{"total_purchases": 1},
		})

		// Simple Rollback attempt if User update fails
		if err != nil {
			couponColl.UpdateOne(context.Background(), bson.M{"_id": cp.ID}, bson.M{
				"$inc":  bson.M{"uses": -1},
				"$pull": bson.M{"used_by": userOID},
			})
			return map[string]string{"msg": "Failed to apply bonus"}, 500, err
		}

		if updatedCp.MaxUses != nil && updatedCp.Uses >= *updatedCp.MaxUses {
			// Clean cleanup later instead of delete immediate can be safer, but logic maintained:
			couponColl.DeleteOne(context.Background(), bson.M{"_id": updatedCp.ID})
		}

		return map[string]interface{}{
			"msg":        "Coupon applied",
			"new_expiry": newExpiry.Format(time.RFC3339),
		}, 200, nil
	}

	if txHash == "" {
		return map[string]string{"msg": "TX Hash required"}, 400, nil
	}

	// Check duplicates
	count, _ := db.Collection("transactions").CountDocuments(ctx, bson.M{"tx_hash": txHash})
	if count > 0 {
		return map[string]string{"msg": "Transaction exists"}, 409, nil
	}

	newTx := Transaction{
		UserID:    userOID,
		Username:  user.Username,
		TxHash:    txHash,
		Days:      daysReq,
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}

	res, err := db.Collection("transactions").InsertOne(ctx, newTx)
	if err != nil {
		return nil, 500, err
	}

	idStr := "unknown"
	if oid, ok := res.InsertedID.(primitive.ObjectID); ok {
		idStr = oid.Hex()
	}

	return map[string]interface{}{
		"msg":   "Pending approval",
		"tx_id": idStr,
	}, 201, nil
}

// ----- AUTH & MIDDLEWARE -----

type CustomClaims struct {
	SessionSalt string `json:"session_salt"`
	jwt.RegisteredClaims
}

func generateTokens(username, salt string) (string, string, error) {
	accClaims := CustomClaims{
		SessionSalt: salt,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(4 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accClaims)
	accStr, err := token.SignedString(cfg.JWTSecret)
	if err != nil {
		return "", "", err
	}

	refClaims := CustomClaims{
		SessionSalt: salt,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
		},
	}
	rToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refClaims)
	refStr, err := rToken.SignedString(cfg.JWTSecret)
	return accStr, refStr, err
}

func AuthMiddleware(requiredAdmin bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"msg": "Missing Token"})
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &CustomClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return cfg.JWTSecret, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(401, gin.H{"msg": "Invalid Token"})
			return
		}

		username := claims.Subject
		// Context for strict check
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var user User
		err = db.Collection("users").FindOne(ctx, bson.M{"username": username}).Decode(&user)

		if err != nil || user.SessionSalt != claims.SessionSalt {
			c.AbortWithStatusJSON(401, gin.H{"msg": "Session Expired"})
			return
		}

		isAdmin := user.Role == "admin"
		for _, adm := range cfg.AdminUsernames {
			if adm == username {
				isAdmin = true; break
			}
		}
		if cfg.AdminEnvUser != "" && username == cfg.AdminEnvUser {
			isAdmin = true
		}

		if requiredAdmin && !isAdmin {
			c.AbortWithStatusJSON(403, gin.H{"msg": "Forbidden"})
			return
		}

		// Save User Value (NOT POINTER) to Context
		c.Set("user", user)
		c.Next()
	}
}

// ----- HANDLERS -----

func register(c *gin.Context) {
	var body struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"msg": "Missing fields"})
		return
	}

	username := strings.ToLower(strings.TrimSpace(body.Username))
	if len(username) < 3 {
		c.JSON(400, gin.H{"msg": "Username too short"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count, _ := db.Collection("users").CountDocuments(ctx, bson.M{"username": username})
	if count > 0 {
		c.JSON(409, gin.H{"msg": "Username exists"})
		return
	}

	hashed, _ := hashPassword(body.Password)
	salt := strconv.FormatInt(time.Now().UnixNano(), 10)

	role := "user"
	for _, adm := range cfg.AdminUsernames {
		if adm == username { role = "admin" }
	}
	if cfg.AdminEnvUser == username { role = "admin" }

	newUser := User{
		Username:    username,
		Password:    hashed,
		Role:        role,
		SessionSalt: salt,
		CreatedAt:   time.Now().UTC(),
	}

	_, err := db.Collection("users").InsertOne(ctx, newUser)
	if err != nil {
		c.JSON(500, gin.H{"msg": "Registration failed"})
		return
	}

	at, rt, _ := generateTokens(username, salt)
	c.JSON(201, gin.H{"msg": "Registered", "access_token": at, "refresh_token": rt})
}

func login(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	c.ShouldBindJSON(&body)
	username := strings.ToLower(strings.TrimSpace(body.Username))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	err := db.Collection("users").FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil || !checkPassword(body.Password, user.Password) {
		c.JSON(401, gin.H{"msg": "Invalid credentials"})
		return
	}

	newSalt := strconv.FormatInt(time.Now().UnixNano(), 10)
	// Ignore update error, session will just persist old salt briefly
	db.Collection("users").UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{"$set": bson.M{"session_salt": newSalt}})

	at, rt, _ := generateTokens(username, newSalt)
	c.JSON(200, gin.H{"access_token": at, "refresh_token": rt})
}

func getMe(c *gin.Context) {
	// SAFE CASTING
	uVal, exists := c.Get("user")
	if !exists {
		c.JSON(401, gin.H{"msg": "Unauthorized context"})
		return
	}
	
	// Create safe copy for closure
	currentUser, ok := uVal.(User)
	if !ok {
		c.JSON(500, gin.H{"msg": "User context corrupted"})
		return
	}

	task := func() (interface{}, int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var user User
		// Refresh from DB
		err := db.Collection("users").FindOne(ctx, bson.M{"_id": currentUser.ID}).Decode(&user)
		if err != nil {
			return nil, 404, err
		}

		now := time.Now().UTC()
		daysLeft := 0
		var expIso interface{} = nil

		if user.ExpiryDate != nil {
			iso := user.ExpiryDate.Format(time.RFC3339)
			expIso = iso
			if user.ExpiryDate.After(now) {
                diff := user.ExpiryDate.Sub(now)
                daysLeft = int(math.Ceil(diff.Hours() / 24))
            }
		}

		return gin.H{
			"username":   user.Username,
			"role":       user.Role,
			"days_left":  daysLeft,
			"expiry_iso": expIso,
		}, 200, nil
	}

	res, code, err := SubmitJob(0, task, true)
	if err != nil {
		c.JSON(code, gin.H{"msg": "Error", "detail": err.Error()})
		return
	}
	c.JSON(code, res)
}

func submitPayment(c *gin.Context) {
	uVal, exists := c.Get("user")
	if !exists {
		c.JSON(401, gin.H{"msg": "Unauthorized"})
		return
	}
	currentUser := uVal.(User)

	var body struct {
		Days       *int   `json:"days"`
		TxHash     string `json:"tx_hash"`
		CouponCode string `json:"coupon_code"`
	}
	
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"msg": "Invalid JSON"})
		return
	}

	// Logic inputs
	days := 0
	if body.Days != nil { days = *body.Days }
	
	if body.CouponCode == "" && (days < 1 || days > 3650) {
		c.JSON(400, gin.H{"msg": "Days required (1-3650) if no coupon"})
		return
	}

	// Wrap in worker task
	task := func() (interface{}, int, error) {
		return logicApplyPayment(currentUser.ID.Hex(), body.CouponCode, body.TxHash, days)
	}

	res, code, err := SubmitJob(10, task, true)
	if err != nil {
		// Try to forward structured error map if available
		if resMap, ok := res.(map[string]string); ok {
			c.JSON(code, resMap)
			return
		}
		c.JSON(code, gin.H{"msg": "System failure", "error": err.Error()})
		return
	}
	c.JSON(code, res)
}

// ----- ADMIN HANDLERS -----

func adminListTx(c *gin.Context) {
	status := c.Query("status")
	filter := bson.M{}
	if status != "" {
		filter["status"] = status
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opts := options.Find().SetSort(bson.M{"created_at": -1}).SetLimit(100)
	cursor, err := db.Collection("transactions").Find(ctx, filter, opts)
	if err != nil {
		c.JSON(500, gin.H{"msg": "DB error"})
		return
	}
	// Do NOT Close cursor manually, All() handles it, but deferring close is safe practice
	defer cursor.Close(ctx)

	var rawResults []Transaction
	if err := cursor.All(ctx, &rawResults); err != nil {
		c.JSON(500, gin.H{"msg": "Cursor read error"})
		return
	}

	output := []gin.H{}
	// Make sure slice is not nil for safety
	if rawResults == nil { rawResults = []Transaction{} }

	for _, tx := range rawResults {
		item := gin.H{
			"_id":        tx.ID.Hex(),
			"user_id":    tx.UserID.Hex(),
			"username":   tx.Username,
			"tx_hash":    tx.TxHash,
			"days":       tx.Days,
			"status":     tx.Status,
			"created_at": tx.CreatedAt.Format(time.RFC3339),
		}
		// Safely handle pointers
		if tx.ProcessedAt != nil {
			item["processed_at"] = tx.ProcessedAt.Format(time.RFC3339)
		}
		if tx.RejectedAt != nil {
			item["rejected_at"] = tx.RejectedAt.Format(time.RFC3339)
		}
		if tx.RejectReason != "" {
			item["reject_reason"] = tx.RejectReason
		}
		output = append(output, item)
	}
	c.JSON(200, output)
}

func adminApproveTx(c *gin.Context) {
	txID := c.Param("tx_id")
	uVal, _ := c.Get("user") // Safe from MustGet in case of rare middleware slip
	admin, ok := uVal.(User)
	if !ok {
		c.JSON(401, gin.H{"msg": "Auth Error"})
		return 
	}

	task := func() (interface{}, int, error) {
		ctx := context.Background() // Worker uses bg or specific timeout
		oid, err := primitive.ObjectIDFromHex(txID)
		if err != nil {
			return map[string]string{"msg": "Invalid ID"}, 400, nil
		}

		var tx Transaction
		if err := db.Collection("transactions").FindOne(ctx, bson.M{"_id": oid, "status": "pending"}).Decode(&tx); err != nil {
			return map[string]string{"msg": "TX not pending"}, 404, nil
		}

		var targetUser User
		if err := db.Collection("users").FindOne(ctx, bson.M{"_id": tx.UserID}).Decode(&targetUser); err != nil {
			return map[string]string{"msg": "User missing"}, 404, nil
		}

		now := time.Now().UTC()
		start := now
		if targetUser.ExpiryDate != nil && targetUser.ExpiryDate.After(now) {
			start = *targetUser.ExpiryDate
		}
		newExp := start.Add(time.Duration(tx.Days) * 24 * time.Hour)

		_, err = db.Collection("users").UpdateOne(ctx, bson.M{"_id": targetUser.ID}, bson.M{
			"$set": bson.M{"expiryDate": newExp},
			"$inc": bson.M{"total_purchases": 1},
		})

		if err == nil {
			db.Collection("transactions").UpdateOne(ctx, bson.M{"_id": oid}, bson.M{
				"$set": bson.M{
					"status":       "approved",
					"approved_by":  admin.Username,
					"processed_at": now,
				},
			})
		}

		return map[string]string{"msg": "Approved", "new_expiry": newExp.Format(time.RFC3339)}, 200, nil
	}

	res, code, _ := SubmitJob(5, task, true)
	c.JSON(code, res)
}

func adminRejectTx(c *gin.Context) {
	txID := c.Param("tx_id")
	uVal, _ := c.Get("user")
	admin := uVal.(User)

	var body struct { Reason string `json:"reason"` }
	// ShouldBind can leave fields empty, manual init check logic:
	if err := c.ShouldBindJSON(&body); err != nil {
		// Just continue if body empty or invalid
	}
	if body.Reason == "" { body.Reason = "No reason" }

	task := func() (interface{}, int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		oid, err := primitive.ObjectIDFromHex(txID)
		if err != nil { return map[string]string{"msg": "ID error"}, 400, nil }

		res, err := db.Collection("transactions").UpdateOne(ctx,
			bson.M{"_id": oid, "status": "pending"},
			bson.M{"$set": bson.M{
				"status":        "rejected",
				"rejected_by":   admin.Username,
				"rejected_at":   time.Now().UTC(),
				"reject_reason": body.Reason,
			}},
		)
		if err != nil || res.MatchedCount == 0 {
			return map[string]string{"msg": "Update failed (not found/processed)"}, 404, nil
		}
		return map[string]string{"msg": "Rejected"}, 200, nil
	}

	res, code, _ := SubmitJob(5, task, true)
	c.JSON(code, res)
}

func manageCoupons(c *gin.Context) {
	if c.Request.Method == "GET" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cursor, err := db.Collection("coupons").Find(ctx, bson.M{}, options.Find().SetSort(bson.M{"created_at": -1}))
		if err != nil {
			c.JSON(500, gin.H{"msg": "DB error"})
			return
		}
		var coupons []Coupon
		// IMPORTANT: Initialize to empty slice so JSON returns [] not null
		coupons = []Coupon{} 
		cursor.All(ctx, &coupons)

		output := []gin.H{}
		for _, cp := range coupons {
			// Protection against nil slices in legacy data
			usedByStrs := []string{}
			if cp.UsedBy != nil {
				for _, u := range cp.UsedBy {
					usedByStrs = append(usedByStrs, u.Hex())
				}
			}

			item := gin.H{
				"_id":        cp.ID.Hex(),
				"code":       cp.Code,
				"bonus_days": cp.BonusDays,
				"max_uses":   cp.MaxUses,
				"uses":       cp.Uses,
				"used_by":    usedByStrs,
				"created_at": cp.CreatedAt.Format(time.RFC3339),
			}
			if cp.ExpiresAt != nil {
				item["expires_at"] = cp.ExpiresAt.Format(time.RFC3339)
			} else {
				item["expires_at"] = nil
			}
			output = append(output, item)
		}
		c.JSON(200, output)
		return
	}

	// POST
	var body struct {
		Code      string     `json:"code" binding:"required"`
		BonusDays int        `json:"bonus_days" binding:"required"`
		MaxUses   *int       `json:"max_uses"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"msg": "Validation error"})
		return
	}

	newC := Coupon{
		Code:      body.Code,
		BonusDays: body.BonusDays,
		MaxUses:   body.MaxUses,
		ExpiresAt: body.ExpiresAt,
		Uses:      0,
		UsedBy:    []primitive.ObjectID{}, // Init empty slice
		CreatedAt: time.Now().UTC(),
	}

	_, err := db.Collection("coupons").InsertOne(context.Background(), newC)
	if mongo.IsDuplicateKeyError(err) {
		c.JSON(409, gin.H{"msg": "Coupon code already exists"})
		return
	}
	c.JSON(201, gin.H{"msg": "Coupon created"})
}

// ----- STARTUP -----

func ensureIndexesAndAdmin() {
	// استفاده از timeout جداگانه
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if db == nil {
		log.Println("Skipping EnsureIndexes: DB not ready")
		return
	}

	db.Collection("users").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "username", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	db.Collection("transactions").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "tx_hash", Value: 1}},
		Options: options.Index().SetUnique(true).SetSparse(true),
	})
	db.Collection("coupons").Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "code", Value: 1}},
		Options: options.Index().SetUnique(true),
	})

	// Bootstrap Admin
	if cfg.AdminEnvUser != "" && cfg.AdminEnvPass != "" {
		hash, _ := hashPassword(cfg.AdminEnvPass)
		userColl := db.Collection("users")
		// Use specific find to avoid panic if collection empty/error
		if err := userColl.FindOne(ctx, bson.M{"username": cfg.AdminEnvUser}).Err(); err == mongo.ErrNoDocuments {
			userColl.InsertOne(ctx, User{
				Username:    cfg.AdminEnvUser,
				Password:    hash,
				Role:        "admin",
				SessionSalt: "system",
				CreatedAt:   time.Now().UTC(),
			})
			log.Println("Bootstrap admin created")
		}
	}
}

func cleanupCouponsTask() {
	// Simple ticker loop, recover protected
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Cleanup Task Panic: %v", r)
		}
	}()

	ticker := time.NewTicker(1 * time.Hour)
	for {
		select {
		case <-shutdownCh:
			return
		case <-ticker.C:
			if db != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, _ = db.Collection("coupons").DeleteMany(ctx, bson.M{
					"expires_at": bson.M{"$lt": time.Now().UTC()},
				})
				cancel()
			}
		}
	}
}

func main() {
	log.Println("Starting Server...")
	loadConfig()
	connectDB() // This must block until connected

	// Heap must be initialized
	heap.Init(&jobQueue)
	
	// Start workers after DB and Heap are ready
	startWorkers(cfg.WorkerCount)

	// Async Maintenance
	go func() {
		// Slight delay to allow full startup
		time.Sleep(1 * time.Second)
		ensureIndexesAndAdmin()
		cleanupCouponsTask()
	}()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// Use Recovery middleware (catches Handler panics)
	r.Use(gin.Recovery())

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowAllOrigins = true
	if origins := os.Getenv("FRONTEND_ORIGINS"); origins != "" {
		corsConfig.AllowAllOrigins = false
		corsConfig.AllowOrigins = strings.Split(origins, ",")
	}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	r.Use(cors.New(corsConfig))

	// Routes
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"service":        "TwoManga API",
			"status":         "healthy",
			"workers":        cfg.WorkerCount,
		})
	})

	auth := r.Group("/auth")
	{
		auth.POST("/register", register)
		auth.POST("/login", login)
		auth.GET("/me", AuthMiddleware(false), getMe)
	}

	payment := r.Group("/payment")
	payment.Use(AuthMiddleware(false))
	{
		payment.POST("/submit", submitPayment)
	}

	admin := r.Group("/admin")
	admin.Use(AuthMiddleware(true))
	{
		admin.GET("/transactions", adminListTx)
		admin.POST("/transactions/:tx_id/approve", adminApproveTx)
		admin.POST("/transactions/:tx_id/reject", adminRejectTx)
		admin.GET("/coupons", manageCoupons)
		admin.POST("/coupons", manageCoupons)
	}

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Listen error: %s\n", err)
		}
	}()
	log.Printf("Server listening on port %s", cfg.Port)

	// Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")

	// 1. Signal workers to stop
	close(shutdownCh)

	// 2. Stop Web Server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := srv.Shutdown(ctx); err != nil {
		log.Println("Server Shutdown Force:", err)
	}
	
	// 3. Close DB
	if mongoClient != nil {
		mongoClient.Disconnect(context.Background())
		log.Println("DB Disconnected")
	}
	log.Println("Bye.")
}
