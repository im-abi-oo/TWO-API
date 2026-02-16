# two_manga_api_optimized.py
# Two Manga API — Optimized Queue Mode
# Refactored for Production by Code Interpreter

import os
import uuid
import logging
import traceback
import threading
import queue
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Tuple, Callable, Any

from flask import Flask, request, jsonify, g
from flask_pymongo import PyMongo
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_cors import CORS
from marshmallow import Schema, fields, ValidationError, validates, EXCLUDE
from bson.objectid import ObjectId
from bson import errors as bson_errors
import bcrypt
import requests

# -------------------------------------------------------------------------
# 1. Configuration & Constants
# -------------------------------------------------------------------------
class Config:
    MONGO_URI = os.getenv("MONGO_URI")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    MONGO_DBNAME = os.getenv("MONGO_DBNAME", "twomanga")
    APP_PORT = int(os.getenv("PORT", "5001"))
    
    # Auth
    ACCESS_EXPIRES_HOURS = int(os.getenv("ACCESS_EXPIRES_HOURS", "4"))
    REFRESH_EXPIRES_DAYS = int(os.getenv("REFRESH_EXPIRES_DAYS", "30"))
    BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))
    
    # Admins
    ADMIN_USERNAMES = [u.strip().lower() for u in os.getenv("ADMIN_USERNAMES", "").split(",") if u.strip()]
    ADMIN_ENV_USERNAME = os.getenv("ADMIN_USERNAME")
    ADMIN_ENV_PASSWORD = os.getenv("ADMIN_PASSWORD")

    # Workers
    WORKER_COUNT = int(os.getenv("WORKER_COUNT", "4"))
    JOB_WAIT_SECONDS = float(os.getenv("JOB_WAIT_SECONDS", "5.0"))

    # Rates API
    BRSAPI_KEY = os.getenv("BRSAPI_KEY", "")
    BRSAPI_URL = os.getenv("BRSAPI_URL", "https://BrsApi.ir/Api/Market/Gold_Currency.php")
    NOBITEX_STATS_URL = os.getenv("NOBITEX_STATS_URL", "https://apiv2.nobitex.ir/market/stats")
    
    # Scheduler
    ENABLE_RATE_SCHEDULER = os.getenv("ENABLE_RATE_SCHEDULER", "false").lower() == "true"
    RATE_FETCH_MINUTES = int(os.getenv("RATE_FETCH_MINUTES", "60"))

# Validate required
if not Config.MONGO_URI:
    raise RuntimeError("Missing MONGO_URI")
if not Config.JWT_SECRET_KEY:
    raise RuntimeError("Missing JWT_SECRET_KEY")

# Logging
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("api")

# -------------------------------------------------------------------------
# 2. Flask Setup & Database
# -------------------------------------------------------------------------
app = Flask(__name__)
app.config["MONGO_URI"] = Config.MONGO_URI
app.config["JWT_SECRET_KEY"] = Config.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=Config.ACCESS_EXPIRES_HOURS)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=Config.REFRESH_EXPIRES_DAYS)

mongo = PyMongo(app)
jwt = JWTManager(app)

# CORS Setup
origins_raw = os.getenv("FRONTEND_ORIGINS", "http://localhost:3000")
cors_origins = "*" if origins_raw in ("*", "") else [o.strip() for o in origins_raw.split(",") if o.strip()]
CORS(app, resources={r"/*": {"origins": cors_origins}}, supports_credentials=True)

# -------------------------------------------------------------------------
# 3. Helpers & Utilities
# -------------------------------------------------------------------------
def get_utc_now() -> datetime:
    """Returns current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=Config.BCRYPT_ROUNDS)).decode("utf-8")

def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

# Safe fake hash for timing attacks mitigation
FAKE_HASH = bcrypt.hashpw(b"fake", bcrypt.gensalt(rounds=Config.BCRYPT_ROUNDS)).decode("utf-8")

def safe_object_id(oid_str: str) -> Optional[ObjectId]:
    try:
        return ObjectId(oid_str)
    except (bson_errors.InvalidId, TypeError):
        return None

# -------------------------------------------------------------------------
# 4. Schemas (Validation Layer)
# -------------------------------------------------------------------------
class RegisterSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)
    @validates("username")
    def validate_user(self, value):
        if len(value.strip()) < 3 or " " in value:
            raise ValidationError("Username must be 3+ chars, no spaces.")
    @validates("password")
    def validate_pass(self, value):
        if len(value) < 6:
            raise ValidationError("Password must be 6+ chars.")

class LoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)

class PaymentSubmitSchema(Schema):
    # Accept anything via allow_none, validate in logic or here
    tx_hash = fields.Str(load_default=None)
    coupon_code = fields.Str(load_default=None)
    days = fields.Int(required=True, strict=True)
    @validates("days")
    def val_days(self, value):
        if value <= 0 or value > 3650:
            raise ValidationError("Days must be between 1 and 3650.")

class CouponCreateSchema(Schema):
    code = fields.Str(required=True)
    bonus_days = fields.Int(required=True)
    max_uses = fields.Int(load_default=None, allow_none=True)
    expires_at = fields.DateTime(load_default=None, allow_none=True) # Handles ISO parsing automatically

    @validates("bonus_days")
    def val_bonus(self, val):
        if val <= 0: raise ValidationError("bonus_days must be > 0")

class RejectTxSchema(Schema):
    reason = fields.Str(load_default="")

# -------------------------------------------------------------------------
# 5. Background Worker System (Simplified)
# -------------------------------------------------------------------------
_job_counter = 0
_job_lock = threading.Lock()

class Job:
    def __init__(self, priority: int, func: Callable, args=(), wait=False):
        global _job_counter
        with _job_lock:
            self.seq = _job_counter
            _job_counter += 1
        self.priority = priority
        self.func = func
        self.args = args
        self.wait = wait
        self._done_event = threading.Event() if wait else None
        self.result = None
        self.error = None
    
    def execute(self):
        try:
            self.result = self.func(*self.args)
        except Exception as e:
            self.error = e
            logger.error(f"Job execution failed: {e}")
            logger.debug(traceback.format_exc())
        finally:
            if self._done_event:
                self._done_event.set()

    def wait_result(self, timeout):
        if not self._done_event: return None
        if self._done_event.wait(timeout):
            if self.error:
                raise self.error
            return self.result
        return None # Timed out

# Tuple structure for priority queue: (priority, sequence, job_object)
job_queue = queue.PriorityQueue()
workers_running = True

def worker_thread(idx):
    logger.info(f"Worker {idx} started.")
    with app.app_context(): # Ensure Flask context for DB access
        while workers_running:
            try:
                # 1 second timeout to allow checking `workers_running` flag
                _, _, job = job_queue.get(timeout=1.0)
                job.execute()
                job_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker {idx} crashed loop: {e}")

def enqueue(func, args=(), priority=50, wait=False):
    job = Job(priority, func, args, wait)
    job_queue.put((priority, job.seq, job))
    if wait:
        try:
            res = job.wait_result(timeout=Config.JOB_WAIT_SECONDS)
            if job._done_event.is_set():
                return {"finished": True, "result": res}
            return {"finished": False} # Timed out
        except Exception as e:
            # Propagate exception message cleanly
            return {"finished": True, "error_msg": str(e)}
    return {"queued": True}

# Start Workers
worker_threads_list = []
for i in range(Config.WORKER_COUNT):
    t = threading.Thread(target=worker_thread, args=(i,), daemon=True)
    t.start()
    worker_threads_list.append(t)

# -------------------------------------------------------------------------
# 6. Auth Decorators & Middlewares
# -------------------------------------------------------------------------
def single_session_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        identity = get_jwt_identity()
        user = mongo.db.users.find_one({"username": identity.strip().lower()}, {"session_salt": 1})
        if not user or user.get("session_salt") != claims.get("session_salt"):
            return jsonify({"msg": "Session invalidated"}), 401
        # Set Global User
        g.current_user_doc = mongo.db.users.find_one({"_id": user["_id"]})
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity()
        identity = identity.strip().lower()
        
        # Method 1: Check if env admin
        is_env_admin = (
            Config.ADMIN_ENV_USERNAME and 
            identity == Config.ADMIN_ENV_USERNAME.lower()
        )
        # Method 2: Check username list or DB role
        if not is_env_admin:
            user = mongo.db.users.find_one({"username": identity})
            if not user:
                return jsonify({"msg": "User not found"}), 403
            is_role_admin = user.get("role") == "admin"
            is_list_admin = identity in Config.ADMIN_USERNAMES
            if not (is_role_admin or is_list_admin):
                 return jsonify({"msg": "Admins only"}), 403
            g.current_admin = user
        else:
            g.current_admin = {"username": "superuser", "_id": None}
            
        return fn(*args, **kwargs)
    return wrapper

# Database Connectivity Check Middleware
@app.before_request
def check_db_health():
    # Only skip for basic OPTIONS/Health requests to save overhead
    if request.path in ["/", "/debug/health"]:
        return
    # Simple check only if command failed recently (opt: add lightweight check here if paranoid)
    # PyMongo handles this usually, no manual ping needed per request in production.
    pass

# -------------------------------------------------------------------------
# 7. Worker Logic Functions
# -------------------------------------------------------------------------
def logic_auth_me(username):
    # Runs in worker
    user = mongo.db.users.find_one({"username": username})
    if not user: return None, 404
    now = get_utc_now()
    exp = user.get("expiryDate")
    # ensure datetime logic
    if exp and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    
    is_premium = bool(exp and exp > now)
    days_left = (exp - now).days if is_premium else 0
    
    return {
        "username": user["username"],
        "role": user.get("role", "user"),
        "is_premium": is_premium,
        "days_left": max(0, days_left),
        "expiry_date": exp.isoformat() if exp else None,
        "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
        "total_purchases": user.get("total_purchases", 0)
    }, 200

def logic_process_payment(user_id, data):
    # Runs in worker
    # Reload user to ensure freshness inside worker thread
    user = mongo.db.users.find_one({"_id": user_id})
    if not user: raise Exception("User gone")

    days = data["days"]
    coupon_code = data.get("coupon_code")
    tx_hash = data.get("tx_hash")

    # A. Coupon Logic
    if coupon_code:
        coupon = mongo.db.coupons.find_one({"code": coupon_code})
        if not coupon:
            return {"msg": "Invalid coupon"}, 400
        
        # Expiry Check
        if coupon.get("expires_at"):
            c_exp = coupon["expires_at"]
            if c_exp.tzinfo is None: c_exp = c_exp.replace(tzinfo=timezone.utc)
            if c_exp < get_utc_now():
                return {"msg": "Coupon expired"}, 400

        # Usage Check
        if coupon.get("max_uses") is not None:
            if coupon.get("uses", 0) >= coupon["max_uses"]:
                return {"msg": "Coupon limit reached"}, 400
        
        # Apply
        now = get_utc_now()
        current_exp = user.get("expiryDate")
        if current_exp and current_exp.tzinfo is None: current_exp = current_exp.replace(tzinfo=timezone.utc)
        
        start_date = current_exp if (current_exp and current_exp > now) else now
        bonus = coupon.get("bonus_days", days) # fallback to 'days' input if logic demands, usually coupon has own bonus
        new_exp = start_date + timedelta(days=bonus)
        
        mongo.db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"expiryDate": new_exp}, "$inc": {"total_purchases": 1}}
        )
        mongo.db.coupons.update_one(
            {"_id": coupon["_id"]},
            {"$inc": {"uses": 1}}
        )
        return {"msg": "Coupon applied", "expiry_date": new_exp.isoformat()}, 200

    # B. Transaction Logic
    if not tx_hash:
        return {"msg": "TX Hash required"}, 400
    
    if mongo.db.transactions.find_one({"tx_hash": tx_hash}):
        return {"msg": "Transaction hash already used"}, 400
        
    doc = {
        "user_id": user["_id"],
        "username": user["username"],
        "tx_hash": tx_hash,
        "days": days,
        "status": "pending",
        "created_at": get_utc_now()
    }
    res = mongo.db.transactions.insert_one(doc)
    return {"msg": "Payment pending approval", "tx_id": str(res.inserted_id)}, 200

# -------------------------------------------------------------------------
# 8. Routes
# -------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def health():
    # Light DB ping
    db_ok = True
    try:
        mongo.db.command("ping")
    except:
        db_ok = False
    return jsonify({
        "status": "ok", 
        "queue_size": job_queue.qsize(),
        "db": "connected" if db_ok else "error"
    })

# --- AUTH ---
@app.route("/auth/register", methods=["POST"])
def register():
    try:
        data = RegisterSchema().load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400

    username = data["username"].strip().lower()
    if mongo.db.users.find_one({"username": username}):
        return jsonify({"msg": "Username taken"}), 409
    
    # Check if admin (env based)
    role = "user"
    if username in Config.ADMIN_USERNAMES:
        role = "admin"
    if Config.ADMIN_ENV_USERNAME and username == Config.ADMIN_ENV_USERNAME.lower():
        role = "admin"

    doc = {
        "username": username,
        "password": hash_password(data["password"]),
        "created_at": get_utc_now(),
        "session_salt": str(uuid.uuid4()),
        "role": role,
        "expiryDate": None,
        "total_purchases": 0
    }
    mongo.db.users.insert_one(doc)
    return jsonify({"msg": "Registered successfully"}), 201

@app.route("/auth/login", methods=["POST"])
def login():
    try:
        data = LoginSchema().load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400

    username = data["username"].strip().lower()
    user = mongo.db.users.find_one({"username": username})
    
    check_hash = user["password"] if user else FAKE_HASH
    if not check_password(data["password"], check_hash) or not user:
        return jsonify({"msg": "Invalid credentials"}), 401

    salt = str(uuid.uuid4())
    mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"session_salt": salt}})
    
    acc = create_access_token(identity=username, additional_claims={"session_salt": salt})
    ref = create_refresh_token(identity=username, additional_claims={"session_salt": salt})
    return jsonify({"access_token": acc, "refresh_token": ref})

@app.route("/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token():
    claims = get_jwt()
    ident = get_jwt_identity()
    user = mongo.db.users.find_one({"username": ident.strip().lower()}, {"session_salt": 1})
    if not user or user.get("session_salt") != claims.get("session_salt"):
        return jsonify({"msg": "Token invalid"}), 401
    
    new_acc = create_access_token(identity=ident, additional_claims={"session_salt": user["session_salt"]})
    return jsonify({"access_token": new_acc})

@app.route("/auth/me", methods=["GET"])
@jwt_required()
@single_session_required
def get_me():
    # Priority 0: Immediate User info
    res = enqueue(logic_auth_me, args=(g.current_user_doc["username"],), priority=0, wait=True)
    if res.get("error_msg"):
         return jsonify({"msg": "Processing error"}), 500
    if res.get("finished"):
        data, status = res["result"]
        return jsonify(data), status
    return jsonify({"msg": "System busy, please retry"}), 503

# --- PAYMENT ---
@app.route("/payment/submit", methods=["POST"])
@jwt_required()
@single_session_required
def submit_payment():
    try:
        # Pass unknown=EXCLUDE if front-end sends extra noise
        data = PaymentSubmitSchema().load(request.json, unknown=EXCLUDE)
    except ValidationError as err:
        return jsonify(err.messages), 400

    # We pass the ObjectId directly, worker re-fetches cleanly
    res = enqueue(logic_process_payment, args=(g.current_user_doc["_id"], data), priority=10, wait=True)
    
    if res.get("error_msg"):
         return jsonify({"msg": str(res.get("error_msg"))}), 500

    if res.get("finished"):
        # The result from worker is a tuple (json_response, http_code)
        resp_data, code = res["result"]
        return jsonify(resp_data), code
    
    # If wait timed out
    return jsonify({"msg": "Payment queued for processing"}), 202

# --- USER TRANSACTIONS ---
@app.route("/user/transactions", methods=["GET"])
@jwt_required()
@single_session_required
def user_txs():
    user = g.current_user_doc
    txs = list(mongo.db.transactions.find(
        {"user_id": user["_id"]},
        {"_id": 1, "tx_hash": 1, "days": 1, "status": 1, "created_at": 1}
    ).sort("created_at", -1).limit(50))
    
    for t in txs:
        t["_id"] = str(t["_id"])
        if t.get("created_at"): t["created_at"] = t["created_at"].isoformat()
        
    return jsonify({"transactions": txs})

# --- ADMIN ---
@app.route("/admin/coupons", methods=["GET", "POST"])
@admin_required
def admin_coupons():
    if request.method == "POST":
        try:
            data = CouponCreateSchema().load(request.json)
        except ValidationError as err:
            return jsonify(err.messages), 400

        # Handle expiry timezone safely
        if data.get("expires_at"):
            if data["expires_at"].tzinfo is None:
                data["expires_at"] = data["expires_at"].replace(tzinfo=timezone.utc)

        doc = {
            "code": data["code"],
            "bonus_days": data["bonus_days"],
            "uses": 0,
            "max_uses": data["max_uses"],
            "expires_at": data.get("expires_at"),
            "created_at": get_utc_now()
        }
        try:
            mongo.db.coupons.insert_one(doc)
            return jsonify({"msg": "Coupon created"}), 201
        except Exception as e:
            return jsonify({"msg": "Error creating coupon", "error": str(e)}), 400

    # GET List
    data = list(mongo.db.coupons.find().sort("created_at", -1).limit(100))
    for c in data:
        c["_id"] = str(c["_id"])
        if c.get("created_at"): c["created_at"] = c["created_at"].isoformat()
        if c.get("expires_at"): c["expires_at"] = c["expires_at"].isoformat()
    return jsonify(data)

@app.route("/admin/transactions", methods=["GET"])
@admin_required
def admin_tx_list():
    query = {}
    status = request.args.get("status")
    if status: query["status"] = status
    
    data = list(mongo.db.transactions.find(query).sort("created_at", -1).limit(200))
    for t in data:
        t["_id"] = str(t["_id"])
        t["user_id"] = str(t["user_id"])
        if t.get("created_at"): t["created_at"] = t["created_at"].isoformat()
    return jsonify({"transactions": data})

@app.route("/admin/transactions/<tx_id>/approve", methods=["POST"])
@admin_required
def admin_approve(tx_id):
    oid = safe_object_id(tx_id)
    if not oid: return jsonify({"msg": "Invalid ID"}), 400
    
    tx = mongo.db.transactions.find_one({"_id": oid, "status": "pending"})
    if not tx:
        return jsonify({"msg": "Transaction not found or processed"}), 404
    
    user = mongo.db.users.find_one({"_id": tx["user_id"]})
    if not user:
        return jsonify({"msg": "User associated not found"}), 404
        
    now = get_utc_now()
    cur_exp = user.get("expiryDate")
    if cur_exp and cur_exp.tzinfo is None: cur_exp = cur_exp.replace(tzinfo=timezone.utc)
    
    start = cur_exp if (cur_exp and cur_exp > now) else now
    new_exp = start + timedelta(days=tx["days"])
    
    # Atomic-like update not strictly necessary but safer
    mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"expiryDate": new_exp}, "$inc": {"total_purchases": 1}})
    mongo.db.transactions.update_one({"_id": oid}, {"$set": {
        "status": "approved", 
        "processed_at": now, 
        "approved_by": g.current_admin.get("username", "system")
    }})
    
    return jsonify({"msg": "Approved", "new_expiry": new_exp.isoformat()})

@app.route("/admin/transactions/<tx_id>/reject", methods=["POST"])
@admin_required
def admin_reject(tx_id):
    oid = safe_object_id(tx_id)
    if not oid: return jsonify({"msg": "Invalid ID"}), 400

    reason = request.json.get("reason", "") if request.json else ""

    res = mongo.db.transactions.update_one(
        {"_id": oid, "status": "pending"},
        {"$set": {
            "status": "rejected",
            "rejected_at": get_utc_now(),
            "reject_reason": reason,
            "rejected_by": g.current_admin.get("username", "system")
        }}
    )
    if res.matched_count == 0:
         return jsonify({"msg": "Tx not found or processed"}), 404
    return jsonify({"msg": "Rejected"})

# -------------------------------------------------------------------------
# 9. Initialization Logic
# -------------------------------------------------------------------------
def initial_setup():
    with app.app_context():
        try:
            # Safe index creation
            mongo.db.users.create_index("username", unique=True)
            mongo.db.coupons.create_index("code", unique=True)
            mongo.db.transactions.create_index("tx_hash", unique=True, sparse=True)
            
            # Create Env Admin
            if Config.ADMIN_ENV_USERNAME and Config.ADMIN_ENV_PASSWORD:
                u = Config.ADMIN_ENV_USERNAME.lower()
                existing = mongo.db.users.find_one({"username": u})
                if not existing:
                    logger.info(f"Creating env admin: {u}")
                    mongo.db.users.insert_one({
                        "username": u,
                        "password": hash_password(Config.ADMIN_ENV_PASSWORD),
                        "role": "admin",
                        "session_salt": "system",
                        "created_at": get_utc_now()
                    })
                else:
                    mongo.db.users.update_one({"username": u}, {"$set": {"role": "admin"}})
            logger.info("DB Indexes ensured.")
        except Exception as e:
            logger.warning(f"Startup DB init failed (DB might be down): {e}")

if __name__ == "__main__":
    initial_setup()
    app.run(host="0.0.0.0", port=Config.APP_PORT, debug=False)
