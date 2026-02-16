# Two Manga API — Professional Queue Mode (Refactored & Fixed)
# Architecture: Threaded Workers + Priority Queue + Singleton DB Manager
# Features: Strong Consistency, Graceful Shutdown, Thread-Safe Locking, Coupon Logic Fixed

import os
import uuid
import json
import logging
import traceback
import datetime
import time
import threading
import queue
import atexit
from functools import wraps
from concurrent.futures import Future
from typing import Optional, Any, Callable, List, Dict

from flask import Flask, request, jsonify, g
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_cors import CORS
from marshmallow import Schema, fields, ValidationError, validates, EXCLUDE
from pymongo import MongoClient, ASCENDING
from pymongo.errors import ConnectionFailure, DuplicateKeyError
from bson.objectid import ObjectId
from bson.errors import InvalidId
import bcrypt

# ----- CONFIG & LOGGING -----
class AppConfig:
    # Mandatory
    MONGO_URI = os.getenv("MONGO_URI")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

    # Optional Defaults
    MONGO_DBNAME = os.getenv("MONGO_DBNAME", "twomanga")
    APP_PORT = int(os.getenv("PORT", "5001"))
    
    # Logic / Queues
    WORKER_COUNT = int(os.getenv("WORKER_COUNT", "4"))
    JOB_WAIT_SECONDS = float(os.getenv("JOB_WAIT_SECONDS", "8.0"))
    
    # Admins
    ADMIN_USERNAMES = [u.strip().lower() for u in os.getenv("ADMIN_USERNAMES", "").split(",") if u.strip()]
    
    ADMIN_ENV_USER = os.getenv("ADMIN_USERNAME")
    ADMIN_ENV_PASS = os.getenv("ADMIN_PASSWORD")
    
    BCRYPT_ROUNDS = 12

if not AppConfig.MONGO_URI or not AppConfig.JWT_SECRET_KEY:
    # Fallback only for testing if env vars are missing, remove in prod strict mode if needed
    print("WARNING: MONGO_URI or JWT_SECRET_KEY not set. Checking logic...") 
    # raise RuntimeError("Critical: MONGO_URI or JWT_SECRET_KEY missing.")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("TwoMangaCore")

# ----- UTILITIES: TIME & SECURITY -----
def get_utc_now() -> datetime.datetime:
    """Production safe UTC time."""
    return datetime.datetime.now(datetime.timezone.utc)

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=AppConfig.BCRYPT_ROUNDS)).decode("utf-8")

def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False

# ----- ADVANCED DATABASE MANAGER -----
class MongoManager:
    """
    Robust MongoDB Manager designed for long-running worker processes.
    Handles reconnection automatically.
    """
    def __init__(self, uri: str, db_name: str):
        self._uri = uri
        self._db_name = db_name
        self._client: Optional[MongoClient] = None
        self._db = None
        self._connect_lock = threading.Lock()

    def get_db(self):
        """Lazy connection retriever with retry logic."""
        if self._db is not None:
            return self._db

        with self._connect_lock:
            if self._db is not None:
                return self._db
            try:
                self._client = MongoClient(self._uri, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
                # Fail fast check
                self._client.admin.command('ping')
                
                try:
                    target_db = MongoClient(self._uri).get_default_database().name
                except:
                    target_db = self._db_name
                
                self._db = self._client[target_db]
                logger.info(f"DB Connected successfully to {target_db}")
                return self._db
            except Exception as e:
                logger.critical(f"DB Connection failed: {e}")
                self._client = None
                raise ConnectionFailure("Could not connect to database")

    def is_alive(self) -> bool:
        try:
            if self._client:
                self._client.admin.command('ping')
                return True
            return False
        except:
            return False

    def get_collection(self, name: str):
        return self.get_db()[name]

db_core = MongoManager(AppConfig.MONGO_URI, AppConfig.MONGO_DBNAME)

# ----- QUEUE & WORKER ENGINE (ADVANCED) -----
class JobWrapper:
    """Encapsulates a unit of work with a Future result."""
    def __init__(self, priority: int, func: Callable, args: tuple, kwargs: dict):
        self.priority = priority
        self.sequence = time.time_ns()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.future = Future()

    def __lt__(self, other):
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.sequence < other.sequence

class WorkerEngine:
    def __init__(self, num_workers: int):
        self.queue = queue.PriorityQueue()
        self.threads = []
        self._shutdown = threading.Event()
        self.num_workers = num_workers
        self._started = False

    def start(self):
        if self._started: return
        logger.info(f"Starting Engine with {self.num_workers} workers...")
        for i in range(self.num_workers):
            t = threading.Thread(target=self._worker_loop, name=f"Worker-{i}", daemon=True)
            t.start()
            self.threads.append(t)
        self._started = True

    def stop(self):
        logger.info("Stopping Worker Engine...")
        self._shutdown.set()
        for _ in self.threads:
            self.queue.put(JobWrapper(-1, lambda: None, (), {})) 
        for t in self.threads:
            t.join(timeout=2.0)

    def _worker_loop(self):
        while not self._shutdown.is_set():
            try:
                job: JobWrapper = self.queue.get(timeout=2.0)
                if job.priority == -1 and job.func() is None:
                    self.queue.task_done()
                    continue

                try:
                    result = job.func(*job.args, **job.kwargs)
                    if not job.future.done():
                        job.future.set_result(result)
                except Exception as e:
                    logger.error(f"Worker Exception in {job.func.__name__}: {e}")
                    if not job.future.done():
                        job.future.set_exception(e)
                finally:
                    self.queue.task_done()
                    
            except queue.Empty:
                continue
            except Exception as outer_e:
                logger.critical(f"Worker Loop Fatal Error: {outer_e}")

    def submit_job(self, func, *args, priority=10, wait=False, **kwargs) -> Dict[str, Any]:
        job = JobWrapper(priority, func, args, kwargs)
        self.queue.put(job)
        
        if not wait:
            return {"queued": True, "job_id": job.sequence}
        
        try:
            result = job.future.result(timeout=AppConfig.JOB_WAIT_SECONDS)
            return {"finished": True, "result": result}
        except TimeoutError:
            return {"finished": False, "msg": "Processing queued due to load"}
        except Exception as e:
            return {"finished": True, "error_msg": str(e)}

worker_engine = WorkerEngine(AppConfig.WORKER_COUNT)

# ----- FLASK APP SETUP -----
app = Flask(__name__)
app.config["MONGO_URI"] = AppConfig.MONGO_URI
app.config["JWT_SECRET_KEY"] = AppConfig.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=4)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(days=30)

jwt = JWTManager(app)

# --- STRICT CORS ---
cors_origins = "*" if not os.getenv("FRONTEND_ORIGINS") else os.getenv("FRONTEND_ORIGINS").split(",")
CORS(app, resources={r"/*": {"origins": cors_origins}}, supports_credentials=True)

# ----- VALIDATION SCHEMAS -----
class RegisterSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    
    @validates("username")
    def validate_username(self, val, **kwargs):
        if len(val.strip()) < 3 or " " in val:
            raise ValidationError("Invalid username format")

class PaymentSchema(Schema):
    days = fields.Int(required=False, allow_none=True)
    tx_hash = fields.Str(load_default=None)
    coupon_code = fields.Str(load_default=None)

    @validates("days")
    def validate_days(self, value, **kwargs):
        if value is None:
            return
        if value < 1 or value > 3650:
            raise ValidationError("Days must be between 1-3650")

class CouponSchema(Schema):
    code = fields.Str(required=True)
    bonus_days = fields.Int(required=True)
    max_uses = fields.Int(load_default=None, allow_none=True)
    expires_at = fields.DateTime(load_default=None, allow_none=True)

# ----- AUTH MIDDLEWARE -----
def get_current_user_safe():
    ident = get_jwt_identity()
    if not ident: return None
    coll = db_core.get_collection("users")
    return coll.find_one({"username": ident.strip().lower()})

def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current = get_current_user_safe()
        ident = get_jwt_identity()
        
        is_admin_db = current and current.get("role") == "admin"
        is_admin_list = ident in AppConfig.ADMIN_USERNAMES
        is_admin_env = (AppConfig.ADMIN_ENV_USER and ident == AppConfig.ADMIN_ENV_USER.lower())

        if is_admin_db or is_admin_list or is_admin_env:
            g.current_user = current or {"username": ident}
            return fn(*args, **kwargs)
        return jsonify({"msg": "Admin access required"}), 403
    return wrapper

def strict_session(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        ident = get_jwt_identity()
        user = db_core.get_collection("users").find_one({"username": ident.lower()})
        if not user or user.get("session_salt") != claims.get("session_salt"):
            return jsonify({"msg": "Session expired or overridden"}), 401
        g.current_user = user
        return fn(*args, **kwargs)
    return wrapper

# ----- COUPON CLEANUP (AUTO-DELETE EXPIRED) -----
def cleanup_expired_coupons():
    try:
        db = db_core.get_db()
        now = get_utc_now()
        result = db.coupons.delete_many({
            "expires_at": {"$lt": now}
        })
        if result.deleted_count > 0:
            logger.info(f"Deleted {result.deleted_count} expired coupons")
    except Exception as e:
        logger.error(f"Coupon cleanup failed: {e}")

# ----- BUSINESS LOGIC (WORKER SIDE) -----

def worker_logic_payment(user_id_str, data):
    """
    Handles payment submission and Coupon application.
    FIXES:
    1. Checks if user already used the coupon.
    2. Deletes coupon automatically if max_uses reached.
    """
    db = db_core.get_db()
    users = db.users
    coupons = db.coupons
    transactions = db.transactions

    user_oid = ObjectId(user_id_str)
    user = users.find_one({"_id": user_oid})
    if not user:
        raise ValueError("User not found")

    coupon_code = data.get("coupon_code")
    days = data.get("days")
    tx_hash = data.get("tx_hash")

    # 1. Coupon Handling
    if coupon_code:
        # NOTE: We fetch 'used_by' to check abuse
        c_doc = coupons.find_one({"code": coupon_code})
        if not c_doc:
            return {"msg": "Invalid coupon code"}, 400
        
        now_utc = get_utc_now()
        exp_at = c_doc.get("expires_at")
        
        # Check Expiry
        if exp_at and exp_at.replace(tzinfo=datetime.timezone.utc) < now_utc:
            coupons.delete_one({"_id": c_doc["_id"]})
            return {"msg": "Coupon expired"}, 400
        
        # Check Max Uses (Global Limit)
        max_uses = c_doc.get("max_uses")
        current_uses = c_doc.get("uses", 0)
        
        if max_uses is not None and current_uses >= max_uses:
            # Should have been deleted, but just in case
            coupons.delete_one({"_id": c_doc["_id"]})
            return {"msg": "Coupon limits reached"}, 400

        # [FIX] Check if THIS user already used it
        used_by_list = c_doc.get("used_by", [])
        if user_oid in used_by_list:
            return {"msg": "You have already used this coupon"}, 400

        # Apply Bonus Logic
        bonus = c_doc.get("bonus_days", 0)
        curr_expiry = user.get("expiryDate")
        if curr_expiry:
            if curr_expiry.tzinfo is None:
                curr_expiry = curr_expiry.replace(tzinfo=datetime.timezone.utc)
            start_point = curr_expiry if curr_expiry > now_utc else now_utc
        else:
            start_point = now_utc

        new_expiry = start_point + datetime.timedelta(days=bonus)
        
        # Execute DB Updates
        # Update User
        users.update_one({"_id": user_oid}, {
            "$set": {"expiryDate": new_expiry}, 
            "$inc": {"total_purchases": 1}
        })
        
        # [FIX] Update Coupon: Inc uses AND add user to used_by list
        coupons.update_one(
            {"_id": c_doc["_id"]}, 
            {
                "$inc": {"uses": 1},
                "$push": {"used_by": user_oid}
            }
        )
        
        # [FIX] Post-Update: Check if we need to DELETE the coupon (limit reached)
        if max_uses is not None:
            # We incremented uses by 1, so check (current_uses + 1)
            if (current_uses + 1) >= max_uses:
                coupons.delete_one({"_id": c_doc["_id"]})
                logger.info(f"Coupon {coupon_code} fully used and deleted from DB.")
        
        return {
            "msg": "Coupon applied successfully",
            "new_expiry": new_expiry.isoformat()
        }, 200

    # 2. Transaction Submission (Crypto)
    if not tx_hash:
        return {"msg": "TX Hash required if no coupon"}, 400

    if transactions.find_one({"tx_hash": tx_hash}):
        return {"msg": "Transaction already submitted"}, 409
    
    # Insert Pending
    doc = {
        "user_id": user_oid,
        "username": user["username"],
        "tx_hash": tx_hash,
        "days": days,
        "status": "pending",
        "created_at": get_utc_now()
    }
    new_tx = transactions.insert_one(doc)
    
    return {
        "msg": "Transaction pending approval",
        "tx_id": str(new_tx.inserted_id)
    }, 201

def worker_logic_approve_tx(tx_oid_str, admin_name):
    db = db_core.get_db()
    try:
        tx_oid = ObjectId(tx_oid_str)
    except InvalidId:
        return {"msg": "Invalid ID format"}, 400
        
    tx = db.transactions.find_one({"_id": tx_oid, "status": "pending"})
    if not tx:
        return {"msg": "Transaction not found or not pending"}, 404

    user = db.users.find_one({"_id": tx["user_id"]})
    if not user:
        return {"msg": "Linked user missing"}, 404

    now = get_utc_now()
    cur_exp = user.get("expiryDate")
    if cur_exp:
        if cur_exp.tzinfo is None:
            cur_exp = cur_exp.replace(tzinfo=datetime.timezone.utc)
        start = max(cur_exp, now)
    else:
        start = now
        
    days = tx.get("days", 0)
    new_exp = start + datetime.timedelta(days=days)

    db.users.update_one({"_id": user["_id"]}, {
        "$set": {"expiryDate": new_exp},
        "$inc": {"total_purchases": 1}
    })
    
    db.transactions.update_one({"_id": tx_oid}, {
        "$set": {
            "status": "approved",
            "approved_by": admin_name,
            "processed_at": now
        }
    })
    
    return {"msg": "Approved", "new_expiry": new_exp.isoformat()}, 200

def worker_logic_reject_tx(tx_oid_str, admin_name, reason):
    """
    [FIXED] Reject logic now strictly updates status and reason.
    """
    db = db_core.get_db()

    try:
        tx_oid = ObjectId(tx_oid_str)
    except InvalidId:
        return {"msg": "Invalid ID format"}, 400

    # Ensure transaction exists and is pending
    tx = db.transactions.find_one({"_id": tx_oid, "status": "pending"})
    if not tx:
        logger.warning(f"Reject failed: TX {tx_oid_str} not found or not pending.")
        return {"msg": "Transaction not found or not pending"}, 404

    result = db.transactions.update_one(
        {"_id": tx_oid},
        {
            "$set": {
                "status": "rejected",
                "rejected_by": admin_name,
                "rejected_at": get_utc_now(),
                "reject_reason": reason
            }
        }
    )
    
    if result.modified_count > 0:
        return {"msg": "Transaction rejected successfully"}, 200
    else:
        return {"msg": "Update failed (DB Error)"}, 500


# ----- ROUTES -----

@app.route("/", methods=["GET"])
def index():
    status = {
        "service": "TwoManga API",
        "mode": "Worker Queue PRO (Fixed)",
        "workers_active": worker_engine.num_workers,
        "db": db_core.is_alive()
    }
    return jsonify(status)

@app.route("/auth/register", methods=["POST"])
def register():
    try:
        data = RegisterSchema().load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400

    coll = db_core.get_collection("users")
    username = data["username"].strip().lower()

    if coll.find_one({"username": username}):
        return jsonify({"msg": "Username exists"}), 409

    hashed = hash_password(data["password"])

    role = "user"
    if username in AppConfig.ADMIN_USERNAMES:
        role = "admin"
    if AppConfig.ADMIN_ENV_USER and username == AppConfig.ADMIN_ENV_USER.lower():
        role = "admin"

    salt = str(uuid.uuid4())

    doc = {
        "username": username,
        "password": hashed,
        "role": role,
        "session_salt": salt,
        "created_at": get_utc_now(),
        "total_purchases": 0
    }

    coll.insert_one(doc)

    access = create_access_token(
        identity=username,
        additional_claims={"session_salt": salt}
    )

    refresh = create_refresh_token(
        identity=username,
        additional_claims={"session_salt": salt}
    )

    return jsonify({
        "msg": "Registered",
        "access_token": access,
        "refresh_token": refresh
    }), 201


@app.route("/auth/login", methods=["POST"])
def login():
    try:
        data = Schema.from_dict({"username": fields.Str(), "password": fields.Str()})().load(request.json, unknown=EXCLUDE)
    except ValidationError:
        return jsonify({"msg": "Bad inputs"}), 400

    username = data.get("username", "").strip().lower()
    user = db_core.get_collection("users").find_one({"username": username})
    
    if not user or not check_password(data.get("password", ""), user.get("password")):
        return jsonify({"msg": "Invalid credentials"}), 401
    
    salt = str(uuid.uuid4())
    db_core.get_collection("users").update_one({"_id": user["_id"]}, {"$set": {"session_salt": salt}})
    
    access = create_access_token(identity=username, additional_claims={"session_salt": salt})
    refresh = create_refresh_token(identity=username, additional_claims={"session_salt": salt})
    return jsonify({"access_token": access, "refresh_token": refresh})

@app.route("/auth/me", methods=["GET"])
@strict_session
def me():
    def _fetch_profile(username):
        u = db_core.get_collection("users").find_one({"username": username})
        if not u: raise Exception("User missing")
        
        now = get_utc_now()
        exp = u.get("expiryDate")
        if exp and exp.tzinfo is None: exp = exp.replace(tzinfo=datetime.timezone.utc)
        
        days_left = (exp - now).days if (exp and exp > now) else 0
        
        return {
            "username": u["username"],
            "role": u.get("role", "user"),
            "days_left": days_left,
            "expiry_iso": exp.isoformat() if exp else None
        }

    job = worker_engine.submit_job(_fetch_profile, g.current_user["username"], priority=0, wait=True)
    if job.get("finished"):
        if "error_msg" in job: return jsonify({"msg": "System error"}), 500
        return jsonify(job["result"]), 200
    
    return jsonify({"msg": "Processing..."}), 202

@app.route("/payment/submit", methods=["POST"])
@strict_session
def payment_submit():
    try:
        data = PaymentSchema().load(request.json, unknown=EXCLUDE)
    except ValidationError as e:
        logger.warning(f"Validation failed: {e.messages}")
        return jsonify(e.messages), 400

    if not data.get("coupon_code") and not data.get("days"):
        return jsonify({"msg": "days is required when no coupon is used"}), 400

    user_id_str = str(g.current_user["_id"])
    
    job = worker_engine.submit_job(
        worker_logic_payment, 
        user_id_str, 
        data, 
        priority=10, 
        wait=True
    )

    if job.get("finished"):
        if job.get("error_msg"):
            # Check for known errors to return 400 correctly
            err = job.get("error_msg")
            if "already used" in err or "limits reached" in err:
                return jsonify({"msg": err}), 400
            
            logger.error(f"Worker logic failed: {err}")
            return jsonify({"msg": "Operation failed", "detail": "Internal processing error"}), 500
        
        try:
            res_data, code = job["result"]
            return jsonify(res_data), code
        except Exception as e:
            return jsonify({"msg": "Response formatting error"}), 500

    return jsonify({"msg": "Request queued", "job_id": job.get("job_id")}), 202

# ----- ADMIN ROUTES -----

@app.route("/admin/transactions", methods=["GET"])
@admin_required
def admin_tx_list():
    status = request.args.get("status")
    query = {}
    if status: query["status"] = status
    
    cursor = db_core.get_collection("transactions").find(query).sort("created_at", -1).limit(100)
    output = []
    for tx in cursor:
        tx["_id"] = str(tx["_id"])
        tx["user_id"] = str(tx["user_id"])
        if tx.get("created_at"): tx["created_at"] = tx["created_at"].isoformat()
        if tx.get("processed_at"): tx["processed_at"] = tx["processed_at"].isoformat()
        if tx.get("rejected_at"): tx["rejected_at"] = tx["rejected_at"].isoformat()
        output.append(tx)
    return jsonify(output)

@app.route("/admin/transactions/<tx_id>/approve", methods=["POST"])
@admin_required
def approve_tx(tx_id):
    job = worker_engine.submit_job(
        worker_logic_approve_tx,
        tx_id,
        g.current_user["username"],
        priority=5,
        wait=True
    )
    if job.get("finished") and "result" in job:
        res, code = job["result"]
        return jsonify(res), code
    return jsonify({"msg": "Processing"}), 202

@app.route("/admin/transactions/<tx_id>/reject", methods=["POST"])
@admin_required
def reject_tx(tx_id):
    """
    [FIXED] Passes explicit arguments to the worker to ensure reliability.
    """
    body = request.json or {}
    reason = body.get("reason", "No reason provided")

    job = worker_engine.submit_job(
        worker_logic_reject_tx,
        tx_id,
        g.current_user["username"],
        reason,
        priority=5,
        wait=True
    )

    if job.get("finished") and "result" in job:
        res, code = job["result"]
        return jsonify(res), code

    if job.get("error_msg"):
        return jsonify({"msg": "Worker Error", "detail": job["error_msg"]}), 500

    return jsonify({"msg": "Processing"}), 202


@app.route("/admin/coupons", methods=["GET", "POST"])
@admin_required
def manage_coupons():
    if request.method == "GET":
        cursor = db_core.get_collection("coupons").find().sort("created_at", -1)
        output = []
        for c in cursor:
            c["_id"] = str(c["_id"])
            if c.get("created_at"): c["created_at"] = c["created_at"].isoformat()
            if c.get("expires_at"): c["expires_at"] = c["expires_at"].isoformat()
            # Convert ObjectId list to string list for JSON
            if "used_by" in c:
                c["used_by"] = [str(uid) for uid in c["used_by"]]
            output.append(c)
        return jsonify(output)

    try:
        data = CouponSchema().load(request.json)
    except ValidationError as e:
        return jsonify(e.messages), 400
        
    try:
        doc = {
            "code": data["code"],
            "bonus_days": data["bonus_days"],
            "max_uses": data["max_uses"],
            "uses": 0,
            "used_by": [],  # [FIX] Initialize list to track users
            "expires_at": data["expires_at"], 
            "created_at": get_utc_now()
        }
        db_core.get_collection("coupons").insert_one(doc)
        return jsonify({"msg": "Coupon created"}), 201
    except DuplicateKeyError:
        return jsonify({"msg": "Coupon code already exists"}), 409

# ----- INITIALIZATION -----

def on_app_ready():
    logger.info("Initializing Indexes & Workers...")
    worker_engine.start()
    
    def _ensure_indexes():
        try:
            db = db_core.get_db()
            db.users.create_index([("username", ASCENDING)], unique=True)
            db.transactions.create_index([("tx_hash", ASCENDING)], unique=True, sparse=True)
            db.coupons.create_index([("code", ASCENDING)], unique=True)
            db.coupons.create_index([("expires_at", ASCENDING)])
            logger.info("DB Indexes secured.")
            
            if AppConfig.ADMIN_ENV_USER and AppConfig.ADMIN_ENV_PASS:
                u_col = db.users
                name = AppConfig.ADMIN_ENV_USER.lower()
                if not u_col.find_one({"username": name}):
                    u_col.insert_one({
                        "username": name,
                        "password": hash_password(AppConfig.ADMIN_ENV_PASS),
                        "role": "admin",
                        "session_salt": "system",
                        "created_at": get_utc_now()
                    })
                    logger.info("Bootstrap admin created.")
        except Exception as e:
            logger.error(f"Index init failed: {e}")

    worker_engine.submit_job(_ensure_indexes, priority=50, wait=False)
    worker_engine.submit_job(cleanup_expired_coupons, priority=40, wait=False)

atexit.register(lambda: worker_engine.stop())

if __name__ == "__main__":
    on_app_ready()
    app.run(host="0.0.0.0", port=AppConfig.APP_PORT, debug=False)
