# two_manga_api_pro.py
# Two Manga API — Professional Queue Mode (Refixed)
# Fixes: Marshmallow Validation Crash, Admin Coupon List, Strong Type Checking

import os
import uuid
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
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, DuplicateKeyError
from bson.objectid import ObjectId
from bson.errors import InvalidId
import bcrypt

# ----- CONFIG & LOGGING -----
class AppConfig:
    MONGO_URI = os.getenv("MONGO_URI")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

    MONGO_DBNAME = os.getenv("MONGO_DBNAME", "twomanga")
    APP_PORT = int(os.getenv("PORT", "5001"))
    
    WORKER_COUNT = int(os.getenv("WORKER_COUNT", "4"))
    JOB_WAIT_SECONDS = float(os.getenv("JOB_WAIT_SECONDS", "8.0"))
    
    # Admins list from ENV (comma separated)
    ADMIN_USERNAMES = [u.strip().lower() for u in os.getenv("ADMIN_USERNAMES", "").split(",") if u.strip()]
    ADMIN_ENV_USER = os.getenv("ADMIN_USERNAME")
    ADMIN_ENV_PASS = os.getenv("ADMIN_PASSWORD")
    
    BCRYPT_ROUNDS = 12

if not AppConfig.MONGO_URI or not AppConfig.JWT_SECRET_KEY:
    raise RuntimeError("Critical: MONGO_URI or JWT_SECRET_KEY missing.")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("TwoMangaCore")

# ----- UTILITIES -----
def get_utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=AppConfig.BCRYPT_ROUNDS)).decode("utf-8")

def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, ObjectId):
        return str(obj)
    raise TypeError ("Type %s not serializable" % type(obj))

# ----- DB MANAGER -----
class MongoManager:
    def __init__(self, uri: str, db_name: str):
        self._uri = uri
        self._db_name = db_name
        self._client: Optional[MongoClient] = None
        self._db = None
        self._connect_lock = threading.Lock()

    def get_db(self):
        if self._db is not None:
            return self._db

        with self._connect_lock:
            if self._db is not None:
                return self._db
            try:
                self._client = MongoClient(self._uri, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
                self._client.admin.command('ping')
                try:
                    target_db = MongoClient(self._uri).get_default_database().name
                except:
                    target_db = self._db_name
                
                self._db = self._client[target_db]
                logger.info(f"DB Connected: {target_db}")
                return self._db
            except Exception as e:
                logger.critical(f"DB Connection failed: {e}")
                raise ConnectionFailure("Could not connect to database")

    def is_alive(self) -> bool:
        try:
            if self._client:
                self._client.admin.command('ping')
                return True
            return False
        except:
            return False
    
    def get_collection(self, name):
        return self.get_db()[name]

db_core = MongoManager(AppConfig.MONGO_URI, AppConfig.MONGO_DBNAME)

# ----- WORKER ENGINE -----
class JobWrapper:
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
                if job.priority == -1:
                    self.queue.task_done()
                    continue

                try:
                    result = job.func(*job.args, **job.kwargs)
                    if not job.future.done():
                        job.future.set_result(result)
                except Exception as e:
                    logger.error(f"Worker Error: {e}")
                    logger.debug(traceback.format_exc())
                    if not job.future.done():
                        job.future.set_exception(e)
                finally:
                    self.queue.task_done()
            except queue.Empty:
                continue

    def submit_job(self, func, *args, priority=10, wait=False, **kwargs) -> Dict[str, Any]:
        job = JobWrapper(priority, func, args, kwargs)
        self.queue.put(job)
        if not wait:
            return {"queued": True, "job_id": job.sequence}
        try:
            result = job.future.result(timeout=AppConfig.JOB_WAIT_SECONDS)
            return {"finished": True, "result": result}
        except TimeoutError:
            return {"finished": False, "msg": "Timeout processing job"}
        except Exception as e:
            return {"finished": True, "error_msg": str(e)}

worker_engine = WorkerEngine(AppConfig.WORKER_COUNT)

# ----- SCHEMAS (FIXED) -----
# FIX: Added **kwargs to validators to prevent "unexpected keyword argument" errors
class RegisterSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    
    @validates("username")
    def validate_username(self, val, **kwargs):
        if len(val.strip()) < 3 or " " in val:
            raise ValidationError("Invalid username format")

class PaymentSchema(Schema):
    days = fields.Int(required=True)
    tx_hash = fields.Str(load_default=None)
    coupon_code = fields.Str(load_default=None)

    @validates("days")
    def validate_days(self, val, **kwargs):
        # FIX: **kwargs catches unexpected arguments from Marshmallow internals
        if val < 1 or val > 3650:
            raise ValidationError("Days must be between 1-3650")

class CouponSchema(Schema):
    code = fields.Str(required=True)
    bonus_days = fields.Int(required=True)
    max_uses = fields.Int(load_default=None, allow_none=True)
    expires_at = fields.DateTime(load_default=None, allow_none=True)

# ----- FLASK APP -----
app = Flask(__name__)
app.config["MONGO_URI"] = AppConfig.MONGO_URI
app.config["JWT_SECRET_KEY"] = AppConfig.JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=4)

jwt = JWTManager(app)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# ----- MIDDLEWARE -----
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        ident = get_jwt_identity()
        user = db_core.get_collection("users").find_one({"username": ident.lower()})
        
        is_admin = False
        if user and user.get("role") == "admin": is_admin = True
        if ident in AppConfig.ADMIN_USERNAMES: is_admin = True
        if AppConfig.ADMIN_ENV_USER and ident == AppConfig.ADMIN_ENV_USER.lower(): is_admin = True

        if is_admin:
            g.current_user = user
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
             return jsonify({"msg": "Session invalid"}), 401
        g.current_user = user
        return fn(*args, **kwargs)
    return wrapper

# ----- WORKER LOGIC -----
def worker_logic_payment(user_id_str, data):
    db = db_core.get_db()
    users = db.users
    coupons = db.coupons
    transactions = db.transactions

    user_oid = ObjectId(user_id_str)
    user = users.find_one({"_id": user_oid})
    if not user:
        return {"msg": "User not found"}, 404

    coupon_code = data.get("coupon_code")
    days = data.get("days")
    tx_hash = data.get("tx_hash")

    # 1. Coupon Logic
    if coupon_code:
        # Check atomic coupon validity
        c_doc = coupons.find_one({"code": coupon_code})
        if not c_doc:
            return {"msg": "Invalid coupon code"}, 400
        
        now_utc = get_utc_now()
        exp_at = c_doc.get("expires_at")
        # Ensure exp_at is timezone aware for comparison
        if exp_at and exp_at.replace(tzinfo=datetime.timezone.utc) < now_utc:
            return {"msg": "Coupon expired"}, 400
        
        if c_doc.get("max_uses") is not None and c_doc.get("uses", 0) >= c_doc["max_uses"]:
            return {"msg": "Coupon usage limit reached"}, 400

        # Apply
        bonus = c_doc.get("bonus_days", 0)
        curr_expiry = user.get("expiryDate")
        if curr_expiry:
             # Force tz aware
            if curr_expiry.tzinfo is None:
                curr_expiry = curr_expiry.replace(tzinfo=datetime.timezone.utc)
            start_point = curr_expiry if curr_expiry > now_utc else now_utc
        else:
            start_point = now_utc

        new_expiry = start_point + datetime.timedelta(days=bonus)
        
        # Two-step Update
        users.update_one({"_id": user_oid}, {
            "$set": {"expiryDate": new_expiry}, 
            "$inc": {"total_purchases": 1}
        })
        coupons.update_one({"_id": c_doc["_id"]}, {"$inc": {"uses": 1}})
        
        return {
            "msg": "Coupon applied successfully",
            "new_expiry": new_expiry.isoformat()
        }, 200

    # 2. TX Logic
    if not tx_hash:
        return {"msg": "TX Hash required if no coupon"}, 400

    if transactions.find_one({"tx_hash": tx_hash}):
        return {"msg": "Transaction hash already exists"}, 409
    
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
        "msg": "Transaction submitted",
        "tx_id": str(new_tx.inserted_id)
    }, 201

# ----- ROUTES -----
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "online",
        "worker_engine": "active",
        "workers": worker_engine.num_workers
    })

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
        
    doc = {
        "username": username,
        "password": hash_password(data["password"]),
        "role": "admin" if username in AppConfig.ADMIN_USERNAMES else "user",
        "session_salt": str(uuid.uuid4()),
        "created_at": get_utc_now(),
        "total_purchases": 0
    }
    coll.insert_one(doc)
    return jsonify({"msg": "Registered"}), 201

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "").strip().lower()
    user = db_core.get_collection("users").find_one({"username": username})
    
    if not user or not check_password(data.get("password", ""), user.get("password")):
        return jsonify({"msg": "Invalid credentials"}), 401
    
    salt = str(uuid.uuid4())
    db_core.get_collection("users").update_one({"_id": user["_id"]}, {"$set": {"session_salt": salt}})
    return jsonify({
        "access_token": create_access_token(identity=username, additional_claims={"session_salt": salt}),
        "refresh_token": create_refresh_token(identity=username, additional_claims={"session_salt": salt})
    })

@app.route("/payment/submit", methods=["POST"])
@strict_session
def payment_submit():
    # 1. Validation Schema
    try:
        # FIX: Validate inputs safely first
        data = PaymentSchema().load(request.json, unknown=EXCLUDE)
    except ValidationError as e:
        logger.warning(f"Payment Validation Error: {e.messages}")
        return jsonify(e.messages), 400
    except Exception as e:
        logger.error(f"Unexpected Schema Error: {e}")
        return jsonify({"msg": "Invalid Request Data"}), 400

    # 2. Worker Execution
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
            logger.error(f"Payment Logic Error: {job.get('error_msg')}")
            return jsonify({"msg": "Internal Process Error"}), 500
        
        # Result contains (body_dict, status_code)
        res_data, code = job["result"]
        return jsonify(res_data), code

    return jsonify({"msg": "Processing queued...", "job_id": job.get("job_id")}), 202

# ----- ADMIN ROUTES -----
# FIX: Added separate GET handler for coupon listing
@app.route("/admin/coupons", methods=["GET"])
@admin_required
def get_coupons():
    try:
        cursor = db_core.get_collection("coupons").find().sort("created_at", -1)
        results = []
        for c in cursor:
            # Safe Serialization
            c["_id"] = str(c["_id"])
            if c.get("created_at"): c["created_at"] = c["created_at"].isoformat()
            if c.get("expires_at"): c["expires_at"] = c["expires_at"].isoformat()
            results.append(c)
        return jsonify(results), 200
    except Exception as e:
        logger.error(f"Coupon List Error: {e}")
        return jsonify({"msg": "Failed to fetch coupons"}), 500

@app.route("/admin/coupons", methods=["POST"])
@admin_required
def create_coupon():
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
            "expires_at": data["expires_at"], 
            "created_at": get_utc_now()
        }
        db_core.get_collection("coupons").insert_one(doc)
        return jsonify({"msg": "Coupon created"}), 201
    except DuplicateKeyError:
        return jsonify({"msg": "Code already exists"}), 409

@app.route("/admin/transactions", methods=["GET"])
@admin_required
def list_tx():
    cursor = db_core.get_collection("transactions").find().sort("created_at", -1).limit(50)
    res = []
    for tx in cursor:
        tx["_id"] = str(tx["_id"])
        tx["user_id"] = str(tx["user_id"])
        if "created_at" in tx: tx["created_at"] = tx["created_at"].isoformat()
        res.append(tx)
    return jsonify(res)

@app.route("/admin/transactions/<tx_id>/approve", methods=["POST"])
@admin_required
def approve_tx_route(tx_id):
    def _approve_logic(tid, adm):
        db = db_core.get_db()
        try:
            toid = ObjectId(tid)
        except:
            return {"msg": "Bad ID"}, 400
            
        tx = db.transactions.find_one({"_id": toid, "status": "pending"})
        if not tx: return {"msg": "Not found or not pending"}, 404
        
        user = db.users.find_one({"_id": tx["user_id"]})
        if not user: return {"msg": "User missing"}, 404
        
        # Time calc
        now = get_utc_now()
        current_exp = user.get("expiryDate")
        if current_exp:
             if current_exp.tzinfo is None:
                 current_exp = current_exp.replace(tzinfo=datetime.timezone.utc)
             start = current_exp if current_exp > now else now
        else:
             start = now
             
        new_exp = start + datetime.timedelta(days=tx["days"])
        
        db.users.update_one({"_id": user["_id"]}, {
            "$set": {"expiryDate": new_exp},
            "$inc": {"total_purchases": 1}
        })
        db.transactions.update_one({"_id": toid}, {
            "$set": {"status": "approved", "approver": adm, "processed_at": now}
        })
        return {"msg": "Approved", "expiry": new_exp.isoformat()}, 200

    job = worker_engine.submit_job(_approve_logic, tx_id, g.current_user["username"], priority=1, wait=True)
    if job.get("finished") and "result" in job:
        data, code = job["result"]
        return jsonify(data), code
    return jsonify({"msg": "Error"}), 500

# ----- BOOT -----
def init_db_indexes():
    # Helper to run index creation in worker
    def _do_index():
        try:
            db = db_core.get_db()
            db.users.create_index("username", unique=True)
            db.transactions.create_index("tx_hash", unique=True, sparse=True)
            db.coupons.create_index("code", unique=True)
            logger.info("Indexes Verified.")
            
            # Auto-create env admin
            if AppConfig.ADMIN_ENV_USER:
                u = AppConfig.ADMIN_ENV_USER.lower()
                if not db.users.find_one({"username": u}):
                    db.users.insert_one({
                        "username": u,
                        "password": hash_password(AppConfig.ADMIN_ENV_PASS or "admin123"),
                        "role": "admin",
                        "session_salt": "system",
                        "created_at": get_utc_now()
                    })
                    logger.info("Admin bootstrap created.")
        except Exception as e:
            logger.error(f"Index error: {e}")

    worker_engine.submit_job(_do_index, priority=20)

atexit.register(lambda: worker_engine.stop())

if __name__ == "__main__":
    worker_engine.start()
    init_db_indexes()
    app.run(host="0.0.0.0", port=AppConfig.APP_PORT, debug=False)
