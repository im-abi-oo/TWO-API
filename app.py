# two_manga_api_final_queue.py
"""
Two Manga API - final production-ready single-file version with in-process priority queue.
Features:
 - No global rate limiting.
 - In-memory prioritized request queue (no Redis) with worker threads.
 - /me (auth/me) is high priority and will wait a short time for processing result.
 - Admin auth: JWT as before OR Basic Auth using ADMIN_USERNAME / ADMIN_PASSWORD env.
 - DBManager robust connection + monitor thread.
 - All env notes are below.
"""

import os
import uuid
import json
import logging
import traceback
import datetime
import re
import time
import threading
import base64
import queue
from functools import wraps
from typing import Optional, Any, Callable, Tuple

from flask import Flask, request, jsonify, g
from flask_pymongo import PyMongo
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_cors import CORS
from marshmallow import Schema, fields, ValidationError, validates
from pymongo import ASCENDING, DESCENDING, errors as pymongo_errors
from bson.objectid import ObjectId
import bcrypt
import requests
from pymongo import MongoClient

# -------------------------
# ENVIRONMENT / CONFIG NOTES
# -------------------------
# Required:
#   MONGO_URI          - MongoDB connection URI
#   JWT_SECRET_KEY     - long random secret for JWT
#
# Optional / recommended:
#   MONGO_DBNAME (default "twomanga")
#   PORT (default 5001)
#   ADMIN_USERNAMES    - comma-separated usernames to mark existing users as admin
#   ADMIN_USERNAME     - single admin username to create/update at startup
#   ADMIN_PASSWORD     - password for ADMIN_USERNAME (store securely in env)
#   EXPLORER_URLS      - comma-separated templates with {tx_hash} for auto verification (leave empty for manual)
#   WORKER_COUNT       - number of queue worker threads (default 4)
#   JOB_WAIT_SECONDS   - secs endpoints wait for job result before returning queued (default 5)
#   DB_PING_INTERVAL, DB_CONNECT_RETRIES, DB_CONNECT_TIMEOUT_MS - DB tuning
#
# Security note:
#   - ADMIN_USERNAME/ADMIN_PASSWORD must be set as secrets on hosting platform.
#   - Always use HTTPS when using Basic Auth.

# ---------- Configuration & Logging ----------

def getenv_required(key: str) -> str:
    v = os.getenv(key)
    if not v:
        raise RuntimeError(f"Missing required environment variable: {key}")
    return v

# required envs
MONGO_URI = getenv_required("MONGO_URI")
JWT_SECRET_KEY = getenv_required("JWT_SECRET_KEY")

# optionals
MONGO_DBNAME = os.getenv("MONGO_DBNAME", "twomanga")
APP_PORT = int(os.getenv("PORT", "5001"))
ADMIN_USERNAMES = [u.strip().lower() for u in os.getenv("ADMIN_USERNAMES", "").split(",") if u.strip()]
ADMIN_ENV_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_ENV_PASSWORD = os.getenv("ADMIN_PASSWORD")

BRSAPI_KEY = os.getenv("BRSAPI_KEY", "")
BRSAPI_URL = os.getenv("BRSAPI_URL", "https://BrsApi.ir/Api/Market/Gold_Currency.php")
NOBITEX_STATS_URL = os.getenv("NOBITEX_STATS_URL", "https://apiv2.nobitex.ir/market/stats")
API_LOCAL_RATES = os.getenv("API_LOCAL_RATES", "/public/rates")
EXPLORER_URLS = os.getenv("EXPLORER_URLS", "")

ENABLE_RATE_SCHEDULER = os.getenv("ENABLE_RATE_SCHEDULER", "false").lower() == "true"
RATE_FETCH_MINUTES = int(os.getenv("RATE_FETCH_MINUTES", "60"))

# DB manager tuning
DB_PING_INTERVAL = int(os.getenv("DB_PING_INTERVAL", "30"))
DB_CONNECT_RETRIES = int(os.getenv("DB_CONNECT_RETRIES", "5"))
DB_CONNECT_TIMEOUT_MS = int(os.getenv("DB_CONNECT_TIMEOUT_MS", "5000"))

BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))

# Queue config
WORKER_COUNT = int(os.getenv("WORKER_COUNT", "4"))
JOB_WAIT_SECONDS = float(os.getenv("JOB_WAIT_SECONDS", "5.0"))

FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "http://localhost:3000")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
logger = logging.getLogger("two-manga-backend")

# ---------- Flask App & Extensions ----------
app = Flask(__name__)
app.config["MONGO_URI"] = MONGO_URI
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=int(os.getenv("ACCESS_EXPIRES_HOURS", "4")))
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(days=int(os.getenv("REFRESH_EXPIRES_DAYS", "30")))

mongo = PyMongo(app)
jwt = JWTManager(app)

# CORS
origins_raw = FRONTEND_ORIGINS.strip()
if origins_raw == "*" or origins_raw == "":
    origins = "*"
else:
    origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
CORS(app, resources={r"/*": {"origins": origins}}, supports_credentials=True)

# ---------- Schemas ----------
class RegisterSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)
    @validates("username")
    def check_username(self, value, **kwargs):
        if not value or len(value.strip()) < 3:
            raise ValidationError("username must be at least 3 characters")
        if " " in value:
            raise ValidationError("username must not contain spaces")
    @validates("password")
    def check_password(self, value, **kwargs):
        if not value or len(value) < 6:
            raise ValidationError("password must be at least 6 characters")

class LoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)

class PaymentSubmitSchema(Schema):
    tx_hash = fields.Str(required=False, allow_none=True)
    coupon_code = fields.Str(required=False, allow_none=True)
    days = fields.Int(required=True)
    @validates("days")
    def check_days(self, value, **kwargs):
        if value is None or value <= 0 or value > 3650:
            raise ValidationError("days must be between 1 and 3650")

# ---------- Helpers ----------
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")
def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False
try:
    FAKE_PASSWORD_HASH = bcrypt.hashpw(b"fake_password_for_timing_mitigation", bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")
except Exception:
    FAKE_PASSWORD_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.2uQf7Pn6y6Gk1v4b6ZJdXb0sZr7Qe6"

class DatabaseUnavailable(Exception):
    pass
def parse_dbname_from_uri(uri: str) -> Optional[str]:
    m = re.search(r"/([^/?]+)(?:\?|$)", uri)
    return m.group(1) if m else None

# ---------- DB Manager ----------
class DBManager:
    def __init__(self, uri: str, default_dbname: str, ping_interval: int = 30, connect_timeout_ms: int = 5000, retries: int = 5):
        self.uri = uri
        self.default_dbname = default_dbname
        self.ping_interval = ping_interval
        self.connect_timeout_ms = connect_timeout_ms
        self.retries = retries
        self._client: Optional[MongoClient] = None
        self._db = None
        self._lock = threading.Lock()
        self._available = False
        self._last_error: Optional[str] = None
        self._last_ping: Optional[float] = None
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
    def _connect_once(self) -> bool:
        try:
            try:
                if hasattr(mongo, "cx") and mongo.cx is not None:
                    mongo.cx.admin.command("ping")
                    if hasattr(mongo, "db") and mongo.db is not None:
                        self._client = mongo.cx
                        self._db = mongo.db
                        logger.info("DBManager: using Flask-PyMongo client/db")
                        return True
            except Exception as e:
                logger.debug("DBManager: Flask-PyMongo ping failed: %s", str(e))
            client = MongoClient(self.uri, serverSelectionTimeoutMS=self.connect_timeout_ms)
            client.admin.command("ping")
            db = client.get_default_database()
            if db is None:
                parsed = parse_dbname_from_uri(self.uri)
                chosen = parsed or self.default_dbname
                db = client[chosen]
                logger.warning("DBManager: no default DB in URI; using '%s' as fallback DB name", chosen)
            self._client = client
            self._db = db
            logger.info("DBManager: connected to MongoDB (direct client)")
            return True
        except Exception as e:
            self._last_error = str(e)
            logger.warning("DBManager: direct MongoClient ping failed: %s", self._last_error)
            return False
    def connect(self) -> bool:
        with self._lock:
            for attempt in range(1, self.retries + 1):
                ok = self._connect_once()
                if ok:
                    self._available = True
                    self._last_ping = time.time()
                    self._last_error = None
                    return True
                else:
                    logger.debug("DBManager: connect attempt %d/%d failed", attempt, self.retries)
                    time.sleep(0.2 * attempt)
            self._available = False
            return False
    def is_available(self) -> bool:
        return self._available
    def get_collection(self, name: str):
        if not self.is_available() or self._db is None:
            if not self.connect():
                raise DatabaseUnavailable("MongoDB not available")
        try:
            now = time.time()
            if self._last_ping is None or (now - self._last_ping) > max(1, self.ping_interval):
                try:
                    self._client.admin.command("ping")
                    self._last_ping = now
                except Exception as e:
                    logger.warning("DBManager: ping failed in get_collection: %s", str(e))
                    self._available = False
                    self._last_error = str(e)
                    raise DatabaseUnavailable("MongoDB ping failed")
            return self._db[name]
        except DatabaseUnavailable:
            raise
        except Exception as e:
            self._last_error = str(e)
            logger.exception("DBManager: unexpected error in get_collection")
            raise DatabaseUnavailable("MongoDB error")
    def _monitor_loop(self):
        while True:
            try:
                if self._client:
                    try:
                        self._client.admin.command("ping")
                        self._available = True
                        self._last_ping = time.time()
                        self._last_error = None
                    except Exception as e:
                        logger.debug("DBManager monitor: ping failed: %s", str(e))
                        self._available = False
                        self._last_error = str(e)
                        self.connect()
                else:
                    self.connect()
            except Exception:
                logger.exception("DBManager monitor loop error")
            time.sleep(max(1, self.ping_interval))
    def status(self) -> dict:
        return {
            "available": bool(self._available),
            "last_ping_at": datetime.datetime.utcfromtimestamp(self._last_ping).isoformat() if self._last_ping else None,
            "last_error": self._last_error
        }

db_manager = DBManager(MONGO_URI, MONGO_DBNAME, ping_interval=DB_PING_INTERVAL, connect_timeout_ms=DB_CONNECT_TIMEOUT_MS, retries=DB_CONNECT_RETRIES)

# ---------- DB Setup ----------
def setup_database_indexes_safe():
    try:
        users = db_manager.get_collection("users")
        transactions = db_manager.get_collection("transactions")
        coupons = db_manager.get_collection("coupons")
        rates = db_manager.get_collection("rates")
        users.create_index([("username", ASCENDING)], unique=True)
        transactions.create_index([("tx_hash", ASCENDING)], unique=True, sparse=True)
        coupons.create_index([("code", ASCENDING)], unique=True)
        rates.create_index([("ts", DESCENDING)])
        logger.info("Indexes ensured (safe setup).")
    except DatabaseUnavailable:
        logger.warning("setup_database_indexes_safe: DB not available at startup; indexes skipped for now.")
    except Exception:
        logger.exception("setup_database_indexes_safe failed")

def seed_admin_roles_safe():
    if ADMIN_USERNAMES:
        try:
            users = db_manager.get_collection("users")
        except DatabaseUnavailable:
            logger.warning("seed_admin_roles_safe: DB not available; skipping admin seeding.")
            return
        for u in ADMIN_USERNAMES:
            try:
                users.update_one({"username": u}, {"$set": {"role": "admin"}}, upsert=False)
            except Exception:
                logger.exception("Failed applying admin role for %s", u)
        logger.info("Admin usernames applied to existing users (if present).")

def ensure_env_admin_account():
    if not (ADMIN_ENV_USERNAME and ADMIN_ENV_PASSWORD):
        return
    try:
        users = db_manager.get_collection("users")
    except DatabaseUnavailable:
        logger.warning("ensure_env_admin_account: DB not available; skipping env-admin creation.")
        return
    username = ADMIN_ENV_USERNAME.strip().lower()
    if not username:
        return
    try:
        hashed = hash_password(ADMIN_ENV_PASSWORD)
        now = datetime.datetime.utcnow()
        users.update_one(
            {"username": username},
            {"$set": {
                "username": username,
                "password": hashed,
                "role": "admin",
                "session_salt": str(uuid.uuid4()),
                "created_at": now
            }},
            upsert=True
        )
        logger.info("Env admin account ensured for username=%s", username)
    except Exception:
        logger.exception("Failed to ensure env admin account")

try:
    setup_database_indexes_safe()
    seed_admin_roles_safe()
    ensure_env_admin_account()
except Exception:
    logger.exception("Database setup failed at startup")

# ---------- Error handlers ----------
@app.errorhandler(ValidationError)
def handle_validation_error(err):
    return jsonify({"msg": "validation error", "errors": err.messages}), 400
@app.errorhandler(404)
def handle_404(e):
    return jsonify({"msg": "endpoint not found"}), 404
@app.errorhandler(DatabaseUnavailable)
def handle_db_unavailable(e):
    return jsonify({"msg": "database unavailable"}), 503
@app.errorhandler(Exception)
def global_exception_handler(e):
    tb = traceback.format_exc()
    logger.error("Unhandled exception: %s\n%s", str(e), tb)
    return jsonify({"msg": "internal server error"}), 500

# ---------- Request guard ----------
@app.before_request
def ensure_db_available_for_routes():
    if request.method == "OPTIONS" or request.path in ("/", "/debug/ping", "/debug/db-status"):
        return None
    if not db_manager.is_available():
        try:
            db_manager.connect()
        except Exception:
            pass
        if not db_manager.is_available():
            return jsonify({"msg": "database unavailable"}), 503
    return None

# ---------- Auth utilities ----------
def to_objectid(val: str) -> Optional[ObjectId]:
    try:
        return ObjectId(val)
    except Exception:
        return None

def _basic_auth_from_request():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return None, None
    try:
        b64 = auth.split(" ", 1)[1].strip()
        decoded = base64.b64decode(b64).decode("utf-8")
        username, password = decoded.split(":", 1)
        return username.strip().lower(), password
    except Exception:
        return None, None

def _is_request_basic_admin():
    if not (ADMIN_ENV_USERNAME and ADMIN_ENV_PASSWORD):
        return False
    u, p = _basic_auth_from_request()
    if not u or not p:
        return False
    return u == ADMIN_ENV_USERNAME.strip().lower() and p == ADMIN_ENV_PASSWORD

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            identity = None
            try:
                identity = get_jwt_identity()
            except Exception:
                identity = None
            if identity:
                users = db_manager.get_collection("users")
                user = users.find_one({"username": identity})
                if user and (user.get("role") == "admin" or identity.lower() in ADMIN_USERNAMES):
                    g.current_user = user
                    return fn(*args, **kwargs)
                return jsonify({"msg": "admin required"}), 403
            if _is_request_basic_admin():
                g.current_user = {"username": ADMIN_ENV_USERNAME.strip().lower(), "role": "admin", "_env_admin": True}
                return fn(*args, **kwargs)
            return jsonify({"msg": "unauthorized"}), 401
        except DatabaseUnavailable:
            return jsonify({"msg": "database unavailable"}), 503
        except Exception:
            logger.exception("admin_required failure")
            return jsonify({"msg": "authentication failed"}), 401
    return wrapper

def single_session_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            claims = get_jwt()
            identity = get_jwt_identity()
            if not identity:
                return jsonify({"msg": "unauthorized"}), 401
            users = db_manager.get_collection("users")
            user = users.find_one({"username": identity}, {"session_salt": 1})
            if not user:
                return jsonify({"msg": "user not found"}), 401
            if claims.get("session_salt") != user.get("session_salt"):
                return jsonify({"msg": "session invalidated"}), 401
            g.current_user = users.find_one({"username": identity})
            return fn(*args, **kwargs)
        except DatabaseUnavailable:
            return jsonify({"msg": "database unavailable"}), 503
        except Exception:
            logger.exception("single_session_required error")
            return jsonify({"msg": "authentication error"}), 401
    return wrapper

# ---------- Priority Queue Implementation (in-process) ----------
# Lower priority number => executed earlier
_job_seq = 0
_job_seq_lock = threading.Lock()

class Job:
    def __init__(self, priority: int, func: Callable, args: Tuple = (), kwargs: dict = None, wait_for_result: bool = False):
        global _job_seq
        with _job_seq_lock:
            self.seq = _job_seq
            _job_seq += 1
        self.priority = int(priority)
        self.func = func
        self.args = args or ()
        self.kwargs = kwargs or {}
        self.wait_for_result = wait_for_result
        self._event = threading.Event() if wait_for_result else None
        self._result = None
        self._exc = None
    def run(self):
        try:
            res = self.func(*self.args, **self.kwargs)
            if self.wait_for_result:
                self._result = res
        except Exception as e:
            self._exc = e
            logger.exception("Job execution exception")
        finally:
            if self.wait_for_result:
                self._event.set()
    def wait(self, timeout: Optional[float] = None):
        if not self.wait_for_result or not self._event:
            return None
        finished = self._event.wait(timeout=timeout)
        if not finished:
            return None
        if self._exc:
            raise self._exc
        return self._result

class PriorityJobQueue:
    def __init__(self):
        self._pq = queue.PriorityQueue()
    def put(self, job: Job):
        # priority ordering: (priority, seq)
        self._pq.put((job.priority, job.seq, job))
    def get(self, block=True, timeout=None) -> Job:
        _, _, job = self._pq.get(block=block, timeout=timeout)
        return job
    def task_done(self):
        self._pq.task_done()
    def qsize(self):
        return self._pq.qsize()

job_queue = PriorityJobQueue()

# Worker threads
_worker_threads = []
_worker_stop = threading.Event()

def _worker_loop(worker_id: int):
    logger.info("Worker %d starting", worker_id)
    while not _worker_stop.is_set():
        try:
            job = job_queue.get(block=True, timeout=1.0)
        except queue.Empty:
            continue
        try:
            job.run()
        except Exception:
            logger.exception("Unhandled exception in job.run")
        finally:
            job_queue.task_done()
    logger.info("Worker %d stopping", worker_id)

def start_workers(count: int):
    for i in range(count):
        t = threading.Thread(target=_worker_loop, args=(i,), daemon=True)
        _worker_threads.append(t)
        t.start()
    logger.info("Started %d worker threads", count)

def stop_workers():
    _worker_stop.set()
    # join with timeout
    for t in _worker_threads:
        t.join(timeout=1.0)

# Start workers at import/run
start_workers(WORKER_COUNT)

# ---------- Utility: enqueue and optionally wait ----------
def enqueue_job(func: Callable, args: Tuple = (), kwargs: dict = None, priority: int = 50, wait: bool = False, wait_timeout: float = JOB_WAIT_SECONDS):
    """
    priority: lower number = higher priority (0 is highest)
    wait: if True, block current request thread until job finishes or timeout
    """
    job = Job(priority=priority, func=func, args=args, kwargs=kwargs or {}, wait_for_result=wait)
    job_queue.put(job)
    if wait:
        try:
            res = job.wait(timeout=wait_timeout)
            return {"finished": res is not None, "result": res}
        except Exception as e:
            logger.exception("Exception from job when waiting")
            return {"finished": False, "error": str(e)}
    return {"queued": True, "job_seq": job.seq}

# ---------- Health & Debug ----------
@app.route("/")
def health():
    return jsonify({"status": "ok", "server": "Two Manga API", "queue_size": job_queue.qsize()}), 200

@app.route("/debug/ping", methods=["GET"])
def ping():
    return jsonify({"msg": "pong"}), 200

@app.route("/debug/db-status", methods=["GET"])
def db_status():
    return jsonify(db_manager.status()), 200

# ---------- Auth & User Routes ----------
@app.route("/auth/register", methods=["POST"])
def register():
    try:
        users = db_manager.get_collection("users")
        payload = request.get_json(force=True)
        data = RegisterSchema().load(payload)
        username = data["username"].strip().lower()
        password = data["password"]
        existing = users.find_one({"username": username})
        if existing:
            return jsonify({"msg": "username already exists"}), 409
        hashed = hash_password(password)
        now = datetime.datetime.utcnow()
        user_doc = {
            "username": username,
            "password": hashed,
            "created_at": now,
            "session_salt": str(uuid.uuid4()),
            "role": "admin" if username in ADMIN_USERNAMES else "user",
            "expiryDate": None,
            "total_purchases": 0
        }
        users.insert_one(user_doc)
        return jsonify({"msg": "registered"}), 201
    except ValidationError as ve:
        return jsonify({"msg": "validation failed", "errors": ve.messages}), 400
    except pymongo_errors.DuplicateKeyError:
        return jsonify({"msg": "username already exists"}), 409
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("register error")
        return jsonify({"msg": "internal error"}), 500

@app.route("/auth/login", methods=["POST"])
def login():
    try:
        users = db_manager.get_collection("users")
        payload = request.get_json(force=True)
        data = LoginSchema().load(payload)
        username = data["username"].strip().lower()
        password = data["password"]
        user = users.find_one({"username": username})
        hash_to_check = user["password"] if user else FAKE_PASSWORD_HASH
        pw_ok = check_password(password, hash_to_check)
        if not user or not pw_ok:
            return jsonify({"msg": "invalid credentials"}), 401
        salt = str(uuid.uuid4())
        users.update_one({"_id": user["_id"]}, {"$set": {"session_salt": salt}})
        access = create_access_token(identity=username, additional_claims={"session_salt": salt})
        refresh = create_refresh_token(identity=username, additional_claims={"session_salt": salt})
        return jsonify({"access_token": access, "refresh_token": refresh}), 200
    except ValidationError as ve:
        return jsonify({"msg": "validation failed", "errors": ve.messages}), 400
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("login error")
        return jsonify({"msg": "internal error"}), 500

@app.route("/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        users = db_manager.get_collection("users")
        claims = get_jwt()
        identity = get_jwt_identity()
        if not identity:
            return jsonify({"msg": "unauthorized"}), 401
        user = users.find_one({"username": identity}, {"session_salt": 1})
        if not user:
            return jsonify({"msg": "user not found"}), 404
        if claims.get("session_salt") != user.get("session_salt"):
            return jsonify({"msg": "refresh token invalidated"}), 401
        access = create_access_token(identity=identity, additional_claims={"session_salt": user.get("session_salt")})
        return jsonify({"access_token": access}), 200
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("refresh error")
        return jsonify({"msg": "internal error"}), 500

# ---------- Core: /me endpoint via queue (highest priority) ----------
def _process_me(username: str):
    # quick DB read - keep this function fast
    users = db_manager.get_collection("users")
    user = users.find_one({"username": username})
    if not user:
        return {"msg": "user not found"}, 404
    now = datetime.datetime.utcnow()
    exp = user.get("expiryDate")
    is_premium = bool(exp and exp > now)
    days_left = (exp - now).days if is_premium else 0
    return {
        "username": user.get("username"),
        "role": user.get("role", "user"),
        "is_premium": is_premium,
        "days_left": days_left,
        "expiry_date": exp.isoformat() if isinstance(exp, datetime.datetime) else None,
        "created_at": user.get("created_at").isoformat() if isinstance(user.get("created_at"), datetime.datetime) else None,
        "total_purchases": int(user.get("total_purchases", 0))
    }, 200

@app.route("/auth/me", methods=["GET"])
@jwt_required()
@single_session_required
def auth_me():
    # this endpoint has highest priority: priority 0
    identity = get_jwt_identity()
    # enqueue job and WAIT for short time (JOB_WAIT_SECONDS). If worker processes quickly, returns real result.
    # If worker is busy and timeout occurs, return queued status to client.
    try:
        result = enqueue_job(func=_process_me, args=(identity,), priority=0, wait=True, wait_timeout=JOB_WAIT_SECONDS)
        if result.get("finished"):
            resp_body, status_code = result.get("result")
            return jsonify(resp_body), status_code
        else:
            # queued (worker couldn't finish within timeout)
            return jsonify({"msg": "processing queued", "note": "will be available shortly"}), 202
    except Exception:
        logger.exception("auth_me queued error")
        return jsonify({"msg": "internal error"}), 500

# ---------- Payment & coupons (enqueue medium priority) ----------
def verify_tx_on_chain(tx_hash: str) -> bool:
    try:
        if not tx_hash or len(tx_hash) < 8:
            return False
        if EXPLORER_URLS:
            urls = [u.strip() for u in EXPLORER_URLS.split(",") if u.strip()]
            for template in urls:
                try:
                    url = template.replace("{tx_hash}", tx_hash)
                    r = requests.get(url, timeout=5)
                    if r.status_code == 200:
                        logger.info("Explorer validated tx via %s", url)
                        return True
                except Exception:
                    continue
            return False
        logger.warning("No EXPLORER_URLS configured; verify_tx_on_chain returns False by default (manual admin approval required).")
        return False
    except Exception:
        logger.exception("verify_tx_on_chain error")
        return False

def _process_submit_payment(user_obj, payload):
    # This runs in worker thread; keep DB calls here.
    users = db_manager.get_collection("users")
    coupons = db_manager.get_collection("coupons")
    transactions = db_manager.get_collection("transactions")
    data = payload  # already validated externally
    user = user_obj
    tx_hash = (data.get("tx_hash") or "").strip() or None
    coupon = (data.get("coupon_code") or "").strip() or None
    days = int(data.get("days"))
    if coupon:
        c = coupons.find_one({"code": coupon})
        if not c:
            return {"msg": "invalid coupon"}, 400
        now = datetime.datetime.utcnow()
        if c.get("expires_at") and c["expires_at"] < now:
            return {"msg": "coupon expired"}, 400
        max_uses = c.get("max_uses")
        uses = c.get("uses", 0)
        if max_uses and uses >= max_uses:
            return {"msg": "coupon use limit reached"}, 400
        start = user.get("expiryDate") if (user.get("expiryDate") and user["expiryDate"] > now) else now
        new_exp = start + datetime.timedelta(days=c.get("bonus_days", days))
        users.update_one({"_id": user["_id"]}, {"$set": {"expiryDate": new_exp}, "$inc": {"total_purchases": 1}})
        coupons.update_one({"_id": c["_id"]}, {"$inc": {"uses": 1}})
        return {"msg": "coupon applied", "expiry_date": new_exp.isoformat()}, 200
    if not tx_hash:
        return {"msg": "tx_hash or coupon required"}, 400
    if transactions.find_one({"tx_hash": tx_hash}):
        return {"msg": "tx_hash already submitted"}, 400
    verified = verify_tx_on_chain(tx_hash)
    status = "pending" if verified else "pending_verification"
    tx_doc = {
        "user_id": user["_id"],
        "username": user["username"],
        "tx_hash": tx_hash,
        "days": days,
        "status": status,
        "created_at": datetime.datetime.utcnow()
    }
    try:
        inserted = transactions.insert_one(tx_doc)
    except pymongo_errors.DuplicateKeyError:
        return {"msg": "tx_hash already exists"}, 400
    tx_id = str(inserted.inserted_id)
    return {"msg": "payment submitted", "tx_id": tx_id, "status": status}, 200

@app.route("/payment/submit", methods=["POST"])
@jwt_required()
@single_session_required
def submit_payment():
    try:
        payload = request.get_json(force=True)
        data = PaymentSubmitSchema().load(payload)
        # For payments, enqueue with medium priority (10)
        # We will not block waiting for result — return queued immediate response
        # but to be convenient return tx placeholder if job completes quickly (wait short)
        user = g.current_user
        result = enqueue_job(func=_process_submit_payment, args=(user, data), priority=10, wait=True, wait_timeout=1.0)
        if result.get("finished"):
            body, status = result.get("result")
            return jsonify(body), status
        else:
            # job queued; when worker runs it will create DB transaction; return queued acknowledgement
            return jsonify({"msg": "payment queued for processing"}), 202
    except ValidationError as ve:
        return jsonify({"msg": "validation failed", "errors": ve.messages}), 400
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("submit_payment error")
        return jsonify({"msg": "internal error"}), 500

# ---------- Admin endpoints (execute synchronously for immediacy) ----------
@app.route("/admin/transactions/<tx_id>/approve", methods=["POST"])
@admin_required
def admin_approve_transaction(tx_id):
    try:
        transactions = db_manager.get_collection("transactions")
        users = db_manager.get_collection("users")
        oid = to_objectid(tx_id)
        if not oid:
            return jsonify({"msg": "invalid tx id"}), 400
        tx = transactions.find_one({"_id": oid, "status": {"$in": ["pending", "pending_verification"]}})
        if not tx:
            return jsonify({"msg": "transaction not found or already processed"}), 404
        user = users.find_one({"_id": tx["user_id"]})
        if not user:
            return jsonify({"msg": "associated user not found"}), 404
        now = datetime.datetime.utcnow()
        start = user.get("expiryDate") if (user.get("expiryDate") and user["expiryDate"] > now) else now
        new_exp = start + datetime.timedelta(days=tx.get("days", 0))
        users.update_one({"_id": user["_id"]}, {"$set": {"expiryDate": new_exp}, "$inc": {"total_purchases": 1}})
        approved_by = g.current_user.get("username") if g.current_user else "unknown"
        transactions.update_one({"_id": tx["_id"]}, {"$set": {"status": "approved", "processed_at": now, "approved_by": approved_by}})
        return jsonify({"msg": "transaction approved", "new_expiry": new_exp.isoformat()}), 200
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("admin_approve_transaction error")
        return jsonify({"msg": "internal error"}), 500

@app.route("/admin/transactions/<tx_id>/reject", methods=["POST"])
@admin_required
def admin_reject_transaction(tx_id):
    try:
        transactions = db_manager.get_collection("transactions")
        reason = (request.get_json(silent=True) or {}).get("reason", "")
        oid = to_objectid(tx_id)
        if not oid:
            return jsonify({"msg": "invalid tx id"}), 400
        tx = transactions.find_one({"_id": oid, "status": {"$in": ["pending", "pending_verification"]}})
        if not tx:
            return jsonify({"msg": "transaction not found or already processed"}), 404
        rejected_by = g.current_user.get("username") if g.current_user else "unknown"
        transactions.update_one({"_id": tx["_id"]}, {"$set": {"status": "rejected", "rejected_at": datetime.datetime.utcnow(), "rejected_by": rejected_by, "reject_reason": reason}})
        return jsonify({"msg": "transaction rejected"}), 200
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("admin_reject_transaction error")
        return jsonify({"msg": "internal error"}), 500

@app.route("/admin/transactions", methods=["GET"])
@admin_required
def admin_list_transactions():
    try:
        transactions = db_manager.get_collection("transactions")
        status = request.args.get("status")
        q = {}
        if status:
            q["status"] = status
        cursor = transactions.find(q).sort("created_at", -1).limit(200)
        out = []
        for t in cursor:
            t["_id"] = str(t["_id"])
            try:
                t["user_id"] = str(t["user_id"])
            except Exception:
                t["user_id"] = t.get("user_id")
            if "processed_at" in t and isinstance(t["processed_at"], datetime.datetime):
                t["processed_at"] = t["processed_at"].isoformat()
            if "created_at" in t and isinstance(t["created_at"], datetime.datetime):
                t["created_at"] = t["created_at"].isoformat()
            out.append(t)
        return jsonify({"transactions": out}), 200
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("admin_list_transactions error")
        return jsonify({"msg": "internal error"}), 500

# ---------- Coupons ----------
@app.route("/admin/coupons", methods=["POST"])
@admin_required
def create_coupon():
    try:
        coupons = db_manager.get_collection("coupons")
        payload = request.get_json(force=True)
        code = (payload.get("code") or "").strip()
        bonus_days = int(payload.get("bonus_days", 0))
        expires_at = payload.get("expires_at")
        max_uses = payload.get("max_uses")
        if not code or bonus_days <= 0:
            return jsonify({"msg": "invalid coupon payload"}), 400
        doc = {
            "code": code,
            "bonus_days": bonus_days,
            "uses": 0,
            "max_uses": int(max_uses) if max_uses not in (None, "") else None,
            "created_at": datetime.datetime.utcnow()
        }
        if expires_at:
            try:
                doc["expires_at"] = datetime.datetime.fromisoformat(expires_at)
            except Exception:
                return jsonify({"msg": "invalid expires_at format, use ISO"}), 400
        coupons.insert_one(doc)
        return jsonify({"msg": "coupon created"}), 201
    except pymongo_errors.DuplicateKeyError:
        return jsonify({"msg": "coupon already exists"}), 409
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("create_coupon error")
        return jsonify({"msg": "internal error"}), 500

@app.route("/admin/coupons", methods=["GET"])
@admin_required
def list_coupons():
    try:
        coupons = db_manager.get_collection("coupons")
        cursor = coupons.find().sort("created_at", -1).limit(200)
        out = []
        for c in cursor:
            c["_id"] = str(c["_id"])
            if "expires_at" in c and isinstance(c["expires_at"], datetime.datetime):
                c["expires_at"] = c["expires_at"].isoformat()
            if "created_at" in c and isinstance(c["created_at"], datetime.datetime):
                c["created_at"] = c["created_at"].isoformat()
            out.append(c)
        return jsonify({"coupons": out}), 200
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("list_coupons error")
        return jsonify({"msg": "internal error"}), 500

# ---------- Rates & public endpoint ----------
def fetch_and_store_rates():
    try:
        rates_coll = db_manager.get_collection("rates")
        out = {"ts": datetime.datetime.utcnow()}
        try:
            brs_url = BRSAPI_URL
            if BRSAPI_KEY:
                if "?" in brs_url:
                    brs_url = f"{brs_url}&key={BRSAPI_KEY}"
                else:
                    brs_url = f"{brs_url}?key={BRSAPI_KEY}"
            r = requests.get(brs_url, timeout=6)
            if r.ok:
                j = r.json()
                usdt = None
                if isinstance(j, dict):
                    if j.get("price") and (j.get("symbol","").upper()=="USDT"):
                        usdt = float(j.get("price"))
                    elif j.get("USDT") and isinstance(j["USDT"], dict) and j["USDT"].get("price"):
                        usdt = float(j["USDT"]["price"])
                    elif "cryptocurrency" in j and isinstance(j["cryptocurrency"], list):
                        for it in j["cryptocurrency"]:
                            if (it.get("symbol","").upper() == "USDT") and it.get("price"):
                                usdt = float(it.get("price"))
                                break
                elif isinstance(j, list):
                    for it in j:
                        if (it.get("symbol","").upper() == "USDT") and it.get("price"):
                            usdt = float(it.get("price"))
                            break
                if usdt:
                    out["USDT"] = int(round(usdt))
        except Exception:
            logger.exception("brsapi fetch failed")
        try:
            base = NOBITEX_STATS_URL
            for code, sym in (("trx","TRX"), ("usdt","USDT"), ("ton","TON"), ("sol","SOL")):
                try:
                    resp = requests.get(base, params={"srcCurrency": code, "dstCurrency": "rls"}, timeout=6)
                    if resp.ok:
                        jr = resp.json()
                        stats = jr.get("stats") or {}
                        key = next((k for k in stats.keys() if k.startswith(code)), None)
                        if key:
                            latest_riyal = int(float(stats[key].get("latest", 0)))
                            out[sym] = latest_riyal // 10
                except Exception:
                    continue
        except Exception:
            logger.exception("nobitex fetch failed")
        if not any(k in out for k in ("USDT","TRX","TON","SOL")):
            logger.warning("No external rates fetched; skipping store")
            return False
        rates_coll.insert_one(out)
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=7)
        rates_coll.delete_many({"ts": {"$lt": cutoff}})
        logger.info("Rates stored: %s", out)
        return True
    except DatabaseUnavailable:
        logger.warning("fetch_and_store_rates: DB not available.")
        return False
    except Exception:
        logger.exception("fetch_and_store_rates failed")
        return False

@app.route("/public/rates", methods=["GET"])
def public_rates():
    try:
        rates_coll = db_manager.get_collection("rates")
        last = rates_coll.find_one(sort=[("ts", DESCENDING)])
        if not last:
            return jsonify({"msg": "no rates available"}), 404
        last.pop("_id", None)
        if isinstance(last.get("ts"), datetime.datetime):
            last["ts"] = last["ts"].isoformat()
        return jsonify(last), 200
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("public_rates error")
        return jsonify({"msg": "internal error"}), 500

@app.route("/admin/fetch-rates", methods=["POST"])
@admin_required
def admin_fetch_rates():
    try:
        ok = fetch_and_store_rates()
        if ok:
            return jsonify({"msg": "rates fetched"}), 200
        return jsonify({"msg": "no rates fetched"}), 500
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("admin_fetch_rates error")
        return jsonify({"msg":"internal error"}), 500

# ---------- User transactions endpoint ----------
@app.route("/user/transactions", methods=["GET"])
@jwt_required()
@single_session_required
def user_transactions():
    try:
        transactions = db_manager.get_collection("transactions")
        user = g.current_user
        try:
            limit = min(200, int(request.args.get("limit", 50)))
        except Exception:
            limit = 50
        status = request.args.get("status")
        q = {"user_id": user["_id"]}
        if status:
            q["status"] = status
        cursor = transactions.find(q).sort("created_at", -1).limit(limit)
        out = []
        for t in cursor:
            t["_id"] = str(t["_id"])
            try:
                t["user_id"] = str(t["user_id"])
            except Exception:
                t["user_id"] = t.get("user_id")
            if "processed_at" in t and isinstance(t["processed_at"], datetime.datetime):
                t["processed_at"] = t["processed_at"].isoformat()
            if "created_at" in t and isinstance(t["created_at"], datetime.datetime):
                t["created_at"] = t["created_at"].isoformat()
            out.append(t)
        return jsonify({"transactions": out}), 200
    except DatabaseUnavailable:
        return jsonify({"msg": "database unavailable"}), 503
    except Exception:
        logger.exception("user_transactions error")
        return jsonify({"msg": "internal error"}), 500

# Optional scheduler
if ENABLE_RATE_SCHEDULER:
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        sched = BackgroundScheduler()
        sched.add_job(fetch_and_store_rates, 'interval', minutes=RATE_FETCH_MINUTES, next_run_time=datetime.datetime.utcnow())
        sched.start()
        logger.info("Background rate fetch scheduler started every %s minutes", RATE_FETCH_MINUTES)
    except Exception:
        logger.exception("Failed to start APScheduler; consider using external cron/job runner")

# ---------- Graceful shutdown handlers ----------
import atexit
def _on_exit():
    try:
        stop_workers()
    except Exception:
        pass
atexit.register(_on_exit)

# ---------- Run ----------
if __name__ == "__main__":
    try:
        logger.info("Starting Two Manga API (queue mode) on port %s with %d workers", APP_PORT, WORKER_COUNT)
        app.run(host="0.0.0.0", port=APP_PORT, debug=False)
    except Exception:
        logger.exception("Failed to start application")
        raise
