"""
Two Manga API - resilient, production-friendly refactor
- create_app() factory
- DatabaseManager: manages pymongo.MongoClient, ping, reconnect background thread with backoff
- require_db decorator: returns 503 when DB unavailable
- health endpoint: DB + optional external checks
- safe startup: critical envs validated, but app will not permanently crash if DB temporarily unreachable
"""

import os
import uuid
import json
import logging
import traceback
import datetime
import time
import threading
from functools import wraps
from typing import Optional, Any, Callable, Dict, List

import requests
import bcrypt
from flask import Flask, request, jsonify, g
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from marshmallow import Schema, fields, ValidationError, validates
from pymongo import MongoClient, ASCENDING, DESCENDING, errors as pymongo_errors
from bson.objectid import ObjectId

# ---------- Configuration & Logging ----------

def getenv_required(key: str, default: Optional[str] = None, required: bool = True) -> str:
    v = os.getenv(key, default)
    if required and not v:
        raise RuntimeError(f"Missing required environment variable: {key}")
    return v or ""

# Required
JWT_SECRET_KEY = getenv_required("JWT_SECRET_KEY")
# MONGO_URI is recommended but we tolerate temporary absence to keep service resilient.
MONGO_URI = getenv_required("MONGO_URI", default="", required=False)

APP_PORT = int(os.getenv("PORT", "5001"))
ADMIN_USERNAMES = [u.strip().lower() for u in os.getenv("ADMIN_USERNAMES", "").split(",") if u.strip()]

# Tuning
ACCESS_EXPIRES_HOURS = int(os.getenv("ACCESS_EXPIRES_HOURS", "4"))
REFRESH_EXPIRES_DAYS = int(os.getenv("REFRESH_EXPIRES_DAYS", "30"))
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))

# External endpoints
BRSAPI_KEY = os.getenv("BRSAPI_KEY", "")
BRSAPI_URL = os.getenv("BRSAPI_URL", "https://BrsApi.ir/Api/Market/Gold_Currency.php")
NOBITEX_STATS_URL = os.getenv("NOBITEX_STATS_URL", "https://apiv2.nobitex.ir/market/stats")
EXPLORER_URLS = os.getenv("EXPLORER_URLS", "")

ENABLE_RATE_SCHEDULER = os.getenv("ENABLE_RATE_SCHEDULER", "false").lower() == "true"
RATE_FETCH_MINUTES = int(os.getenv("RATE_FETCH_MINUTES", "60"))

FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "http://localhost:3000")

# Rate limiter storage (optional)
RATE_LIMIT_STORAGE_URI = os.getenv("RATE_LIMIT_STORAGE_URI", "")  # e.g. redis://:pass@host:6379/0

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s"
)
logger = logging.getLogger("two-manga-backend")

# ---------- Utilities ----------

def iso_to_dt(val: Optional[str]) -> Optional[datetime.datetime]:
    if not val:
        return None
    try:
        return datetime.datetime.fromisoformat(val)
    except Exception:
        try:
            return datetime.datetime.fromisoformat(val.rstrip("Z"))
        except Exception:
            return None

def to_objectid(val: str) -> Optional[ObjectId]:
    try:
        return ObjectId(val)
    except Exception:
        return None

def serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            out[k] = str(v)
        elif isinstance(v, datetime.datetime):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out

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

# ---------- Security helpers ----------

try:
    FAKE_PASSWORD_HASH = bcrypt.hashpw(b"fake_password_for_timing_mitigation", bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")
except Exception:
    FAKE_PASSWORD_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.2uQf7Pn6y6Gk1v4b6ZJdXb0sZr7Qe6"

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")

def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

# ---------- DatabaseManager (resilient) ----------

class DatabaseManager:
    def __init__(self, database_name: str = "two_manga", uri: str = "", reconnect_interval: int = 15):
        """
        Manages a pymongo.MongoClient with background reconnect attempts.
        - uri may be empty (service will remain available but DB endpoints return 503 until connected)
        """
        self._uri = uri
        self._db_name = database_name
        self._reconnect_interval = max(5, reconnect_interval)
        self._client: Optional[MongoClient] = None
        self._lock = threading.Lock()
        self._connected = False
        self._stop = False

        # Try initial connect but do not allow failure to kill the process
        self._connect(initial=True)

        # start reconnect thread (daemon)
        self._thread = threading.Thread(target=self._reconnect_loop, daemon=True)
        self._thread.start()

    def _connect(self, initial: bool = False) -> None:
        with self._lock:
            if not self._uri:
                logger.warning("DatabaseManager: no MONGO_URI configured, DB will remain unavailable until provided.")
                self._client = None
                self._connected = False
                return
            try:
                # serverSelectionTimeoutMS ensures quick fail if server unreachable
                client = MongoClient(self._uri, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
                # try ping
                client.admin.command("ping")
                self._client = client
                self._connected = True
                logger.info("DatabaseManager: connected to MongoDB")
            except Exception as exc:
                logger.warning("DatabaseManager: initial/connect ping failed: %s", str(exc))
                self._client = None
                self._connected = False
                if initial:
                    logger.info("DatabaseManager: continuing startup even though DB is unavailable (will retry in background)")

    @property
    def client(self) -> Optional[MongoClient]:
        return self._client

    @property
    def db(self):
        if not self._client:
            return None
        try:
            return self._client[self._db_name]
        except Exception:
            return None

    def ping_db(self, timeout: int = 5) -> bool:
        with self._lock:
            if not self._client:
                return False
            try:
                # low-level ping
                self._client.admin.command("ping")
                self._connected = True
                return True
            except Exception:
                self._connected = False
                return False

    def ensure_indexes(self, retries: int = 3, delay: float = 1.0) -> None:
        """
        Create indexes safely. If DB not ready simply log and return.
        Called on connect and in reconnect worker.
        """
        try:
            db = self.db
            if not db:
                logger.warning("ensure_indexes: DB not ready, skipping index creation")
                return

            # simple retry in case of transient error
            for attempt in range(1, retries + 1):
                try:
                    db.users.create_index([("username", ASCENDING)], unique=True)
                    db.transactions.create_index([("tx_hash", ASCENDING)], unique=True, sparse=True)
                    db.coupons.create_index([("code", ASCENDING)], unique=True)
                    db.rates.create_index([("ts", DESCENDING)])
                    logger.info("Database indices ensured.")
                    return
                except pymongo_errors.OperationFailure as e:
                    logger.warning("ensure_indexes attempt %s failed: %s", attempt, e)
                    time.sleep(delay)
                except Exception:
                    logger.exception("ensure_indexes unexpected error")
                    time.sleep(delay)
            logger.warning("ensure_indexes: all retries exhausted, indexes may be incomplete")
        except Exception:
            logger.exception("ensure_indexes top-level failure")

    def seed_admin_roles(self, admin_usernames: List[str]) -> None:
        if not admin_usernames:
            return
        try:
            db = self.db
            if not db:
                logger.warning("seed_admin_roles: db not available")
                return
            for username in admin_usernames:
                try:
                    db.users.update_one({"username": username}, {"$set": {"role": "admin"}}, upsert=False)
                except Exception:
                    logger.exception("Failed applying admin role for %s", username)
            logger.info("Admin usernames applied to existing users (if present).")
        except Exception:
            logger.exception("seed_admin_roles failed")

    def close(self):
        with self._lock:
            self._stop = True
            if self._client:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None
            self._connected = False

    def _reconnect_loop(self):
        backoff = 1
        while not self._stop:
            if not self._connected:
                logger.info("DatabaseManager: attempting reconnect to MongoDB...")
                try:
                    self._connect()
                    if self._connected:
                        # post-connect tasks
                        self.ensure_indexes()
                        self.seed_admin_roles(ADMIN_USERNAMES)
                        backoff = 1
                    else:
                        # exponential backoff (capped)
                        logger.debug("DatabaseManager: reconnect failed, backing off %s seconds", backoff)
                        time.sleep(backoff)
                        backoff = min(60, backoff * 2)
                except Exception:
                    logger.exception("DatabaseManager reconnect attempt failed")
                    time.sleep(5)
            else:
                # sleep normally when connected
                time.sleep(self._reconnect_interval)

    def is_connected(self) -> bool:
        return self.ping_db()

# ---------- Flask factory ----------

def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=ACCESS_EXPIRES_HOURS)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(days=REFRESH_EXPIRES_DAYS)

    # extensions
    jwt = JWTManager(app)

    # limiter: use storage URI if provided (e.g. redis), otherwise default (in-memory)
    limiter_kwargs = {"key_func": get_remote_address}
    if RATE_LIMIT_STORAGE_URI:
        limiter_kwargs["storage_uri"] = RATE_LIMIT_STORAGE_URI
    limiter = Limiter(app=app, **limiter_kwargs)

    origins_raw = (FRONTEND_ORIGINS or "").strip()
    origins = "*" if origins_raw in ("*", "") else [o.strip() for o in origins_raw.split(",") if o.strip()]
    CORS(app, resources={r"/*": {"origins": origins}}, supports_credentials=True)

    # attach DB manager to app (non-blocking)
    app.db_manager = DatabaseManager(database_name=os.getenv("MONGO_DBNAME", "two_manga"), uri=MONGO_URI, reconnect_interval=15)

    # if connected now, ensure indexes/seed synchronously (best-effort)
    try:
        if app.db_manager.is_connected():
            app.db_manager.ensure_indexes()
            app.db_manager.seed_admin_roles(ADMIN_USERNAMES)
    except Exception:
        logger.exception("Initial DB setup failed (continuing)")

    # convenience property
    app.mongo_client = app.db_manager.client

    # ---------- Error handlers ----------
    @app.errorhandler(ValidationError)
    def handle_validation_error(err):
        return jsonify({"msg": "validation error", "errors": err.messages}), 400

    @app.errorhandler(404)
    def handle_404(e):
        return jsonify({"msg": "endpoint not found"}), 404

    @app.errorhandler(Exception)
    def global_exception_handler(e):
        tb = traceback.format_exc()
        logger.error("Unhandled exception: %s\n%s", str(e), tb)
        return jsonify({"msg": "internal server error"}), 500

    # ---------- Decorators ----------
    def require_db(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not app.db_manager.is_connected() or not app.db_manager.db:
                logger.warning("DB unavailable for endpoint %s", request.path)
                return jsonify({"msg": "database unavailable"}), 503
            g.db = app.db_manager.db
            return fn(*args, **kwargs)
        return wrapper

    def admin_required(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                identity = get_jwt_identity()
                if not identity:
                    return jsonify({"msg": "unauthorized"}), 401
                user = app.db_manager.db.users.find_one({"username": identity})
                if not user:
                    return jsonify({"msg": "unauthorized"}), 401
                username_lower = identity.lower()
                if user.get("role") == "admin" or username_lower in ADMIN_USERNAMES:
                    g.current_user = user
                    return fn(*args, **kwargs)
                return jsonify({"msg": "admin required"}), 403
            except Exception:
                logger.exception("admin_required failure")
                return jsonify({"msg": "authentication failed"}), 401
        return wrapper

    def single_session_required(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                claims = get_jwt()
                identity = get_jwt_identity()
                if not identity:
                    return jsonify({"msg": "unauthorized"}), 401
                user = app.db_manager.db.users.find_one({"username": identity}, {"session_salt": 1})
                if not user:
                    return jsonify({"msg": "user not found"}), 401
                if claims.get("session_salt") != user.get("session_salt"):
                    return jsonify({"msg": "session invalidated"}), 401
                g.current_user = app.db_manager.db.users.find_one({"username": identity})
                return fn(*args, **kwargs)
            except Exception:
                logger.exception("single_session_required error")
                return jsonify({"msg": "authentication error"}), 401
        return wrapper

    # ---------- Routes ----------
    @app.route("/")
    def health_root():
        return jsonify({"status": "ok", "server": "Two Manga API"}), 200

    @app.route("/health", methods=["GET"])
    def health():
        out = {"service": "two-manga-backend", "time": datetime.datetime.utcnow().isoformat()}
        db_ok = app.db_manager.is_connected()
        out["database"] = {"ok": db_ok}
        external = {}
        session = requests.Session()
        # quick external checks (very short timeout)
        for name, url in (("brsapi", BRSAPI_URL), ("nobitex", NOBITEX_STATS_URL)):
            if not url:
                external[name] = {"ok": False, "error": "not configured"}
                continue
            try:
                r = session.get(url, timeout=2)
                external[name] = {"ok": r.ok, "status_code": r.status_code}
            except Exception as e:
                external[name] = {"ok": False, "error": str(e)}
        out["external"] = external
        return (jsonify(out), 200) if db_ok else (jsonify(out), 503)

    # ---------- Auth & User routes (same logic as original, but using require_db) ----------
    @app.route("/auth/register", methods=["POST"])
    @limiter.limit("5 per minute")
    @require_db
    def register():
        try:
            payload = request.get_json(force=True)
            data = RegisterSchema().load(payload)
            username = data["username"].strip().lower()
            password = data["password"]
            db = g.db
            existing = db.users.find_one({"username": username})
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
            db.users.insert_one(user_doc)
            return jsonify({"msg": "registered"}), 201
        except ValidationError as ve:
            return jsonify({"msg": "validation failed", "errors": ve.messages}), 400
        except pymongo_errors.DuplicateKeyError:
            return jsonify({"msg": "username already exists"}), 409
        except Exception:
            logger.exception("register error")
            return jsonify({"msg": "internal error"}), 500

    @app.route("/auth/login", methods=["POST"])
    @limiter.limit("10 per minute")
    @require_db
    def login():
        try:
            payload = request.get_json(force=True)
            data = LoginSchema().load(payload)
            username = data["username"].strip().lower()
            password = data["password"]
            db = g.db
            user = db.users.find_one({"username": username})
            hash_to_check = user["password"] if user else FAKE_PASSWORD_HASH
            pw_ok = check_password(password, hash_to_check)
            if not user or not pw_ok:
                return jsonify({"msg": "invalid credentials"}), 401
            salt = str(uuid.uuid4())
            db.users.update_one({"_id": user["_id"]}, {"$set": {"session_salt": salt}})
            access = create_access_token(identity=username, additional_claims={"session_salt": salt})
            refresh = create_refresh_token(identity=username, additional_claims={"session_salt": salt})
            return jsonify({"access_token": access, "refresh_token": refresh}), 200
        except ValidationError as ve:
            return jsonify({"msg": "validation failed", "errors": ve.messages}), 400
        except Exception:
            logger.exception("login error")
            return jsonify({"msg": "internal error"}), 500

    @app.route("/auth/refresh", methods=["POST"])
    @jwt_required(refresh=True)
    @require_db
    def refresh():
        try:
            claims = get_jwt()
            identity = get_jwt_identity()
            if not identity:
                return jsonify({"msg": "unauthorized"}), 401
            user = g.db.users.find_one({"username": identity}, {"session_salt": 1})
            if not user:
                return jsonify({"msg": "user not found"}), 404
            if claims.get("session_salt") != user.get("session_salt"):
                return jsonify({"msg": "refresh token invalidated"}), 401
            access = create_access_token(identity=identity, additional_claims={"session_salt": user.get("session_salt")})
            return jsonify({"access_token": access}), 200
        except Exception:
            logger.exception("refresh error")
            return jsonify({"msg": "internal error"}), 500

    @app.route("/auth/me", methods=["GET"])
    @jwt_required()
    @require_db
    @single_session_required
    def auth_me():
        try:
            user = g.current_user
            now = datetime.datetime.utcnow()
            exp = user.get("expiryDate")
            is_premium = bool(exp and exp > now)
            days_left = (exp - now).days if is_premium else 0
            return jsonify({
                "username": user.get("username"),
                "role": user.get("role", "user"),
                "is_premium": is_premium,
                "days_left": days_left,
                "expiry_date": exp.isoformat() if isinstance(exp, datetime.datetime) else None,
                "created_at": user.get("created_at").isoformat() if isinstance(user.get("created_at"), datetime.datetime) else None,
                "total_purchases": int(user.get("total_purchases", 0))
            }), 200
        except Exception:
            logger.exception("auth_me error")
            return jsonify({"msg": "internal error"}), 500

    # payment, admin, coupons, rates, etc. -- ported largely unchanged but all use require_db and g.db
    # for brevity, include the payment endpoint and a couple admins as representative:

    def verify_tx_on_chain(tx_hash: str) -> bool:
        try:
            if not tx_hash or len(tx_hash) < 8:
                return False
            if EXPLORER_URLS:
                urls = [u.strip() for u in EXPLORER_URLS.split(",") if u.strip()]
                session = requests.Session()
                for template in urls:
                    try:
                        url = template.replace("{tx_hash}", tx_hash)
                        r = session.get(url, timeout=5)
                        if r.status_code == 200:
                            logger.info("Explorer validated tx via %s", url)
                            return True
                    except Exception:
                        continue
                return False
            logger.warning("No EXPLORER_URLS configured; verify_tx_on_chain returns False by default.")
            return False
        except Exception:
            logger.exception("verify_tx_on_chain error")
            return False

    @app.route("/payment/submit", methods=["POST"])
    @jwt_required()
    @require_db
    @single_session_required
    @limiter.limit("10 per hour")
    def submit_payment():
        try:
            payload = request.get_json(force=True)
            data = PaymentSubmitSchema().load(payload)
            user = g.current_user
            tx_hash = (data.get("tx_hash") or "").strip() or None
            coupon = (data.get("coupon_code") or "").strip() or None
            days = int(data.get("days"))

            db = g.db
            if coupon:
                c = db.coupons.find_one({"code": coupon})
                if not c:
                    return jsonify({"msg": "invalid coupon"}), 400
                now = datetime.datetime.utcnow()
                if c.get("expires_at") and c["expires_at"] < now:
                    return jsonify({"msg": "coupon expired"}), 400
                max_uses = c.get("max_uses")
                uses = c.get("uses", 0)
                if max_uses and uses >= max_uses:
                    return jsonify({"msg": "coupon use limit reached"}), 400
                start = user.get("expiryDate") if (user.get("expiryDate") and user["expiryDate"] > now) else now
                new_exp = start + datetime.timedelta(days=c.get("bonus_days", days))
                db.users.update_one({"_id": user["_id"]}, {"$set": {"expiryDate": new_exp}, "$inc": {"total_purchases": 1}})
                db.coupons.update_one({"_id": c["_id"]}, {"$inc": {"uses": 1}})
                return jsonify({"msg": "coupon applied", "expiry_date": new_exp.isoformat()}), 200

            if not tx_hash:
                return jsonify({"msg": "tx_hash or coupon required"}), 400

            if db.transactions.find_one({"tx_hash": tx_hash}):
                return jsonify({"msg": "tx_hash already submitted"}), 400

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
                inserted = db.transactions.insert_one(tx_doc)
            except pymongo_errors.DuplicateKeyError:
                return jsonify({"msg": "tx_hash already exists"}), 400

            tx_id = str(inserted.inserted_id)
            return jsonify({"msg": "payment submitted", "tx_id": tx_id, "status": status}), 200
        except ValidationError as ve:
            return jsonify({"msg": "validation failed", "errors": ve.messages}), 400
        except Exception:
            logger.exception("submit_payment error")
            return jsonify({"msg": "internal error"}), 500

    # admin approve/reject (abridged)
    @app.route("/admin/transactions/<tx_id>/approve", methods=["POST"])
    @jwt_required()
    @require_db
    @admin_required
    def admin_approve_transaction(tx_id):
        try:
            oid = to_objectid(tx_id)
            if not oid:
                return jsonify({"msg": "invalid tx id"}), 400
            tx = g.db.transactions.find_one({"_id": oid, "status": {"$in": ["pending", "pending_verification"]}})
            if not tx:
                return jsonify({"msg": "transaction not found or already processed"}), 404
            user = g.db.users.find_one({"_id": tx["user_id"]})
            if not user:
                return jsonify({"msg": "associated user not found"}), 404
            now = datetime.datetime.utcnow()
            start = user.get("expiryDate") if (user.get("expiryDate") and user["expiryDate"] > now) else now
            new_exp = start + datetime.timedelta(days=tx.get("days", 0))
            g.db.users.update_one({"_id": user["_id"]}, {"$set": {"expiryDate": new_exp}, "$inc": {"total_purchases": 1}})
            g.db.transactions.update_one({"_id": tx["_id"]}, {"$set": {"status": "approved", "processed_at": now, "approved_by": g.current_user["username"]}})
            return jsonify({"msg": "transaction approved", "new_expiry": new_exp.isoformat()}), 200
        except Exception:
            logger.exception("admin_approve_transaction error")
            return jsonify({"msg": "internal error"}), 500

    # public rates endpoint (abridged)
    @app.route("/public/rates", methods=["GET"])
    def public_rates():
        try:
            db = app.db_manager.db
            if not db:
                return jsonify({"msg": "no rates available"}), 404
            last = db.rates.find_one(sort=[("ts", DESCENDING)])
            if not last:
                return jsonify({"msg": "no rates available"}), 404
            last.pop("_id", None)
            if isinstance(last.get("ts"), datetime.datetime):
                last["ts"] = last["ts"].isoformat()
            return jsonify(last), 200
        except Exception:
            logger.exception("public_rates error")
            return jsonify({"msg": "internal error"}), 500

    # debug ping
    @app.route("/debug/ping", methods=["GET"])
    def ping():
        return jsonify({"msg": "pong"}), 200

    # optional scheduler (kept optional)
    if ENABLE_RATE_SCHEDULER:
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            sched = BackgroundScheduler()
            sched.add_job(lambda: logger.info("Scheduled rates fetch triggered (implement fetch_and_store_rates)"), 'interval', minutes=RATE_FETCH_MINUTES, next_run_time=datetime.datetime.utcnow())
            sched.start()
            logger.info("Background scheduler started every %s minutes", RATE_FETCH_MINUTES)
        except Exception:
            logger.exception("Failed to start APScheduler; scheduler disabled")

    return app

# ---------- Startup ----------
if __name__ == "__main__":
    app = create_app()
    try:
        logger.info("Starting Two Manga API on port %s (development run). Use gunicorn for production.", APP_PORT)
        app.run(host="0.0.0.0", port=APP_PORT, debug=False)
    except Exception:
        logger.exception("Failed to start application")
        raise
