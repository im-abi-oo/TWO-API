# app.py (FINAL - fixed for Marshmallow 4 compat + minor hardening)
import os
import uuid
import json
import logging
import traceback
import datetime
from functools import wraps
from typing import Optional, Any

from flask import Flask, request, jsonify, g
from flask_pymongo import PyMongo
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from marshmallow import Schema, fields, ValidationError, validates
from pymongo import ASCENDING, DESCENDING, errors as pymongo_errors
from bson.objectid import ObjectId
import bcrypt
import requests

# ---------- Configuration & Logging ----------

def getenv_required(key: str, default: Optional[str] = None) -> str:
    v = os.getenv(key, default)
    if not v:
        raise RuntimeError(f"Missing required environment variable: {key}")
    return v

# Required environment variables (will raise if missing)
MONGO_URI = getenv_required("MONGO_URI")
JWT_SECRET_KEY = getenv_required("JWT_SECRET_KEY")
APP_PORT = int(os.getenv("PORT", "5001"))
ADMIN_USERNAMES = [u.strip().lower() for u in os.getenv("ADMIN_USERNAMES", "").split(",") if u.strip()]

# Optional tuning
ACCESS_EXPIRES_HOURS = int(os.getenv("ACCESS_EXPIRES_HOURS", "4"))
REFRESH_EXPIRES_DAYS = int(os.getenv("REFRESH_EXPIRES_DAYS", "30"))

# External rate sources (configurable)
BRSAPI_KEY = os.getenv("BRSAPI_KEY", "")
BRSAPI_URL = os.getenv("BRSAPI_URL", f"https://BrsApi.ir/Api/Market/Gold_Currency.php")
NOBITEX_STATS_URL = os.getenv("NOBITEX_STATS_URL", "https://apiv2.nobitex.ir/market/stats")
API_LOCAL_RATES = os.getenv("API_LOCAL_RATES", "/public/rates")

# Explorer validation config (comma-separated URLs with {tx_hash} placeholder)
EXPLORER_URLS = os.getenv("EXPLORER_URLS", "")  # e.g. "https://api.tronscan.org/api/transaction-info?hash={tx_hash},https://api.solscan.io/transaction/{tx_hash}"

# Scheduler options
ENABLE_RATE_SCHEDULER = os.getenv("ENABLE_RATE_SCHEDULER", "false").lower() == "true"
RATE_FETCH_MINUTES = int(os.getenv("RATE_FETCH_MINUTES", "60"))

# FRONTEND_ORIGINS for CORS (comma-separated). Default to common dev origin.
FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "http://localhost:3000")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s - %(message)s"
)
logger = logging.getLogger("two-manga-backend")

# ---------- Flask App & Extensions ----------

app = Flask(__name__)
app.config["MONGO_URI"] = MONGO_URI
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=ACCESS_EXPIRES_HOURS)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(days=REFRESH_EXPIRES_DAYS)

# PyMongo client
mongo = PyMongo(app)

# JWT
jwt = JWTManager(app)

# Rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)
limiter.init_app(app)

# CORS setup
# FRONTEND_ORIGINS may be a comma-separated list or "*"
origins_raw = FRONTEND_ORIGINS.strip()
if origins_raw == "*" or origins_raw == "":
    origins = "*"
else:
    # split and strip
    origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
# apply CORS (allow credentials because JWT cookie or fetch with credentials might be used)
CORS(app, resources={r"/*": {"origins": origins}}, supports_credentials=True)

# ---------- Schemas (Validation) ----------
# Marshmallow 4 passes kwargs (like data_key) to validators.
# Ensure all validators accept **kwargs to be future-proof.

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

# Security: choose bcrypt rounds (cost). Default 12 (reasonable).
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "12"))

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")

def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

# Mitigate timing attack info-leak on username enumeration by always checking a hash.
# Precompute a fake hash once (costly but ok at import time) to use when user not found.
try:
    FAKE_PASSWORD_HASH = bcrypt.hashpw(b"fake_password_for_timing_mitigation", bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")
except Exception:
    # fallback: a static known bcrypt hash (safe default)
    FAKE_PASSWORD_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.2uQf7Pn6y6Gk1v4b6ZJdXb0sZr7Qe6"  # example hash

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            # assume @jwt_required applied on route (avoid double verify)
            identity = get_jwt_identity()
            if not identity:
                return jsonify({"msg": "unauthorized"}), 401
            user = mongo.db.users.find_one({"username": identity})
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

def single_session_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            # assume @jwt_required already ensured JWT; just verify session_salt matches DB
            claims = get_jwt()
            identity = get_jwt_identity()
            if not identity:
                return jsonify({"msg": "unauthorized"}), 401
            user = mongo.db.users.find_one({"username": identity}, {"session_salt": 1})
            if not user:
                return jsonify({"msg": "user not found"}), 401
            if claims.get("session_salt") != user.get("session_salt"):
                return jsonify({"msg": "session invalidated"}), 401
            # set current user document for handler (fetch full doc)
            g.current_user = mongo.db.users.find_one({"username": identity})
            return fn(*args, **kwargs)
        except Exception:
            logger.exception("single_session_required error")
            return jsonify({"msg": "authentication error"}), 401
    return wrapper

def to_objectid(val: str) -> Optional[ObjectId]:
    try:
        return ObjectId(val)
    except Exception:
        return None

# ---------- Database Setup ----------

def setup_database():
    try:
        # ensure indexes
        mongo.db.users.create_index([("username", ASCENDING)], unique=True)
        mongo.db.transactions.create_index([("tx_hash", ASCENDING)], unique=True, sparse=True)
        mongo.db.coupons.create_index([("code", ASCENDING)], unique=True)
        mongo.db.rates.create_index([("ts", DESCENDING)])
        logger.info("Database indices ensured.")
    except Exception as e:
        logger.exception("Error creating indices: %s", e)
        raise

def seed_admin_roles():
    if not ADMIN_USERNAMES:
        return
    for u in ADMIN_USERNAMES:
        try:
            mongo.db.users.update_one({"username": u}, {"$set": {"role": "admin"}}, upsert=False)
        except Exception:
            logger.exception("Failed applying admin role for %s", u)
    logger.info("Admin usernames applied to existing users (if present).")

try:
    setup_database()
    seed_admin_roles()
except Exception:
    logger.exception("Database setup failed at startup")

# ---------- Error Handling ----------

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

# ---------- Auth & User Routes ----------

@app.route("/")
def health():
    return jsonify({"status": "ok", "server": "Two Manga API"}), 200

@app.route("/auth/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    try:
        payload = request.get_json(force=True)
        data = RegisterSchema().load(payload)
        username = data["username"].strip().lower()
        password = data["password"]
        existing = mongo.db.users.find_one({"username": username})
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
        mongo.db.users.insert_one(user_doc)
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
def login():
    try:
        payload = request.get_json(force=True)
        data = LoginSchema().load(payload)
        username = data["username"].strip().lower()
        password = data["password"]
        # Mitigate username enumeration timing by always checking a hash
        user = mongo.db.users.find_one({"username": username})
        hash_to_check = user["password"] if user else FAKE_PASSWORD_HASH
        # perform password check regardless
        pw_ok = check_password(password, hash_to_check)
        if not user or not pw_ok:
            return jsonify({"msg": "invalid credentials"}), 401
        salt = str(uuid.uuid4())
        mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"session_salt": salt}})
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
def refresh():
    try:
        # jwt_required already ensured a valid refresh token
        claims = get_jwt()
        identity = get_jwt_identity()
        if not identity:
            return jsonify({"msg": "unauthorized"}), 401
        user = mongo.db.users.find_one({"username": identity}, {"session_salt": 1})
        if not user:
            return jsonify({"msg": "user not found"}), 404
        if claims.get("session_salt") != user.get("session_salt"):
            return jsonify({"msg": "refresh token invalidated"}), 401
        access = create_access_token(identity=identity, additional_claims={"session_salt": user.get("session_salt")})
        return jsonify({"access_token": access}), 200
    except Exception:
        logger.exception("refresh error")
        return jsonify({"msg": "internal error"}), 500

# New endpoint requested: /auth/me -> returns full profile info
@app.route("/auth/me", methods=["GET"])
@jwt_required()
@single_session_required
def auth_me():
    try:
        user = g.current_user
        now = datetime.datetime.utcnow()
        exp = user.get("expiryDate")
        is_premium = bool(exp and exp > now)
        days_left = (exp - now).days if is_premium else 0
        # safe response serialization
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

@app.route("/api/user/status", methods=["GET"])
@jwt_required()
@single_session_required
def get_status():
    try:
        user = g.current_user
        now = datetime.datetime.utcnow()
        exp = user.get("expiryDate")
        is_premium = bool(exp and exp > now)
        days_left = (exp - now).days if is_premium else 0
        return jsonify({
            "username": user["username"],
            "is_premium": is_premium,
            "days_left": days_left,
            "expiry_date": exp.isoformat() if isinstance(exp, datetime.datetime) else None,
            "total_purchases": user.get("total_purchases", 0)
        }), 200
    except Exception:
        logger.exception("get_status error")
        return jsonify({"msg": "internal error"}), 500

# ---------- Payments & Coupons ----------

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

        # If explorers not configured, do not auto-approve (avoid accepting everything in prod)
        logger.warning("No EXPLORER_URLS configured; verify_tx_on_chain returns False by default.")
        return False
    except Exception:
        logger.exception("verify_tx_on_chain error")
        return False

@app.route("/payment/submit", methods=["POST"])
@jwt_required()
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

        if coupon:
            c = mongo.db.coupons.find_one({"code": coupon})
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
            mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"expiryDate": new_exp}, "$inc": {"total_purchases": 1}})
            mongo.db.coupons.update_one({"_id": c["_id"]}, {"$inc": {"uses": 1}})
            return jsonify({"msg": "coupon applied", "expiry_date": new_exp.isoformat()}), 200

        if not tx_hash:
            return jsonify({"msg": "tx_hash or coupon required"}), 400

        if mongo.db.transactions.find_one({"tx_hash": tx_hash}):
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
            inserted = mongo.db.transactions.insert_one(tx_doc)
        except pymongo_errors.DuplicateKeyError:
            return jsonify({"msg": "tx_hash already exists"}), 400

        tx_id = str(inserted.inserted_id)
        return jsonify({"msg": "payment submitted", "tx_id": tx_id, "status": status}), 200
    except ValidationError as ve:
        return jsonify({"msg": "validation failed", "errors": ve.messages}), 400
    except Exception:
        logger.exception("submit_payment error")
        return jsonify({"msg": "internal error"}), 500

# Admin endpoints

@app.route("/admin/transactions/<tx_id>/approve", methods=["POST"])
@jwt_required()
@admin_required
def admin_approve_transaction(tx_id):
    try:
        oid = to_objectid(tx_id)
        if not oid:
            return jsonify({"msg": "invalid tx id"}), 400
        tx = mongo.db.transactions.find_one({"_id": oid, "status": {"$in": ["pending", "pending_verification"]}})
        if not tx:
            return jsonify({"msg": "transaction not found or already processed"}), 404
        user = mongo.db.users.find_one({"_id": tx["user_id"]})
        if not user:
            return jsonify({"msg": "associated user not found"}), 404
        now = datetime.datetime.utcnow()
        start = user.get("expiryDate") if (user.get("expiryDate") and user["expiryDate"] > now) else now
        new_exp = start + datetime.timedelta(days=tx.get("days", 0))
        mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"expiryDate": new_exp}, "$inc": {"total_purchases": 1}})
        mongo.db.transactions.update_one({"_id": tx["_id"]}, {"$set": {"status": "approved", "processed_at": now, "approved_by": g.current_user["username"]}})
        return jsonify({"msg": "transaction approved", "new_expiry": new_exp.isoformat()}), 200
    except Exception:
        logger.exception("admin_approve_transaction error")
        return jsonify({"msg": "internal error"}), 500

@app.route("/admin/transactions/<tx_id>/reject", methods=["POST"])
@jwt_required()
@admin_required
def admin_reject_transaction(tx_id):
    try:
        reason = (request.get_json(silent=True) or {}).get("reason", "")
        oid = to_objectid(tx_id)
        if not oid:
            return jsonify({"msg": "invalid tx id"}), 400
        tx = mongo.db.transactions.find_one({"_id": oid, "status": {"$in": ["pending", "pending_verification"]}})
        if not tx:
            return jsonify({"msg": "transaction not found or already processed"}), 404
        mongo.db.transactions.update_one({"_id": tx["_id"]}, {"$set": {"status": "rejected", "rejected_at": datetime.datetime.utcnow(), "rejected_by": g.current_user["username"], "reject_reason": reason}})
        return jsonify({"msg": "transaction rejected"}), 200
    except Exception:
        logger.exception("admin_reject_transaction error")
        return jsonify({"msg": "internal error"}), 500

@app.route("/admin/transactions", methods=["GET"])
@jwt_required()
@admin_required
def admin_list_transactions():
    try:
        status = request.args.get("status")
        q = {}
        if status:
            q["status"] = status
        cursor = mongo.db.transactions.find(q).sort("created_at", -1).limit(200)
        out = []
        for t in cursor:
            t["_id"] = str(t["_id"])
            t["user_id"] = str(t["user_id"])
            if "processed_at" in t and isinstance(t["processed_at"], datetime.datetime):
                t["processed_at"] = t["processed_at"].isoformat()
            if "created_at" in t and isinstance(t["created_at"], datetime.datetime):
                t["created_at"] = t["created_at"].isoformat()
            out.append(t)
        return jsonify({"transactions": out}), 200
    except Exception:
        logger.exception("admin_list_transactions error")
        return jsonify({"msg": "internal error"}), 500

# ---------- Coupons Management (Admin) ----------

@app.route("/admin/coupons", methods=["POST"])
@jwt_required()
@admin_required
def create_coupon():
    try:
        payload = request.get_json(force=True)
        code = (payload.get("code") or "").strip()
        bonus_days = int(payload.get("bonus_days", 0))
        expires_at = payload.get("expires_at")  # ISO format expected
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
        mongo.db.coupons.insert_one(doc)
        return jsonify({"msg": "coupon created"}), 201
    except pymongo_errors.DuplicateKeyError:
        return jsonify({"msg": "coupon already exists"}), 409
    except Exception:
        logger.exception("create_coupon error")
        return jsonify({"msg": "internal error"}), 500

@app.route("/admin/coupons", methods=["GET"])
@jwt_required()
@admin_required
def list_coupons():
    try:
        cursor = mongo.db.coupons.find().sort("created_at", -1).limit(200)
        out = []
        for c in cursor:
            c["_id"] = str(c["_id"])
            if "expires_at" in c and isinstance(c["expires_at"], datetime.datetime):
                c["expires_at"] = c["expires_at"].isoformat()
            if "created_at" in c and isinstance(c["created_at"], datetime.datetime):
                c["created_at"] = c["created_at"].isoformat()
            out.append(c)
        return jsonify({"coupons": out}), 200
    except Exception:
        logger.exception("list_coupons error")
        return jsonify({"msg": "internal error"}), 500

# ---------- Rates fetching & public endpoint ----------

def fetch_and_store_rates():
    try:
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

        mongo.db.rates.insert_one(out)
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=7)
        mongo.db.rates.delete_many({"ts": {"$lt": cutoff}})
        logger.info("Rates stored: %s", out)
        return True
    except Exception:
        logger.exception("fetch_and_store_rates failed")
        return False

@app.route("/public/rates", methods=["GET"])
def public_rates():
    try:
        last = mongo.db.rates.find_one(sort=[("ts", DESCENDING)])
        if not last:
            return jsonify({"msg": "no rates available"}), 404
        last.pop("_id", None)
        if isinstance(last.get("ts"), datetime.datetime):
            last["ts"] = last["ts"].isoformat()
        return jsonify(last), 200
    except Exception:
        logger.exception("public_rates error")
        return jsonify({"msg": "internal error"}), 500

@app.route("/admin/fetch-rates", methods=["POST"])
@jwt_required()
@admin_required
def admin_fetch_rates():
    try:
        ok = fetch_and_store_rates()
        if ok:
            return jsonify({"msg": "rates fetched"}), 200
        return jsonify({"msg": "no rates fetched"}), 500
    except Exception:
        logger.exception("admin_fetch_rates error")
        return jsonify({"msg":"internal error"}), 500

# ---------- User transactions endpoint (for frontend) ----------

@app.route("/user/transactions", methods=["GET"])
@jwt_required()
@single_session_required
def user_transactions():
    try:
        user = g.current_user
        try:
            limit = min(200, int(request.args.get("limit", 50)))
        except Exception:
            limit = 50
        status = request.args.get("status")
        q = {"user_id": user["_id"]}
        if status:
            q["status"] = status
        cursor = mongo.db.transactions.find(q).sort("created_at", -1).limit(limit)
        out = []
        for t in cursor:
            t["_id"] = str(t["_id"])
            t["user_id"] = str(t["user_id"])
            if "processed_at" in t and isinstance(t["processed_at"], datetime.datetime):
                t["processed_at"] = t["processed_at"].isoformat()
            if "created_at" in t and isinstance(t["created_at"], datetime.datetime):
                t["created_at"] = t["created_at"].isoformat()
            out.append(t)
        return jsonify({"transactions": out}), 200
    except Exception:
        logger.exception("user_transactions error")
        return jsonify({"msg": "internal error"}), 500

# ---------- Utilities ----------

@app.route("/debug/ping", methods=["GET"])
def ping():
    return jsonify({"msg": "pong"}), 200

# ---------- Optional scheduler setup (APScheduler) ----------

if ENABLE_RATE_SCHEDULER:
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        sched = BackgroundScheduler()
        sched.add_job(fetch_and_store_rates, 'interval', minutes=RATE_FETCH_MINUTES, next_run_time=datetime.datetime.utcnow())
        sched.start()
        logger.info("Background rate fetch scheduler started every %s minutes", RATE_FETCH_MINUTES)
    except Exception:
        logger.exception("Failed to start APScheduler; consider using external cron/job runner")

# ---------- Startup (dev) ----------

if __name__ == "__main__":
    try:
        logger.info("Starting Two Manga API on port %s", APP_PORT)
        app.run(host="0.0.0.0", port=APP_PORT, debug=False)
    except Exception:
        logger.exception("Failed to start application")
        raise
