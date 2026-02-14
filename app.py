# app.py
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
from marshmallow import Schema, fields, ValidationError, validates
from pymongo import ASCENDING, errors as pymongo_errors
from bson.objectid import ObjectId
import bcrypt

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
# Note: you can tune connectTimeoutMS, serverSelectionTimeoutMS via MONGO_URI query params if needed
mongo = PyMongo(app)

# JWT
jwt = JWTManager(app)

# Rate limiter
# Use init_app to avoid signature issues across versions of flask-limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)
limiter.init_app(app)

# ---------- Schemas (Validation) ----------

class RegisterSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)

    @validates("username")
    def check_username(self, value):
        if not value or len(value.strip()) < 3:
            raise ValidationError("username must be at least 3 characters")
        if " " in value:
            raise ValidationError("username must not contain spaces")

    @validates("password")
    def check_password(self, value):
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
    def check_days(self, value):
        if value is None or value <= 0 or value > 3650:
            raise ValidationError("days must be between 1 and 3650")

# ---------- Helpers ----------

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            # ensure jwt present & valid
            verify_jwt_in_request()
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
            verify_jwt_in_request()
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
        # optional: logs/temporary ttl index example (commented out)
        logger.info("Database indices ensured.")
    except Exception as e:
        logger.exception("Error creating indices: %s", e)
        # bubble up in import-time initialization would stop the app so that ops notices
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

# call at import/startup so indices exist before handling requests
try:
    setup_database()
    seed_admin_roles()
except Exception:
    logger.exception("Database setup failed at startup")
    # Depending on deployment preference, you may want to re-raise to prevent startup.
    # For now, continue so process doesn't crash unexpectedly in some environments.

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
        user = mongo.db.users.find_one({"username": username})
        if not user or not check_password(password, user["password"]):
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
        # verify jwt and ensure the session_salt still matches DB (prevent using old refresh token)
        verify_jwt_in_request()
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
            "expiry_date": exp.isoformat() if exp else None,
            "total_purchases": user.get("total_purchases", 0)
        }), 200
    except Exception:
        logger.exception("get_status error")
        return jsonify({"msg": "internal error"}), 500

# ---------- Payments & Coupons ----------

def verify_tx_on_chain(tx_hash: str) -> bool:
    """
    Placeholder for blockchain transaction verification.
    In production, integrate with the relevant chain explorer or node RPC,
    check confirmations, network, amounts etc.
    Minimal sanity check used here.
    """
    if not tx_hash or len(tx_hash) < 8:
        return False
    return True

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
            # coupon usage constraints
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

        # basic tx_hash validation + uniqueness
        if mongo.db.transactions.find_one({"tx_hash": tx_hash}):
            return jsonify({"msg": "tx_hash already submitted"}), 400

        if not verify_tx_on_chain(tx_hash):
            # Keep entry as pending but flag as unverifiable (admin will investigate)
            status = "pending_verification"
        else:
            status = "pending"

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
            # race: another request inserted same tx_hash concurrently
            return jsonify({"msg": "tx_hash already exists"}), 400

        tx_id = str(inserted.inserted_id)
        return jsonify({"msg": "payment submitted", "tx_id": tx_id, "status": status}), 200
    except ValidationError as ve:
        return jsonify({"msg": "validation failed", "errors": ve.messages}), 400
    except Exception:
        logger.exception("submit_payment error")
        return jsonify({"msg": "internal error"}), 500

# Admin endpoints to approve/reject payments

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

# ---------- Utilities ----------

@app.route("/debug/ping", methods=["GET"])
def ping():
    return jsonify({"msg": "pong"}), 200

# ---------- Startup (dev) ----------
if __name__ == "__main__":
    try:
        logger.info("Starting Two Manga API on port %s", APP_PORT)
        # In production prefer a WSGI server (gunicorn/uvicorn with multiple workers)
        app.run(host="0.0.0.0", port=APP_PORT, debug=False)
    except Exception:
        logger.exception("Failed to start application")
        raise
