import os
import datetime
import bcrypt
import requests
import json
import traceback
import uuid
import threading
import time
from functools import wraps
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS 
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, 
    get_jwt_identity, JWTManager, get_jwt, verify_jwt_in_request
)
from bson.objectid import ObjectId
from pymongo import ASCENDING, DESCENDING
from dotenv import load_dotenv

# --- بارگذاری متغیرهای محیطی ---
load_dotenv()

app = Flask(__name__)
# تنظیمات CORS برای ارتباط ایمن با فرانت‌سند استاتیک
CORS(app, resources={r"/*": {"origins": "*"}}) 

# --- پیکربندی سیستم ---
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=4)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30)

ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_IDS = [idx.strip() for idx in os.getenv("ADMIN_IDS", "").split(",") if idx.strip()]
LOG_CHANNEL_ID = os.getenv("LOG_CHANNEL_ID")

mongo = PyMongo(app)
jwt = JWTManager(app)

# --- [بهینه‌سازی دیتابیس] ---
def setup_database():
    with app.app_context():
        try:
            mongo.db.users.create_index([("username", ASCENDING)], unique=True)
            mongo.db.users.create_index([("telegram_id", ASCENDING)], unique=True)
            mongo.db.transactions.create_index([("tx_hash", ASCENDING)], unique=True)
            mongo.db.coupons.create_index([("code", ASCENDING)], unique=True)
            mongo.db.transactions.create_index([("status", ASCENDING), ("created_at", DESCENDING)])
            print("✅ Database Indexed Successfully.")
        except Exception as e:
            print(f"❌ DB Indexing Error: {e}")

# --- [امنیت: جلوگیری از ورود همزمان] ---
def single_session_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            claims = get_jwt()
            user = mongo.db.users.find_one({"username": get_jwt_identity()}, {"session_salt": 1})
            if not user or claims.get("session_salt") != user.get("session_salt"):
                return jsonify({"msg": "سشن نامعتبر؛ دستگاه دیگری وارد شده است"}), 401
            return fn(*args, **kwargs)
        except:
            return jsonify({"msg": "خطا در احراز هویت"}), 401
    return wrapper

# --- [توابع کمکی تلگرام] ---
def send_tg(chat_id, text, markup=None):
    if not TELEGRAM_BOT_TOKEN: return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'}
    if markup: payload['reply_markup'] = json.dumps(markup)
    try: requests.post(url, json=payload, timeout=8)
    except: pass

# --- [بخش API های کاربر] ---
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    u, p, t = data.get('username','').strip().lower(), data.get('password'), data.get('telegram_id','').strip()
    if not all([u, p, t]) or len(p) < 6:
        return jsonify({"msg": "اطلاعات ناقص یا رمز عبور کوتاه است"}), 400
    
    hp = bcrypt.hashpw(p.encode('utf-8'), bcrypt.gensalt())
    try:
        mongo.db.users.insert_one({
            'username': u, 'password': hp, 'telegram_id': t,
            'expiryDate': None, 'session_salt': str(uuid.uuid4()),
            'total_purchases': 0, 'created_at': datetime.datetime.utcnow()
        })
        return jsonify({"msg": "ثبت‌نام موفق"}), 201
    except:
        return jsonify({"msg": "نام کاربری یا تلگرام تکراری"}), 409

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = mongo.db.users.find_one({'username': data.get('username','').strip().lower()})
    if user and bcrypt.checkpw(data.get('password').encode('utf-8'), user['password']):
        salt = str(uuid.uuid4())
        mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'session_salt': salt}})
        at = create_access_token(identity=user['username'], additional_claims={"session_salt": salt})
        rt = create_refresh_token(identity=user['username'], additional_claims={"session_salt": salt})
        return jsonify(access_token=at, refresh_token=rt), 200
    return jsonify({"msg": "نام کاربری یا رمز عبور اشتباه"}), 401

@app.route('/api/user/status', methods=['GET'])
@jwt_required()
@single_session_required
def get_status():
    user = mongo.db.users.find_one({'username': get_jwt_identity()})
    now = datetime.datetime.utcnow()
    exp = user.get('expiryDate')
    is_p = exp and exp > now
    return jsonify({
        "username": user['username'],
        "is_premium": bool(is_p),
        "days_left": (exp - now).days if is_p else 0,
        "expiry_date": exp.isoformat() if exp else None
    }), 200

# --- [بخش پرداخت و تراکنش] ---
@app.route('/payment/submit', methods=['POST'])
@jwt_required()
@single_session_required
def submit_payment():
    u_name = get_jwt_identity()
    user = mongo.db.users.find_one({'username': u_name})
    data = request.get_json()
    tx_hash, coupon = data.get('tx_hash','').strip(), data.get('coupon_code','').strip()
    
    if coupon:
        c = mongo.db.coupons.find_one({"code": coupon})
        if c:
            now = datetime.datetime.utcnow()
            start = user['expiryDate'] if (user.get('expiryDate') and user['expiryDate'] > now) else now
            new_exp = start + datetime.timedelta(days=c['bonus_days'])
            mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'expiryDate': new_exp}})
            mongo.db.coupons.delete_one({"_id": c['_id']})
            send_tg(user['telegram_id'], f"🎁 هدیه فعال شد! انقضا: {new_exp.strftime('%Y-%m-%d')}")
            return jsonify({"msg": "کد هدیه اعمال شد"}), 200
        return jsonify({"msg": "کد نامعتبر"}), 400

    if not tx_hash or mongo.db.transactions.find_one({"tx_hash": tx_hash}):
        return jsonify({"msg": "هش تراکنش نامعتبر یا تکراری"}), 400

    tx_id = mongo.db.transactions.insert_one({
        "user_id": user['_id'], "username": u_name, "tx_hash": tx_hash,
        "days": int(data.get('days', 30)), "status": "pending", "created_at": datetime.datetime.utcnow()
    }).inserted_id

    kb = {"inline_keyboard": [[{"text":"✅ تایید","callback_data":f"approve:{tx_id}"},{"text":"❌ رد","callback_data":f"reject:{tx_id}"}]]}
    for admin in ADMIN_IDS:
        send_tg(admin, f"💳 تراکنش جدید از `{u_name}`\nهش: `{tx_hash}`", kb)
    return jsonify({"msg": "تراکنش ثبت شد و در انتظار تایید است"}), 200

# --- [بخش ادمین و وب‌هوک داخلی] ---
@app.route('/admin/webhook', methods=['POST'])
def admin_webhook():
    if request.headers.get('X-Admin-Secret') != ADMIN_SECRET_KEY: return "Forbidden", 403
    data = request.get_json()
    try:
        action, tx_id = data.get('callback_data').split(':')
        tx = mongo.db.transactions.find_one({'_id': ObjectId(tx_id), 'status': 'pending'})
        if not tx: return "Not Found", 404
        
        user = mongo.db.users.find_one({'_id': tx['user_id']})
        if action == "approve":
            now = datetime.datetime.utcnow()
            start = user['expiryDate'] if (user.get('expiryDate') and user['expiryDate'] > now) else now
            new_exp = start + datetime.timedelta(days=tx['days'])
            mongo.db.users.update_one({'_id': user['_id']}, {'$set': {'expiryDate': new_exp}, '$inc': {'total_purchases': 1}})
            mongo.db.transactions.update_one({'_id': tx['_id']}, {'$set': {'status': 'approved', 'processed_at': now}})
            send_tg(user['telegram_id'], f"✅ اشتراک تایید شد تا: {new_exp.strftime('%Y-%m-%d')}")
            send_tg(LOG_CHANNEL_ID, f"💰 فروش: {user['username']} ({tx['days']} روز)")
        else:
            mongo.db.transactions.update_one({'_id': tx['_id']}, {'$set': {'status': 'rejected'}})
            send_tg(user['telegram_id'], "❌ تراکنش شما رد شد.")
        return jsonify({"status": "ok"}), 200
    except: return "Error", 400

# --- [بات تلگرام داخلی برای پردازش دکمه‌ها] ---
def run_telegram_bot():
    """این تابع کلیک روی دکمه‌های تلگرام را بدون نیاز به سرور جداگانه مدیریت می‌کند"""
    print("🤖 Internal Telegram Bot Listener Started...")
    offset = 0
    while True:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates?offset={offset}&timeout=30"
            resp = requests.get(url).json()
            if not resp.get("ok"): continue
            
            for update in resp.get("result", []):
                offset = update["update_id"] + 1
                if "callback_query" in update:
                    # ارسال اطلاعات کلیک شده به اندپوینت وب‌هوک خودمان
                    requests.post(
                        f"http://127.0.0.1:{os.getenv('PORT', 5001)}/admin/webhook",
                        json={"callback_data": update["callback_query"]["data"]},
                        headers={"X-Admin-Secret": ADMIN_SECRET_KEY}
                    )
                    # اطلاع به تلگرام که دستور دریافت شد
                    requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/answerCallbackQuery", 
                                 json={"callback_query_id": update["callback_query"]["id"], "text": "درخواست پردازش شد"})
        except Exception: time.sleep(5)

# --- [مدیریت خطاها] ---
@app.errorhandler(Exception)
def handle_exception(e):
    err = f"🆘 **Backend Crash**\n`{str(e)}`"
    for admin in ADMIN_IDS: send_tg(admin, err)
    return jsonify({"msg": "Internal Server Error"}), 500

if __name__ == '__main__':
    setup_database()
    # اجرای بات تلگرام در یک ترد جداگانه
    threading.Thread(target=run_telegram_bot, daemon=True).start()
    
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", 5001)), debug=False)
