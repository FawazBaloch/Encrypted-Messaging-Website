# app.py

from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import re
from datetime import datetime, timedelta

from database import (
    init_db, get_db_connection, load_conversation,
    load_files_between, get_file_by_id,
    get_db_uuid  
)
from crypto_utils import generate_rsa_keypair, encrypt_private_key_with_password

app = Flask(__name__)

# Allow all origins (including file:// → origin "null")
CORS(app, resources={r"/*": {"origins": "*"}})

app.config["SECRET_KEY"] = "SUPER_SECRET_KEY_CHANGE_THIS"

# Initialize DB
init_db()

# DB signature endpoint
@app.route("/db_signature", methods=["GET"])
def db_signature():
    return jsonify({"db_uuid": get_db_uuid()}), 200


# ============================================================
# AUTO-CREATE DEFAULT ADMIN (NEW)
# ============================================================
def ensure_default_admin():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE username = 'admin'")
    admin = cur.fetchone()

    if not admin:
        print("⚠️ Creating default admin account...")

        admin_password = "Admin@123"  # default admin password

        # RSA keys
        print("🔐 [KEYGEN] Generating RSA keypair for default admin (server-side)...")  # ✅ ADDED
        public_key, private_key_pem = generate_rsa_keypair()
        encrypted_private_key = encrypt_private_key_with_password(private_key_pem, admin_password)
        print("✅ [KEYGEN] Admin RSA keys generated + private key encrypted.")  # ✅ ADDED

        # Hash password
        password_hash = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt())

        cur.execute("""
            INSERT INTO users (username, password_hash, public_key, encrypted_private_key, role)
            VALUES (?, ?, ?, ?, 'admin')
        """, ("admin", password_hash, public_key, encrypted_private_key))

        conn.commit()
        print("✅ Default admin created → username=admin  password=Admin@123")

    conn.close()


# Call admin creation
ensure_default_admin()


# ============================================================
# Helpers
# ============================================================

def get_user(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def generate_token(username, role):
    payload = {
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=6),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def decode_token(token):
    """Decode JWT and return payload or None."""
    try:
        return jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except:
        return None


# ------------------------------------------------------------
# Token Required Decorator (Used for Admin Routes)
# ------------------------------------------------------------
def token_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")

        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid token"}), 401

        token = auth.split(" ")[1]
        decoded = decode_token(token)

        if not decoded:
            return jsonify({"error": "Invalid or expired token"}), 401

        request.user = decoded
        return fn(*args, **kwargs)

    return wrapper


# ------------------------------------------------------------
# Password Strength Check
# ------------------------------------------------------------
def password_is_strong(password):
    pattern = re.compile(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$"
    )
    return bool(pattern.match(password))


# ============================================================
# REGISTER
# ============================================================
@app.route("/api/register", methods=["POST"])
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    if get_user(username):
        return jsonify({"error": "Username already taken"}), 400

    if not password_is_strong(password):
        return jsonify({"error": "Password must include A-Z, a-z, number, special char, 8+ chars"}), 400

    print(f"🧾 [REGISTER] New registration request: username={username}")
    print(f"🔐 [KEYGEN] Generating RSA keypair for user '{username}' (server-side)...")

    public_key, private_key_pem = generate_rsa_keypair()
    encrypted_private_key = encrypt_private_key_with_password(private_key_pem, password)

    print(f"✅ [KEYGEN] RSA keys generated for '{username}' + private key encrypted.")

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO users (username, password_hash, public_key, encrypted_private_key, role)
        VALUES (?, ?, ?, ?, 'user')
    """, (username, password_hash, public_key, encrypted_private_key))

    conn.commit()
    conn.close()

    print(f"✅ [REGISTER] User '{username}' saved to database.")  

    return jsonify({"message": "Registered successfully!"}), 201


# ============================================================
# LOGIN (with role)
# ============================================================
@app.route("/api/login", methods=["POST"])
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = get_user(username)
    if not user:
        return jsonify({"error": "Invalid login"}), 401

    stored_hash = user["password_hash"]
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode()

    if not bcrypt.checkpw(password.encode(), stored_hash):
        return jsonify({"error": "Invalid login"}), 401

    token = generate_token(username, user["role"])

    return jsonify({
        "token": token,
        "username": username,
        "role": user["role"],
        "encrypted_private_key": user["encrypted_private_key"],
    }), 200


# ============================================================
# PUBLIC KEY
# ============================================================
@app.route("/public_key/<username>", methods=["GET"])
def public_key(username):
    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"public_key": user["public_key"]})


# ============================================================
# USER LIST
# ============================================================
@app.route("/users", methods=["GET"])
def list_users():
    exclude = request.args.get("exclude")
    conn = get_db_connection()
    cur = conn.cursor()

    if exclude:
        cur.execute("SELECT username FROM users WHERE username != ? AND role != 'admin'", (exclude,))
    else:
        cur.execute("SELECT username FROM users WHERE role != 'admin'")

    users = [row["username"] for row in cur.fetchall()]
    conn.close()

    return jsonify({"users": users})


# ============================================================
# USER SEARCH
# ============================================================
@app.route("/search_user", methods=["GET"])
def search_user():
    username = request.args.get("username", "").strip()
    return jsonify({"exists": get_user(username) is not None})


# ============================================================
# CONVERSATION (messages)
# ============================================================
@app.route("/messages", methods=["GET"])
def messages():
    user1 = request.args.get("user1")
    user2 = request.args.get("user2")

    if not user1 or not user2:
        return jsonify({"error": "Missing parameters"}), 400

    msgs = load_conversation(user1, user2)
    return jsonify({"messages": msgs})


# ============================================================
# FILES 
# ============================================================
@app.route("/files", methods=["GET"])
def files_between_users():
    user1 = request.args.get("user1")
    user2 = request.args.get("user2")

    if not user1 or not user2:
        return jsonify({"error": "Missing parameters"}), 400

    files = load_files_between(user1, user2)
    return jsonify({"files": files})


@app.route("/files/<int:file_id>", methods=["GET"])
def get_file(file_id):
    f = get_file_by_id(file_id)
    if not f:
        return jsonify({"error": "File not found"}), 404

    f = dict(f)
    f["mimetype"] = f.get("mime_type")
    f["filesize"] = f.get("size_bytes")

    return jsonify(f)


# ============================================================
# ADMIN LOGS (messages)
# ============================================================
@app.route("/admin/logs", methods=["GET"])
@token_required
def admin_logs():
    if request.user["role"] != "admin":
        return jsonify({"error": "Not authorized"}), 403
    sender_filter = request.args.get("sender")
    receiver_filter = request.args.get("receiver")

    conn = get_db_connection()
    cur = conn.cursor()

    query = "SELECT * FROM messages WHERE 1=1"
    params = []

    if sender_filter:
        query += " AND sender = ?"
        params.append(sender_filter)

    if receiver_filter:
        query += " AND receiver = ?"
        params.append(receiver_filter)
    query += " ORDER BY timestamp DESC"
    cur.execute(query, params)
    logs = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jsonify({"logs": logs})


# ============================================================
# ADMIN FILE LOGS 
# ============================================================
@app.route("/admin/files", methods=["GET"])
@token_required
def admin_files():
    if request.user["role"] != "admin":
        return jsonify({"error": "Not authorized"}), 403

    sender_filter = request.args.get("sender")
    receiver_filter = request.args.get("receiver")

    conn = get_db_connection()
    cur = conn.cursor()

    query = "SELECT * FROM files WHERE 1=1"
    params = []

    if sender_filter:
        query += " AND sender = ?"
        params.append(sender_filter)

    if receiver_filter:
        query += " AND receiver = ?"
        params.append(receiver_filter)

    query += " ORDER BY timestamp DESC"

    cur.execute(query, params)
    logs = [dict(row) for row in cur.fetchall()]
    conn.close()

    normalized = []
    for f in logs:
        f = dict(f)
        f["mimetype"] = f.get("mime_type")
        f["filesize"] = f.get("size_bytes")
        normalized.append(f)

    return jsonify({"logs": normalized})


@app.route("/admin/file-logs", methods=["GET"])
@token_required
def admin_file_logs_alias():
    return admin_files()


# ============================================================
# RUN APP
# ============================================================
if __name__ == "__main__":
    print("🔥 Flask API running at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
