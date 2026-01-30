# database.py – Stable SQLite Layer for Secure Chat (with ROLE column added)

import sqlite3
import os
import uuid  # ✅ NEW

# ----------------------------------------
# Database File Location
# ----------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FOLDER = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_FOLDER, "secure_chat.db")


# ----------------------------------------
# Connection Helper
# ----------------------------------------
def get_db_connection():
    """Create DB folder if needed, return SQLite connection."""
    os.makedirs(DB_FOLDER, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ----------------------------------------
# ✅ NEW: DB UUID helpers (used for clearing localStorage when DB resets)
# ----------------------------------------
def _ensure_db_uuid(cur):
    """
    Ensure the DB has a unique signature stored in meta table.
    Called inside init_db() after tables exist.
    """
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)

    cur.execute("SELECT value FROM meta WHERE key = 'db_uuid' LIMIT 1;")
    row = cur.fetchone()

    if not row:
        new_uuid = str(uuid.uuid4())
        cur.execute("INSERT INTO meta (key, value) VALUES ('db_uuid', ?);", (new_uuid,))


def get_db_uuid():
    """
    Return the current DB UUID signature.
    If missing (older DB), create it safely.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    # Make sure meta exists
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)

    cur.execute("SELECT value FROM meta WHERE key = 'db_uuid' LIMIT 1;")
    row = cur.fetchone()

    if not row:
        new_uuid = str(uuid.uuid4())
        cur.execute("INSERT INTO meta (key, value) VALUES ('db_uuid', ?);", (new_uuid,))
        conn.commit()
        conn.close()
        return new_uuid

    conn.close()
    return row["value"]


# ----------------------------------------
# Initialize Database Schema
# ----------------------------------------
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # USER ACCOUNTS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            public_key TEXT NOT NULL,
            encrypted_private_key TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # ENCRYPTED MESSAGES STORAGE
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            encrypted_message TEXT NOT NULL,
            encrypted_aes_key TEXT NOT NULL,
            iv TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender) REFERENCES users(username),
            FOREIGN KEY (receiver) REFERENCES users(username)
        );
    """)

    # ----------------------------------------
    # ENCRYPTED FILES STORAGE
    # ----------------------------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,

            filename TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,

            encrypted_file TEXT NOT NULL,
            encrypted_aes_key_receiver TEXT NOT NULL,
            encrypted_aes_key_sender TEXT NOT NULL,
            iv TEXT NOT NULL,

            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (sender) REFERENCES users(username),
            FOREIGN KEY (receiver) REFERENCES users(username)
        );
    """)

    # ----------------------------------------
    # Ensure DB UUID exists (signature changes when DB file is deleted)
    # ----------------------------------------
    _ensure_db_uuid(cur)

    # ----------------------------------------
    # AUTO-MIGRATION (SAFE) for existing DBs
    # ----------------------------------------
    def table_columns(table_name: str):
        cur.execute(f"PRAGMA table_info({table_name});")
        return {row["name"] for row in cur.fetchall()}

    # If an older "files" table exists (missing new columns), add them safely.
    existing_tables = set()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    for r in cur.fetchall():
        existing_tables.add(r["name"])

    if "files" in existing_tables:
        cols = table_columns("files")

        # Older versions might have used different column names:
        # - encrypted_aes_key (single) instead of receiver/sender split
        if "encrypted_aes_key_receiver" not in cols:
            cur.execute("ALTER TABLE files ADD COLUMN encrypted_aes_key_receiver TEXT;")
        if "encrypted_aes_key_sender" not in cols:
            cur.execute("ALTER TABLE files ADD COLUMN encrypted_aes_key_sender TEXT;")
        if "size_bytes" not in cols:
            cur.execute("ALTER TABLE files ADD COLUMN size_bytes INTEGER;")
        if "mime_type" not in cols:
            cur.execute("ALTER TABLE files ADD COLUMN mime_type TEXT;")
        if "filename" not in cols:
            cur.execute("ALTER TABLE files ADD COLUMN filename TEXT;")
        if "sha256" not in cols:
            cur.execute("ALTER TABLE files ADD COLUMN sha256 TEXT;")

        # Backfill receiver/sender keys from old column if it exists
        cols_after = table_columns("files")
        if "encrypted_aes_key" in cols_after:
            cur.execute("""
                UPDATE files
                SET encrypted_aes_key_receiver = COALESCE(encrypted_aes_key_receiver, encrypted_aes_key),
                    encrypted_aes_key_sender   = COALESCE(encrypted_aes_key_sender, encrypted_aes_key)
                WHERE encrypted_aes_key IS NOT NULL;
            """)

        # NOTE: We can't safely force NOT NULL after ALTER in SQLite without rebuilding the table.
        # For demo, this is fine.

    # Indexes for speed
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sender ON messages (sender);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_receiver ON messages (receiver);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON messages (timestamp);")

    # NEW indexes for file queries
    cur.execute("CREATE INDEX IF NOT EXISTS idx_files_sender ON files (sender);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_files_receiver ON files (receiver);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_files_timestamp ON files (timestamp);")

    conn.commit()
    conn.close()
    print("[DB] Initialized and ready.")


# ----------------------------------------
# Store New Encrypted Message
# ----------------------------------------
def store_message(sender, receiver, encrypted_message, encrypted_aes_key, iv):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO messages (sender, receiver, encrypted_message, encrypted_aes_key, iv)
        VALUES (?, ?, ?, ?, ?)
    """, (sender, receiver, encrypted_message, encrypted_aes_key, iv))

    conn.commit()
    conn.close()


# ----------------------------------------
# Store New Encrypted File
# ----------------------------------------
def store_file(sender, receiver, filename, mime_type, size_bytes, sha256,
              encrypted_file, encrypted_aes_key_receiver, encrypted_aes_key_sender, iv):
    """
    Store encrypted file transfer in DB.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO files (
            sender, receiver,
            filename, mime_type, size_bytes, sha256,
            encrypted_file, encrypted_aes_key_receiver, encrypted_aes_key_sender, iv
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        sender, receiver,
        filename, mime_type, int(size_bytes), sha256,
        encrypted_file, encrypted_aes_key_receiver, encrypted_aes_key_sender, iv
    ))

    conn.commit()
    conn.close()


# ----------------------------------------
# Load Full Conversation (Matches chat.js Format)
# ----------------------------------------
def load_conversation(user1, user2):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT sender, receiver, encrypted_message, encrypted_aes_key, iv, timestamp
        FROM messages
        WHERE (sender = ? AND receiver = ?)
           OR (sender = ? AND receiver = ?)
        ORDER BY timestamp ASC
    """, (user1, user2, user2, user1))

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]


# ----------------------------------------
# NEW: Load File Transfers Between Two Users
# ----------------------------------------
def load_files_between(user1, user2):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id, sender, receiver,
            filename, mime_type, size_bytes, sha256,
            encrypted_file, encrypted_aes_key_receiver, encrypted_aes_key_sender, iv,
            timestamp
        FROM files
        WHERE (sender = ? AND receiver = ?)
           OR (sender = ? AND receiver = ?)
        ORDER BY timestamp ASC
    """, (user1, user2, user2, user1))

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]


# ----------------------------------------
# NEW: Get file by id
# ----------------------------------------
def get_file_by_id(file_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id, sender, receiver,
            filename, mime_type, size_bytes, sha256,
            encrypted_file, encrypted_aes_key_receiver, encrypted_aes_key_sender, iv,
            timestamp
        FROM files
        WHERE id = ?
    """, (file_id,))

    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


# ----------------------------------------
# Get All Users Except Current
# ----------------------------------------
def get_all_users(exclude_user):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT username FROM users WHERE username != ?", (exclude_user,))
    rows = cur.fetchall()

    conn.close()
    return [row["username"] for row in rows]
