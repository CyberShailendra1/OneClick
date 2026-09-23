"""
Persistence layer: scan history + VirusTotal hash cache.
Uses SQLite so there's zero external dependency (no server to run).
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "oneclick.db")


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                filename TEXT,
                sha256 TEXT NOT NULL,
                package_name TEXT,
                verdict TEXT,
                risk_score REAL,
                source TEXT,               -- 'virustotal' | 'ml_model'
                features_json TEXT,
                reasons_json TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vt_cache (
                sha256 TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                cached_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                url TEXT NOT NULL,
                verdict TEXT,
                risk_score REAL,
                reasons_json TEXT,
                user_action TEXT DEFAULT 'none'   -- 'none' | 'dismissed' | 'deleted_by_user'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT UNIQUE NOT NULL,
                name TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_otps (
                phone TEXT PRIMARY KEY,
                otp_code TEXT NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                token TEXT PRIMARY KEY,
                phone TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON scan_history(sha256)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_url ON url_scan_history(url)")


def save_scan(filename: str, sha256: str, verdict: str, risk_score: float,
              source: str, features: dict = None, reasons: list = None,
              package_name: str = None):
    init_db()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO scan_history
               (timestamp, filename, sha256, package_name, verdict, risk_score,
                source, features_json, reasons_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                filename,
                sha256,
                package_name,
                verdict,
                risk_score,
                source,
                json.dumps(features or {}, default=str),
                json.dumps(reasons or []),
            ),
        )


def get_history(limit: int = 100) -> list:
    init_db()
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_history_by_hash(sha256: str):
    init_db()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_history WHERE sha256 = ? ORDER BY id DESC LIMIT 1",
            (sha256,),
        ).fetchone()
        return dict(row) if row else None


def cache_vt_result(sha256: str, result: dict):
    init_db()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO vt_cache (sha256, result_json, cached_at)
               VALUES (?, ?, ?)
               ON CONFLICT(sha256) DO UPDATE SET result_json=excluded.result_json,
                                                  cached_at=excluded.cached_at""",
            (sha256, json.dumps(result), datetime.now(timezone.utc).isoformat()),
        )


def get_cached_vt_result(sha256: str, max_age_hours: int = 24):
    """Returns cached VT result if fresh enough, else None (forces a re-query)."""
    init_db()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT result_json, cached_at FROM vt_cache WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if not row:
            return None
        cached_at = datetime.fromisoformat(row["cached_at"])
        if cached_at.tzinfo is None:
            # Backward-compat: rows written before this fix stored naive UTC
            # timestamps. Treat them as UTC rather than raising a
            # naive/aware TypeError on the subtraction below.
            cached_at = cached_at.replace(tzinfo=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
        if age_hours > max_age_hours:
            return None
        return json.loads(row["result_json"])


def clear_history():
    init_db()
    with get_conn() as conn:
        conn.execute("DELETE FROM scan_history")
        conn.execute("DELETE FROM vt_cache")


def save_url_scan(url: str, verdict: str, risk_score: float, reasons: list = None) -> int:
    """Saves a URL scan result and returns its row id (used for later user-action updates)."""
    init_db()
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO url_scan_history (timestamp, url, verdict, risk_score, reasons_json)
               VALUES (?, ?, ?, ?, ?)""",
            (datetime.now(timezone.utc).isoformat(), url, verdict, risk_score, json.dumps(reasons or [])),
        )
        return cur.lastrowid


def get_url_history(limit: int = 100) -> list:
    init_db()
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM url_scan_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def set_url_scan_action(row_id: int, action: str):
    """
    Records what the USER decided to do about a flagged URL
    ('dismissed' = user reviewed and kept it, 'deleted_by_user' = user
    manually removed the message/link themselves). OneClick never sets this
    automatically - see modules/phishing_scanner.py for the design rationale.
    """
    init_db()
    with get_conn() as conn:
        conn.execute("UPDATE url_scan_history SET user_action = ? WHERE id = ?", (action, row_id))


def clear_url_history():
    init_db()
    with get_conn() as conn:
        conn.execute("DELETE FROM url_scan_history")


# ---------------------------------------------------------------------------
# User Authentication & Sessions (Optional Login)
# ---------------------------------------------------------------------------

def save_otp(phone: str, otp_code: str, ttl_seconds: int = 300):
    init_db()
    import time
    expires_at = time.time() + ttl_seconds
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO user_otps (phone, otp_code, expires_at)
               VALUES (?, ?, ?)
               ON CONFLICT(phone) DO UPDATE SET otp_code=excluded.otp_code, expires_at=excluded.expires_at""",
            (phone, otp_code, expires_at)
        )


def verify_otp_and_login(phone: str, otp_code: str) -> dict | None:
    init_db()
    import time
    import uuid
    with get_conn() as conn:
        row = conn.execute(
            "SELECT otp_code, expires_at FROM user_otps WHERE phone = ?", (phone,)
        ).fetchone()
        if not row:
            return None
        if time.time() > row["expires_at"]:
            return None
        if row["otp_code"] != otp_code:
            return None

        # Clean OTP
        conn.execute("DELETE FROM user_otps WHERE phone = ?", (phone,))

        # Upsert user
        now_str = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT INTO users (phone, name, created_at, last_login)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(phone) DO UPDATE SET last_login=excluded.last_login""",
            (phone, f"Citizen User", now_str, now_str)
        )

        # Create session token
        token = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO user_sessions (token, phone, created_at) VALUES (?, ?, ?)",
            (token, phone, now_str)
        )
        return {"token": token, "phone": phone}


def get_user_from_token(token: str) -> dict | None:
    init_db()
    with get_conn() as conn:
        session = conn.execute(
            "SELECT phone, created_at FROM user_sessions WHERE token = ?", (token,)
        ).fetchone()
        if not session:
            return None
        user = conn.execute(
            "SELECT * FROM users WHERE phone = ?", (session["phone"],)
        ).fetchone()
        if user:
            return dict(user)
        return {"phone": session["phone"]}


def delete_session(token: str):
    init_db()
    with get_conn() as conn:
        conn.execute("DELETE FROM user_sessions WHERE token = ?", (token,))

