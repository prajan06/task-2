import sqlite3
import time

from flask import Flask, current_app, g, jsonify, request

from . import hashing, sessions, validation
from .ratelimit import FailureLimiter

COOKIE_NAME = "__Host-session"  # __Host- prefix: Secure, Path=/, no Domain attribute

DEFAULTS = {
    "DB_PATH": "auth.db",
    "CLOCK": time.time,
    "SESSION_IDLE_SECONDS": 15 * 60,
    "SESSION_ABSOLUTE_SECONDS": 8 * 60 * 60,
    "LOGIN_MAX_FAILURES_PER_ACCOUNT": 5,
    "LOGIN_MAX_FAILURES_PER_IP": 20,
    "LOGIN_WINDOW_SECONDS": 15 * 60,
    "REGISTER_MAX_PER_IP": 10,
    "REGISTER_WINDOW_SECONDS": 60 * 60,
    "MAX_CONTENT_LENGTH": 4096,
}

GENERIC_LOGIN_ERROR = "Invalid username or password."
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at REAL NOT NULL,
  last_seen REAL NOT NULL
);
"""


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(DEFAULTS)
    app.config.update(config or {})
    clock = app.config["CLOCK"]

    app.extensions["login_account_limiter"] = FailureLimiter(
        app.config["LOGIN_MAX_FAILURES_PER_ACCOUNT"], app.config["LOGIN_WINDOW_SECONDS"], clock)
    app.extensions["login_ip_limiter"] = FailureLimiter(
        app.config["LOGIN_MAX_FAILURES_PER_IP"], app.config["LOGIN_WINDOW_SECONDS"], clock)
    app.extensions["register_limiter"] = FailureLimiter(
        app.config["REGISTER_MAX_PER_IP"], app.config["REGISTER_WINDOW_SECONDS"], clock)

    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.executescript(SCHEMA)

    # ---- helpers -------------------------------------------------------
    def db():
        if "db" not in g:
            g.db = sqlite3.connect(current_app.config["DB_PATH"], timeout=5)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    def now():
        return current_app.config["CLOCK"]()

    def client_ip():
        # remote_addr only. Do NOT trust X-Forwarded-For unless a known proxy sets it.
        return request.remote_addr or "unknown"

    def json_body():
        """Require JSON (forces a CORS preflight for cross-site requests)."""
        if not request.is_json:
            return None, (jsonify(error="Content-Type must be application/json."), 415)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return None, (jsonify(error="Invalid request."), 400)
        return data, None

    def set_session_cookie(resp, token):
        resp.set_cookie(
            COOKIE_NAME, token,
            max_age=current_app.config["SESSION_ABSOLUTE_SECONDS"],
            httponly=True, secure=True, samesite="Lax", path="/",
        )

    def clear_session_cookie(resp):
        resp.delete_cookie(COOKIE_NAME, httponly=True, secure=True, samesite="Lax", path="/")

    def current_user():
        c = current_app.config
        return sessions.lookup(db(), request.cookies.get(COOKIE_NAME), now(),
                               c["SESSION_IDLE_SECONDS"], c["SESSION_ABSOLUTE_SECONDS"])

    @app.after_request
    def security_headers(resp):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify(error="Request too large."), 413

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify(error="Not found."), 404

    @app.errorhandler(405)
    def bad_method(_e):
        return jsonify(error="Method not allowed."), 405

    # ---- routes --------------------------------------------------------
    @app.post("/register")
    def register():
        limiter = app.extensions["register_limiter"]
        ip = client_ip()
        wait = limiter.retry_after(ip)
        if wait:
            resp = jsonify(error="Too many attempts. Try again later.")
            resp.status_code = 429
            resp.headers["Retry-After"] = str(wait)
            return resp
        limiter.record(ip)  # every registration attempt counts

        data, err = json_body()
        if err:
            return err
        username, password = data.get("username"), data.get("password")
        errors = validation.validate_username(username) + validation.validate_password(
            password, username if isinstance(username, str) else "")
        if errors:
            return jsonify(errors=errors), 400

        pw_hash = hashing.hash_password(password)
        try:
            db().execute("INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
                         (username, pw_hash, now()))
            db().commit()
        except sqlite3.IntegrityError:
            return jsonify(error="Username unavailable."), 409
        return jsonify(message="Account created."), 201

    @app.post("/login")
    def login():
        data, err = json_body()
        if err:
            return err
        username, password = data.get("username"), data.get("password")
        if not isinstance(username, str) or not isinstance(password, str) \
                or len(username) > 64 or len(password) > validation.PASSWORD_MAX:
            return jsonify(error=GENERIC_LOGIN_ERROR), 401

        acct_lim = app.extensions["login_account_limiter"]
        ip_lim = app.extensions["login_ip_limiter"]
        acct_key, ip = username.strip().lower(), client_ip()

        # Throttle BEFORE doing any password work. Keyed on the submitted name
        # whether or not it exists, so lockout doesn't reveal which accounts are real.
        wait = max(acct_lim.retry_after(acct_key), ip_lim.retry_after(ip))
        if wait:
            resp = jsonify(error="Too many attempts. Try again later.")
            resp.status_code = 429
            resp.headers["Retry-After"] = str(wait)
            return resp

        row = db().execute("SELECT id, password_hash FROM users WHERE username = ?",
                           (username.strip(),)).fetchone()
        stored = row["password_hash"] if row else hashing.DUMMY_HASH
        ok = hashing.verify_password(password, stored) and row is not None
        if not ok:
            acct_lim.record(acct_key)
            ip_lim.record(ip)
            return jsonify(error=GENERIC_LOGIN_ERROR), 401

        acct_lim.reset(acct_key)
        c = app.config
        if hashing.needs_rehash(stored):
            db().execute("UPDATE users SET password_hash = ? WHERE id = ?",
                         (hashing.hash_password(password), row["id"]))
            db().commit()

        # Rotate: drop old sessions (prevents fixation) and issue a fresh token.
        sessions.destroy_all_for_user(db(), row["id"])
        sessions.purge_expired(db(), now(), c["SESSION_IDLE_SECONDS"], c["SESSION_ABSOLUTE_SECONDS"])
        token = sessions.create(db(), row["id"], now())
        resp = jsonify(message="Logged in.")
        set_session_cookie(resp, token)
        return resp

    @app.post("/logout")
    def logout():
        _, err = json_body()
        if err:
            return err
        sessions.destroy(db(), request.cookies.get(COOKIE_NAME))  # server-side invalidation
        resp = jsonify(message="Logged out.")
        clear_session_cookie(resp)
        return resp

    @app.get("/me")
    def me():
        user = current_user()
        if user is None:
            return jsonify(error="Not authenticated."), 401
        return jsonify(username=user["username"])

    return app
