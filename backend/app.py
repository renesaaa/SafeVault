from flask import (
    Flask, request, jsonify, send_from_directory,
    session, redirect
)
from database import initialize_database, get_connection, STORAGE_ROOT
from werkzeug.utils import secure_filename
from pathlib import Path
from ai import analyze_text, analyze_image
import mimetypes
import uuid
import os
import hmac
import time
import secrets
import threading
from datetime import datetime, timedelta
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix


app = Flask(
    __name__,
    static_folder="../frontend",
    static_url_path=""
)

# Load SafeVault/.env (the project root, one level above backend/) by absolute
# path, so it is found no matter which directory Flask is started from.
# This must run before SAFEVAULT_PIN / SECRET_KEY are read below.
# override=True so this file wins over a stale value already in the
# environment (e.g. loaded earlier by ai.py from another .env).
# (Named PROJECT_ROOT because BASE_DIR below is already the backend folder.)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"
_env_loaded = load_dotenv(ENV_PATH, override=True)
print(f"[SafeVault] .env path: {ENV_PATH} "
      f"({'found' if ENV_PATH.is_file() else 'NOT FOUND'})")


# ---------------------------------------------------------
# SAFEVAULT SECURITY LOCK
#   SAFEVAULT_PIN         6-digit PIN (server side only, from .env)
#   SECRET_KEY            signs the Flask session cookie (from .env)
#   SAFEVAULT_SESSION_MINUTES   optional, default 120
#   SAFEVAULT_COOKIE_SECURE     optional, 1/0; defaults to 1 on Render
# ---------------------------------------------------------

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    # Safe fallback: a random key per start. Everyone is simply locked
    # again whenever the server restarts. Set SECRET_KEY in .env to keep
    # sessions across restarts.
    SECRET_KEY = secrets.token_hex(32)
    print("[SafeVault] WARNING: SECRET_KEY not set in .env - using a "
          "temporary random key (sessions reset on restart).")

# On Render (which sets RENDER=true) the site is always served over HTTPS
# behind a proxy, so default to Secure cookies and trust the proxy headers.
# Both can be overridden with SAFEVAULT_COOKIE_SECURE / SAFEVAULT_TRUST_PROXY.
_ON_RENDER = os.environ.get("RENDER") == "true"
_cookie_secure_env = os.environ.get("SAFEVAULT_COOKIE_SECURE")
COOKIE_SECURE = (_cookie_secure_env == "1") if _cookie_secure_env is not None else _ON_RENDER
_trust_proxy_env = os.environ.get("SAFEVAULT_TRUST_PROXY")
TRUST_PROXY = (_trust_proxy_env == "1") if _trust_proxy_env is not None else _ON_RENDER

if TRUST_PROXY:
    # Without this every visitor appears to come from the proxy's address,
    # so one person's wrong PINs would lock out everybody.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=105 * 1024 * 1024,
    SESSION_COOKIE_NAME="safevault_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(
        minutes=int(os.environ.get("SAFEVAULT_SESSION_MINUTES", "120") or 120)
    ),
)

_PIN = (os.getenv("SAFEVAULT_PIN") or "").strip()
PIN_CONFIGURED = len(_PIN) == 6 and _PIN.isascii() and _PIN.isdigit()

if not PIN_CONFIGURED:
    # Fail closed: nobody can unlock until a valid PIN is configured.
    _why = ("not set" if not _PIN
            else f"set but is {len(_PIN)} characters / not all digits")
    print(f"[SafeVault] WARNING: SAFEVAULT_PIN is {_why}. It must be "
          "exactly 6 digits - the vault cannot be unlocked.")

# Server-side record of live sessions, so Lock Vault really invalidates a
# session (a signed cookie alone could otherwise be replayed).
_active_sessions = set()

# Brute-force protection (per client address, in memory)
MAX_FREE_ATTEMPTS = 5          # failures allowed before a lockout starts
BASE_LOCKOUT_SECONDS = 30      # first lockout; doubles each further round
MAX_LOCKOUT_SECONDS = 15 * 60
_attempts = {}                 # ip -> {"fails": int, "locked_until": float}
_attempts_lock = threading.Lock()

# Pages/assets that must stay reachable while locked. Everything else
# (dashboard, evidence, timeline and every /api/* route) requires a session.
PUBLIC_PATHS = {
    "/", "/index.html",            # decoy
    "/sos.html",                   # emergency page
    "/lock.html", "/security.js",  # lock screen + shared lock helper
    "/style.css", "/script.js",    # decoy assets
    "/favicon.ico",
    "/health",                     # deployment health check (no data)
}
PUBLIC_API = {"/api/auth/unlock", "/api/auth/lock", "/api/auth/status"}
LOCK_NEXT_ALLOWED = {"/dashboard.html", "/evidence.html", "/timeline.html"}


def is_authenticated():
    sid = session.get("sid")
    return bool(sid) and sid in _active_sessions


def _client_key():
    return request.remote_addr or "unknown"


def _lockout_remaining(key):
    with _attempts_lock:
        entry = _attempts.get(key)
        if not entry:
            return 0
        return max(0, int(entry["locked_until"] - time.time() + 0.999))


def _register_failure(key):
    with _attempts_lock:
        entry = _attempts.setdefault(key, {"fails": 0, "locked_until": 0.0})
        entry["fails"] += 1
        if entry["fails"] % MAX_FREE_ATTEMPTS == 0:
            rounds = entry["fails"] // MAX_FREE_ATTEMPTS
            seconds = min(BASE_LOCKOUT_SECONDS * (2 ** (rounds - 1)),
                          MAX_LOCKOUT_SECONDS)
            entry["locked_until"] = time.time() + seconds


def _clear_failures(key):
    with _attempts_lock:
        _attempts.pop(key, None)


@app.before_request
def require_unlock():
    """Default-deny gate: only the explicit public paths work while locked."""

    path = request.path

    if path in PUBLIC_PATHS or path in PUBLIC_API:
        return None

    if request.method == "OPTIONS":
        return None

    if is_authenticated():
        return None

    if path.startswith("/api/"):
        return jsonify({"error": "Unauthorized"}), 401

    # A protected page: send the visitor to the lock screen
    target = "/lock.html"
    if request.method == "GET" and path in LOCK_NEXT_ALLOWED:
        target += "?next=" + path.lstrip("/")
    return redirect(target)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"

    # Never let the browser/proxies cache anything sensitive, so the Back
    # button cannot reveal the vault after it has been locked.
    if request.path not in {"/", "/index.html", "/style.css", "/script.js"}:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

    return response


@app.route("/lock.html")
def lock_page():
    # Already unlocked? Skip the lock screen.
    if is_authenticated():
        return redirect("/dashboard.html")
    return app.send_static_file("lock.html")


@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    return jsonify({"authenticated": is_authenticated()})


@app.route("/api/auth/unlock", methods=["POST"])
def auth_unlock():

    key = _client_key()

    remaining = _lockout_remaining(key)
    if remaining > 0:
        response = jsonify({
            "error": "Too many attempts. Please wait before trying again.",
            "retry_after": remaining
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(remaining)
        return response

    if not PIN_CONFIGURED:
        return jsonify({
            "error": "SafeVault is not configured. Set SAFEVAULT_PIN on the server."
        }), 503

    data = request.get_json(silent=True)
    pin = data.get("pin") if isinstance(data, dict) else None

    # Constant-time comparison; wrong format is treated like a wrong PIN.
    ok = (
        isinstance(pin, str)
        and hmac.compare_digest(pin.encode("utf-8"), _PIN.encode("utf-8"))
    )

    if not ok:
        _register_failure(key)
        remaining = _lockout_remaining(key)
        if remaining > 0:
            response = jsonify({
                "error": "Too many attempts. Please wait before trying again.",
                "retry_after": remaining
            })
            response.status_code = 429
            response.headers["Retry-After"] = str(remaining)
            return response
        return jsonify({"error": "Incorrect PIN"}), 401

    _clear_failures(key)

    # Fresh session on every successful unlock
    old_sid = session.get("sid")
    if old_sid:
        _active_sessions.discard(old_sid)
    session.clear()

    sid = secrets.token_urlsafe(32)
    _active_sessions.add(sid)
    session["sid"] = sid
    session.permanent = True

    return jsonify({"ok": True, "redirect": "/dashboard.html"})


@app.route("/api/auth/lock", methods=["POST"])
def auth_lock():
    sid = session.get("sid")
    if sid:
        _active_sessions.discard(sid)
    session.clear()
    return jsonify({"ok": True, "redirect": "/lock.html"})


BASE_DIR = Path(__file__).resolve().parent
# Evidence files live in backend/uploads by default, or in
# $SAFEVAULT_STORAGE_PATH/uploads when that variable is set.
UPLOAD_FOLDER = (STORAGE_ROOT / "uploads") if STORAGE_ROOT else (BASE_DIR / "uploads")

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)


# Make sure the database exists
initialize_database()


def ensure_extra_columns():
    """Additively add optional columns used by the Evidence Gallery.
    Existing rows and columns are untouched."""
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("PRAGMA table_info(evidence)")
    existing = {row[1] for row in cursor.fetchall()}
    for column in ("display_name", "tags"):
        if column not in existing:
            cursor.execute(f"ALTER TABLE evidence ADD COLUMN {column} TEXT")
    connection.commit()
    connection.close()


ensure_extra_columns()


# ---------------------------------------------------------
# HEALTH CHECK (public, returns no data)
# ---------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# ---------------------------------------------------------
# HOME
# ---------------------------------------------------------

@app.route("/")
def home():
    return app.send_static_file("index.html")

# ---------------------------------------------------------
# ADD EVIDENCE MANUALLY
# ---------------------------------------------------------

@app.route("/api/evidence", methods=["POST"])
def add_evidence():

    data = request.get_json()

    filename = data.get("filename")
    evidence_type = data.get("evidence_type")
    incident_date = data.get("incident_date")
    category = data.get("category")
    severity = data.get("severity")
    summary = data.get("summary")

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO evidence
        (filename, evidence_type, incident_date, category, severity, summary)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        filename,
        evidence_type,
        incident_date,
        category,
        severity,
        summary
    ))

    connection.commit()

    new_id = cursor.lastrowid

    connection.close()

    return jsonify({
        "message": "Evidence added successfully!",
        "id": new_id
    }), 201


# ---------------------------------------------------------
# GET ALL EVIDENCE
# ---------------------------------------------------------

@app.route("/api/evidence", methods=["GET"])
def get_evidence():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            filename,
            evidence_type,
            incident_date,
            category,
            severity,
            summary,
            created_at,
            display_name,
            tags
        FROM evidence
        ORDER BY incident_date ASC
    """)

    rows = cursor.fetchall()

    connection.close()

    evidence_list = []

    for row in rows:

        evidence_list.append({
            "id": row[0],
            "filename": row[1],
            "evidence_type": row[2],
            "incident_date": row[3],
            "category": row[4],
            "severity": row[5],
            "summary": row[6],
            "created_at": row[7],
            "display_name": row[8],
            "tags": split_tags(row[9])
        })

    return jsonify(evidence_list)


# ---------------------------------------------------------
# UPLOAD IMAGE + GEMINI ANALYSIS + DATABASE
# ---------------------------------------------------------

@app.route("/api/upload", methods=["POST"])
def upload_file():

    # Check whether a file was uploaded
    if "file" not in request.files:
        return jsonify({
            "error": "No file uploaded"
        }), 400

    file = request.files["file"]

    # Check whether a file was selected
    if file.filename == "":
        return jsonify({
            "error": "No file selected"
        }), 400

    # Make the filename safe
    filename = secure_filename(file.filename)

    # Create the file path
    file_path = UPLOAD_FOLDER / filename

    # Save the uploaded file
    file.save(file_path)

    try:

        # -------------------------------------------------
        # SEND IMAGE TO GEMINI
        # -------------------------------------------------

        analysis = analyze_image(str(file_path))


        # -------------------------------------------------
        # SAVE AI RESULT TO DATABASE
        # -------------------------------------------------

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO evidence
            (filename, evidence_type, incident_date, category, severity, summary)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            filename,
            "image",
            analysis.get("incident_date"),
            analysis.get("category"),
            analysis.get("severity"),
            analysis.get("summary")
        ))

        connection.commit()

        new_id = cursor.lastrowid

        connection.close()


        # -------------------------------------------------
        # RETURN RESULT TO FRONTEND
        # -------------------------------------------------

        return jsonify({
            "message": "File uploaded, analyzed and saved successfully!",
            "id": new_id,
            "filename": filename,
            "analysis": analysis
        }), 201


    except Exception as error:

        return jsonify({
            "error": "File uploaded, but AI analysis failed.",
            "details": str(error)
        }), 500


# ---------------------------------------------------------
# TEXT EVIDENCE + GEMINI ANALYSIS + DATABASE
# ---------------------------------------------------------

@app.route("/api/analyze-evidence", methods=["POST"])
def analyze_evidence():

    data = request.get_json()

    text = data.get("text")

    if not text:
        return jsonify({
            "error": "Evidence text is required"
        }), 400


    # Send text to Gemini
    analysis = analyze_text(text)


    # Optional information
    filename = data.get(
        "filename",
        "text-evidence"
    )

    evidence_type = data.get(
        "evidence_type",
        "text"
    )


    # Save AI analysis to database
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO evidence
        (filename, evidence_type, incident_date, category, severity, summary)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        filename,
        evidence_type,
        analysis.get("incident_date"),
        analysis.get("category"),
        analysis.get("severity"),
        analysis.get("summary")
    ))

    connection.commit()

    new_id = cursor.lastrowid

    connection.close()


    return jsonify({
        "message": "Evidence analyzed and saved successfully!",
        "id": new_id,
        "analysis": analysis
    }), 201


# ---------------------------------------------------------
# EVIDENCE GALLERY SUPPORT (additive endpoints)
#   GET    /api/evidence/<id>/file   view / download stored file
#   PATCH  /api/evidence/<id>        rename, categorize, edit details
#   DELETE /api/evidence/<id>        delete record (and file if unused)
#   POST   /api/evidence/file        upload video / audio / document
# ---------------------------------------------------------

VALID_SEVERITIES = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical"
}

FILE_TYPES = {
    "image": {"png", "jpg", "jpeg", "webp", "gif"},
    "video": {"mp4", "mov", "webm", "m4v"},
    "audio": {"mp3", "m4a", "wav", "ogg", "aac"},
    "document": {"pdf", "txt", "doc", "docx"}
}

MAX_UPLOAD_BYTES = 100 * 1024 * 1024

EVIDENCE_COLUMNS = """
    id, filename, evidence_type, incident_date, category,
    severity, summary, created_at, display_name, tags
"""


def split_tags(value):
    return [tag for tag in (value or "").split(",") if tag.strip()]


def normalize_tags(value):
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        return None
    tags = []
    for tag in value:
        tag = str(tag).replace(",", " ").strip()[:30]
        if tag and tag.lower() not in [t.lower() for t in tags]:
            tags.append(tag)
    return ",".join(tags[:10])


def clean_text(value, limit):
    if value is None:
        return ""
    return str(value).strip()[:limit]


def parse_date(value):
    value = clean_text(value, 10)
    if not value:
        return None
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Date must be in YYYY-MM-DD format")
    return value


def fetch_row(evidence_id):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        f"SELECT {EVIDENCE_COLUMNS} FROM evidence WHERE id = ?",
        (evidence_id,)
    )
    row = cursor.fetchone()
    connection.close()
    return row


def row_to_dict(row):
    return {
        "id": row[0],
        "filename": row[1],
        "evidence_type": row[2],
        "incident_date": row[3],
        "category": row[4],
        "severity": row[5],
        "summary": row[6],
        "created_at": row[7],
        "display_name": row[8],
        "tags": split_tags(row[9])
    }


def stored_file_path(filename):
    """Resolve a stored upload safely. Returns None if missing."""
    if not filename:
        return None
    name = secure_filename(filename)
    if not name:
        return None
    root = UPLOAD_FOLDER.resolve()
    path = (root / name).resolve()
    if path.parent != root or not path.is_file():
        return None
    return path


def file_kind(extension):
    for kind, extensions in FILE_TYPES.items():
        if extension in extensions:
            return kind
    return None


@app.route("/api/evidence/<int:evidence_id>/file", methods=["GET"])
def evidence_file(evidence_id):

    row = fetch_row(evidence_id)

    if row is None:
        return jsonify({"error": "Evidence not found"}), 404

    path = stored_file_path(row[1])

    if path is None:
        return jsonify({"error": "No stored file for this evidence"}), 404

    mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

    # Only render known-safe types inline; everything else downloads.
    inline_ok = (
        (mime_type.startswith("image/") and "svg" not in mime_type)
        or mime_type.startswith("video/")
        or mime_type.startswith("audio/")
        or mime_type == "application/pdf"
    )

    as_attachment = request.args.get("download") == "1" or not inline_ok

    download_name = row[8] or row[1] or path.name
    if not Path(download_name).suffix:
        download_name += path.suffix

    response = send_from_directory(
        UPLOAD_FOLDER,
        path.name,
        mimetype=mime_type,
        as_attachment=as_attachment,
        download_name=download_name
    )

    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"

    return response


@app.route("/api/evidence/<int:evidence_id>", methods=["PATCH"])
def update_evidence(evidence_id):

    data = request.get_json(silent=True) or {}

    if fetch_row(evidence_id) is None:
        return jsonify({"error": "Evidence not found"}), 404

    updates = {}

    try:

        if "display_name" in data:
            name = clean_text(data["display_name"], 255)
            if not name:
                raise ValueError("Name cannot be empty")
            updates["display_name"] = name

        if "category" in data:
            category = clean_text(data["category"], 60)
            if not category:
                raise ValueError("Category cannot be empty")
            updates["category"] = category

        if "severity" in data:
            severity = VALID_SEVERITIES.get(
                clean_text(data["severity"], 20).lower()
            )
            if severity is None:
                raise ValueError("Severity must be Low, Medium, High or Critical")
            updates["severity"] = severity

        if "summary" in data:
            updates["summary"] = clean_text(data["summary"], 2000) or None

        if "incident_date" in data:
            updates["incident_date"] = parse_date(data["incident_date"])

        if "tags" in data:
            tags = normalize_tags(data["tags"])
            if tags is None:
                raise ValueError("Tags must be a list or comma-separated text")
            updates["tags"] = tags or None

    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    if not updates:
        return jsonify({"error": "Nothing to update"}), 400

    # Column names come from the fixed keys above, never from user input.
    assignments = ", ".join(f"{column} = ?" for column in updates)

    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        f"UPDATE evidence SET {assignments} WHERE id = ?",
        (*updates.values(), evidence_id)
    )
    connection.commit()
    connection.close()

    return jsonify(row_to_dict(fetch_row(evidence_id)))


@app.route("/api/evidence/<int:evidence_id>", methods=["DELETE"])
def delete_evidence(evidence_id):

    row = fetch_row(evidence_id)

    if row is None:
        return jsonify({"error": "Evidence not found"}), 404

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))

    # Uploads with the same name share one file on disk, so only remove
    # the file once no other record points at it.
    cursor.execute(
        "SELECT COUNT(*) FROM evidence WHERE filename = ?",
        (row[1],)
    )
    still_used = cursor.fetchone()[0] > 0

    connection.commit()
    connection.close()

    if not still_used:
        path = stored_file_path(row[1])
        if path is not None:
            try:
                path.unlink()
            except OSError:
                pass

    return jsonify({"message": "Evidence deleted", "id": evidence_id})


@app.route("/api/evidence/file", methods=["POST"])
def upload_evidence_file():

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if request.content_length and request.content_length > MAX_UPLOAD_BYTES:
        return jsonify({"error": "File is too large (100 MB max)"}), 413

    original_name = clean_text(Path(file.filename).name, 255)
    extension = Path(original_name).suffix.lower().lstrip(".")
    kind = file_kind(extension)

    if kind is None:
        return jsonify({"error": "This file type is not supported"}), 400

    try:
        severity_input = clean_text(request.form.get("severity"), 20)
        severity = VALID_SEVERITIES.get(severity_input.lower(), "Medium")
        incident_date = parse_date(request.form.get("incident_date"))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    category = clean_text(request.form.get("category"), 60) or "Other"
    summary = clean_text(request.form.get("summary"), 2000) or None
    tags = normalize_tags(request.form.get("tags", "")) or None

    # Unique stored name so uploads never overwrite each other
    safe = secure_filename(original_name) or f"file.{extension}"
    stored_name = f"{uuid.uuid4().hex[:12]}_{safe}"

    file.save(UPLOAD_FOLDER / stored_name)

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO evidence
        (filename, evidence_type, incident_date, category, severity,
         summary, display_name, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        stored_name,
        kind,
        incident_date,
        category,
        severity,
        summary,
        original_name,
        tags
    ))

    connection.commit()
    new_id = cursor.lastrowid
    connection.close()

    return jsonify({
        "message": "Evidence saved successfully!",
        "id": new_id
    }), 201


# ---------------------------------------------------------
# START FLASK
# ---------------------------------------------------------

# Production (Render) runs this app with Gunicorn - see render.yaml - and never
# reaches this block. It is only for `python backend/app.py` during local
# development. Debug mode is OFF unless you explicitly set SAFEVAULT_DEBUG=1.
if __name__ == "__main__":
    _port = int(os.environ.get("PORT", "5000"))
    _host = "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"
    app.run(
        host=_host,
        port=_port,
        debug=os.environ.get("SAFEVAULT_DEBUG") == "1",
    )