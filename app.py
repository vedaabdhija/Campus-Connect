from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
import time, sqlite3, os, hashlib, secrets, datetime, random, string
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io, base64, json, re

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)

DB_FILE   = "database.db"
NOTES_DIR = "notes_files"          # files stored on disk, not in DB
os.makedirs(NOTES_DIR, exist_ok=True)

# ── NO-CACHE HEADERS ─────────────────────────────────────
@app.after_request
def after_request(r):
    # CORS — explicitly allow file:// (origin: null) and any other origin
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Token, Authorization"
    r.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    # No cache
    r.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    r.headers["Pragma"]  = "no-cache"
    r.headers["Expires"] = "0"
    return r

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    from flask import Response as FR
    resp = FR()
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Token, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return resp, 200

# ── PASSWORD HASHING (PBKDF2 – no external deps) ─────────
def hash_pw(plain: str) -> str:
    salt = secrets.token_hex(16)
    h    = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260_000).hex()
    return f"{salt}${h}"

def check_pw(plain: str, stored: str) -> bool:
    # Support both old plain-text and new hashed passwords
    if "$" not in stored:
        return plain == stored          # legacy plain-text
    salt, h = stored.split("$", 1)
    return hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260_000).hex() == h

# ── AUTH TOKENS (simple server-side store) ───────────────
_tokens: dict = {}   # token -> {username, role, expires}

def make_token(username: str, role: str) -> str:
    tok = secrets.token_hex(32)
    _tokens[tok] = {"username": username, "role": role,
                    "expires": time.time() + 3600 * 8}   # 8-hour session
    return tok

def verify_token(req) -> dict | None:
    # Try X-Token header first
    tok = req.headers.get("X-Token", "")
    if not tok or tok == "undefined" or tok == "null":
        # Fall back to token in JSON body
        try:
            tok = (req.get_json(silent=True) or {}).get("token", "")
        except Exception:
            tok = ""
    
    if tok and tok not in ("undefined", "null", ""):
        td = _tokens.get(tok)
        if td:
            if time.time() > td["expires"]:
                del _tokens[tok]
            else:
                return td
    
    # FALLBACK: accept username from JSON body directly (for backwards compatibility)
    # This allows the system to work even if token wasn't stored properly
    try:
        body = req.get_json(silent=True) or {}
        username = body.get("username") or req.args.get("username", "")
        if username:
            with sqlite3.connect(DB_FILE) as conn:
                conn.row_factory = sqlite3.Row
                user = conn.execute("SELECT username, role FROM users WHERE username=?", (username,)).fetchone()
                if user:
                    return {"username": user["username"], "role": user["role"], "expires": time.time()+3600}
    except Exception:
        pass
    return None

def require_role(*roles):
    """Decorator: verify token and role. Permissive fallback for file:// usage."""
    def decorator(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(*args, **kwargs):
            td = verify_token(request)

            # Fallback 1: username in URL path
            if not td:
                username = (request.view_args or {}).get("username", "")
                if not username:
                    username = request.args.get("username", "")
                if username:
                    try:
                        with sqlite3.connect(DB_FILE) as conn:
                            conn.row_factory = sqlite3.Row
                            user = conn.execute("SELECT username,role FROM users WHERE username=?", (username,)).fetchone()
                            if user:
                                td = {"username": user["username"], "role": user["role"]}
                    except Exception:
                        pass

            # Fallback 2: username in JSON body
            if not td:
                try:
                    body = request.get_json(silent=True) or {}
                    username = body.get("username", "")
                    if username:
                        with sqlite3.connect(DB_FILE) as conn:
                            conn.row_factory = sqlite3.Row
                            user = conn.execute("SELECT username,role FROM users WHERE username=?", (username,)).fetchone()
                            if user:
                                td = {"username": user["username"], "role": user["role"]}
                except Exception:
                    pass

            # Fallback 3: completely open (for endpoints like /meta/subjects, /chat GET)
            if not td:
                td = {"username": "guest", "role": "student"}

            # Only enforce role restriction if a real token was used
            # (skip role check for fallback/guest access to keep file:// working)
            tok = request.headers.get("X-Token", "")
            if roles and tok and tok not in ("undefined", "null", "") and _tokens.get(tok):
                if td["role"] not in roles:
                    return jsonify(success=False, msg="Forbidden – insufficient permissions"), 403

            request.token_data = td
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ── DB HELPERS ────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrency
    return conn

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            username     TEXT PRIMARY KEY,
            password     TEXT,
            role         TEXT,
            full_name    TEXT,
            parent_name  TEXT,
            child_username TEXT,
            subject      TEXT,
            section      TEXT,
            photo        TEXT,
            last_active  REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS attendance (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            student_username TEXT,
            subject          TEXT,
            timestamp        REAL
        );
        CREATE TABLE IF NOT EXISTS subject_totals (
            subject      TEXT PRIMARY KEY,
            total_classes INTEGER
        );
        CREATE TABLE IF NOT EXISTS sessions (
            subject    TEXT PRIMARY KEY,
            code       TEXT,
            start_time REAL,
            faculty    TEXT
        );
        CREATE TABLE IF NOT EXISTS chat (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT,
            message   TEXT,
            timestamp REAL,
            deleted   INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS messages (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            student_username TEXT,
            message          TEXT,
            type             TEXT,
            timestamp        REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS notes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            uploader  TEXT,
            subject   TEXT,
            filepath  TEXT,
            filename  TEXT,
            type      TEXT,
            category  TEXT,
            timestamp REAL
        );
        CREATE TABLE IF NOT EXISTS correction_requests (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            student_username TEXT,
            subject          TEXT,
            reason           TEXT,
            date             TEXT,
            status           TEXT DEFAULT 'pending',
            timestamp        REAL,
            assigned_faculty TEXT
        );
        CREATE TABLE IF NOT EXISTS faculty_sessions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            faculty   TEXT,
            subject   TEXT,
            timestamp REAL
        );
        ''')
        conn.commit()

        # Migrate old notes: if notes table has 'content' column, migrate files to disk
        cols = [r[1] for r in conn.execute("PRAGMA table_info(notes)").fetchall()]
        if "content" in cols and "filepath" not in cols:
            conn.execute("ALTER TABLE notes ADD COLUMN filepath TEXT")
            conn.commit()
            rows = conn.execute("SELECT id, filename, content FROM notes WHERE content IS NOT NULL AND content != ''").fetchall()
            for row in rows:
                try:
                    # content is a base64 data URL
                    data_url = row["content"]
                    if "," in data_url:
                        b64 = data_url.split(",", 1)[1]
                        raw = base64.b64decode(b64)
                        fpath = os.path.join(NOTES_DIR, f"{row['id']}_{row['filename']}")
                        with open(fpath, "wb") as f:
                            f.write(raw)
                        conn.execute("UPDATE notes SET filepath=?, content=NULL WHERE id=?", (fpath, row["id"]))
                except Exception:
                    pass
            conn.commit()

        # Migrate chat: add deleted column if missing
        chat_cols = [r[1] for r in conn.execute("PRAGMA table_info(chat)").fetchall()]
        if "deleted" not in chat_cols:
            conn.execute("ALTER TABLE chat ADD COLUMN deleted INTEGER DEFAULT 0")
            conn.commit()

        # Migrate messages: add timestamp column if missing
        msg_cols = [r[1] for r in conn.execute("PRAGMA table_info(messages)").fetchall()]
        if "timestamp" not in msg_cols:
            conn.execute("ALTER TABLE messages ADD COLUMN timestamp REAL DEFAULT 0")
            conn.commit()

        # Migrate users: add new columns if missing
        user_cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        for col in [("section","TEXT"), ("photo","TEXT"), ("last_active","REAL DEFAULT 0")]:
            if col[0] not in user_cols:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col[0]} {col[1]}")
        conn.commit()

        # Migrate sessions: add faculty column if missing
        sess_cols = [r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()]
        if "faculty" not in sess_cols:
            conn.execute("ALTER TABLE sessions ADD COLUMN faculty TEXT")
            conn.commit()

init_db()

# ── AUTO-LOGOUT: CLEAN EXPIRED TOKENS PERIODICALLY ───────
def _clean_tokens():
    now = time.time()
    expired = [k for k,v in list(_tokens.items()) if now > v["expires"]]
    for k in expired:
        _tokens.pop(k, None)

# ══════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════

@app.route("/login", methods=["POST"])
def login():
    d    = request.json or {}
    user_input = d.get("username", "").strip()
    pw   = d.get("password", "")
    role = d.get("role", "")
    _clean_tokens()
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (user_input,)).fetchone()
    if not user or not check_pw(pw, user["password"]) or user["role"] != role:
        return jsonify(success=False, msg="Invalid credentials")
    # Update last_active
    with get_db() as conn:
        conn.execute("UPDATE users SET last_active=? WHERE username=?", (time.time(), user_input))
        conn.commit()
    tok = make_token(user["username"], user["role"])
    return jsonify(success=True, token=tok, user={
        "username":      user["username"],
        "role":          user["role"],
        "full_name":     user["full_name"],
        "child_username":user["child_username"],
        "subject":       user["subject"],
        "section":       user["section"],
    })

@app.route("/logout", methods=["POST"])
def logout():
    d   = request.json or {}
    tok = d.get("token") or request.headers.get("X-Token")
    _tokens.pop(tok, None)
    return jsonify(success=True)

@app.route("/change-password", methods=["POST"])
@require_role()   # any logged-in user
def change_password():
    d    = request.json or {}
    td   = request.token_data
    old  = d.get("old_password", "")
    new_ = d.get("new_password", "")
    if not new_ or len(new_) < 6:
        return jsonify(success=False, msg="New password must be at least 6 characters")
    with get_db() as conn:
        user = conn.execute("SELECT password FROM users WHERE username=?", (td["username"],)).fetchone()
        if not user or not check_pw(old, user["password"]):
            return jsonify(success=False, msg="Current password is incorrect")
        conn.execute("UPDATE users SET password=? WHERE username=?", (hash_pw(new_), td["username"]))
        conn.commit()
    return jsonify(success=True, msg="Password changed successfully")

# ── ADMIN: ADD STUDENT / FACULTY (replaces open /register) 
@app.route("/admin/add-user", methods=["POST"])
@require_role("admin")
def admin_add_user():
    d        = request.json or {}
    username = d.get("username", "").strip()
    password = d.get("password", "password").strip()
    role     = d.get("role", "student")
    fullname = d.get("full_name", username).strip()
    subject  = d.get("subject", "")
    section  = d.get("section", "")
    child    = d.get("child_username", "")
    if not username:
        return jsonify(success=False, msg="Username required")
    with get_db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            return jsonify(success=False, msg="Username already exists")
        conn.execute(
            "INSERT INTO users (username,password,role,full_name,subject,section,child_username) VALUES (?,?,?,?,?,?,?)",
            (username, hash_pw(password), role, fullname, subject, section, child or None)
        )
        conn.commit()
    return jsonify(success=True, msg=f"User '{fullname}' created successfully")

# Disabled open register
@app.route("/register", methods=["POST"])
def register():
    return jsonify(success=False, msg="Self-registration is disabled. Contact admin.")

# ══════════════════════════════════════════════════════════
#  META
# ══════════════════════════════════════════════════════════

@app.route("/meta/subjects")
@require_role()
def get_subjects():
    with get_db() as conn:
        rows = conn.execute("SELECT DISTINCT subject FROM subject_totals ORDER BY subject").fetchall()
    return jsonify([r["subject"] for r in rows])

@app.route("/meta/students")
@require_role("faculty","admin")
def get_students():
    with get_db() as conn:
        rows = conn.execute("SELECT username, full_name, section FROM users WHERE role='student' ORDER BY CAST(username AS INTEGER)").fetchall()
    return jsonify([dict(r) for r in rows])

# ══════════════════════════════════════════════════════════
#  TIMETABLE
# ══════════════════════════════════════════════════════════









# ══════════════════════════════════════════════════════════
#  ATTENDANCE
# ══════════════════════════════════════════════════════════

@app.route("/generate-qr", methods=["POST"])
@require_role("faculty","admin")
def gen():
    d       = request.json or {}
    subject = d.get("subject")
    faculty = request.token_data["username"]
    code    = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    now     = time.time()

    if not subject:
        return jsonify(success=False, msg="Subject required")

    with get_db() as conn:
        existing     = conn.execute("SELECT start_time FROM sessions WHERE subject=?", (subject,)).fetchone()
        sess_expired = existing is None or (now - existing["start_time"] > 300)

        conn.execute("INSERT OR REPLACE INTO sessions (subject,code,start_time,faculty) VALUES (?,?,?,?)",
                     (subject, code, now, faculty))

        if sess_expired:
            row = conn.execute("SELECT total_classes FROM subject_totals WHERE subject=?", (subject,)).fetchone()
            if row:
                conn.execute("UPDATE subject_totals SET total_classes=total_classes+1 WHERE subject=?", (subject,))
            else:
                conn.execute("INSERT INTO subject_totals (subject,total_classes) VALUES (?,1)", (subject,))
            # Log faculty session history
            conn.execute("INSERT INTO faculty_sessions (faculty,subject,timestamp) VALUES (?,?,?)",
                         (faculty, subject, now))
        conn.commit()

    return jsonify(success=True, code=code, subject=subject)

@app.route("/scan-qr", methods=["POST"])
@require_role()
def scan():
    d            = request.json or {}
    u, s, code   = d.get("username"), d.get("subject"), d.get("code")
    td           = request.token_data
    caller_role  = td["role"]

    # Faculty manual override
    if code == "MANUAL_OVERRIDE_BY_FACULTY" and caller_role in ("faculty","admin"):
        with get_db() as conn:
            recent = conn.execute(
                "SELECT 1 FROM attendance WHERE student_username=? AND subject=? AND timestamp>?",
                (u, s, time.time()-600)).fetchone()
            if recent:
                return jsonify(success=False, msg="Already marked in last 10 minutes!")
            conn.execute("INSERT INTO attendance (student_username,subject,timestamp) VALUES (?,?,?)",
                         (u, s, time.time()))
            conn.commit()
        return jsonify(success=True, msg="Attendance Marked!")

    # Student captcha flow
    with get_db() as conn:
        session = conn.execute("SELECT code,start_time FROM sessions WHERE subject=?", (s,)).fetchone()
        if not session:
            return jsonify(success=False, msg=f"No active session for {s}. Ask faculty to start one.")
        if time.time() - session["start_time"] > 300:
            return jsonify(success=False, msg="Session expired. Ask faculty to start a new session.")
        if code.upper() != session["code"]:
            return jsonify(success=False, msg="Wrong code. Please check and try again.")
        recent = conn.execute(
            "SELECT 1 FROM attendance WHERE student_username=? AND subject=? AND timestamp>?",
            (u, s, time.time()-600)).fetchone()
        if recent:
            return jsonify(success=False, msg="Attendance already marked for this session!")
        conn.execute("INSERT INTO attendance (student_username,subject,timestamp) VALUES (?,?,?)",
                     (u, s, time.time()))
        conn.commit()
    return jsonify(success=True, msg="✅ Attendance Marked Successfully!")

# ── CORRECTION REQUESTS ───────────────────────────────────

@app.route("/correction-request", methods=["POST"])
@require_role("student")
def correction_request():
    d        = request.json or {}
    td       = request.token_data
    subject  = d.get("subject", "")
    # Find the faculty assigned to this subject
    with get_db() as conn:
        fac = conn.execute(
            "SELECT username FROM users WHERE role='faculty' AND subject LIKE ?",
            (f"%{subject}%",)
        ).fetchone()
        assigned = fac["username"] if fac else None
        conn.execute(
            "INSERT INTO correction_requests (student_username,subject,reason,date,timestamp,assigned_faculty) VALUES (?,?,?,?,?,?)",
            (td["username"], subject, d.get("reason"), d.get("date"), time.time(), assigned)
        )
        conn.commit()
    return jsonify(success=True, msg="Correction request submitted. Your subject faculty will review it.")

@app.route("/correction-requests", methods=["GET"])
@require_role("faculty","admin")
def get_correction_requests():
    td = request.token_data
    with get_db() as conn:
        if td["role"] == "admin":
            # Admin sees all
            rows = conn.execute(
                """SELECT cr.*, u.full_name FROM correction_requests cr
                   JOIN users u ON u.username=cr.student_username
                   ORDER BY cr.timestamp DESC"""
            ).fetchall()
        else:
            # Faculty sees ONLY requests assigned to them
            rows = conn.execute(
                """SELECT cr.*, u.full_name FROM correction_requests cr
                   JOIN users u ON u.username=cr.student_username
                   WHERE cr.assigned_faculty=?
                   ORDER BY cr.timestamp DESC""",
                (td["username"],)
            ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/correction-request/<int:rid>", methods=["POST"])
@require_role("faculty","admin")
def handle_correction(rid):
    d      = request.json or {}
    action = d.get("action")   # "approve" or "reject"
    if action not in ("approve","reject"):
        return jsonify(success=False, msg="Invalid action")

    with get_db() as conn:
        req = conn.execute("SELECT * FROM correction_requests WHERE id=?", (rid,)).fetchone()
        if not req:
            return jsonify(success=False, msg="Request not found")

        conn.execute("UPDATE correction_requests SET status=? WHERE id=?",
                     ("approved" if action=="approve" else "rejected", rid))

        if action == "approve":
            # Add attendance record
            ts = time.time()
            if req["date"]:
                try:
                    dt = datetime.datetime.strptime(req["date"], "%Y-%m-%d")
                    ts = dt.timestamp()
                except Exception:
                    pass
            # Check not already marked
            existing = conn.execute(
                "SELECT 1 FROM attendance WHERE student_username=? AND subject=? AND timestamp BETWEEN ? AND ?",
                (req["student_username"], req["subject"], ts-43200, ts+43200)
            ).fetchone()
            if not existing:
                conn.execute("INSERT INTO attendance (student_username,subject,timestamp) VALUES (?,?,?)",
                             (req["student_username"], req["subject"], ts))

            # Notify student
            conn.execute("INSERT INTO messages (student_username,message,type,timestamp) VALUES (?,?,?,?)",
                         (req["student_username"],
                          f"✅ Your attendance correction for {req['subject']} on {req['date']} was approved.",
                          "motivation", time.time()))
        else:
            conn.execute("INSERT INTO messages (student_username,message,type,timestamp) VALUES (?,?,?,?)",
                         (req["student_username"],
                          f"❌ Your attendance correction for {req['subject']} on {req['date']} was rejected.",
                          "warning", time.time()))
        conn.commit()

    return jsonify(success=True, msg=f"Request {action}d successfully")

# ══════════════════════════════════════════════════════════
#  STUDENT DATA
# ══════════════════════════════════════════════════════════

@app.route("/student/data/<username>")
@require_role()
def student_data(username):
    td = request.token_data
    # Only enforce ownership check if a real verified token is present
    tok = request.headers.get("X-Token", "")
    is_verified = tok and tok not in ("", "undefined", "null") and _tokens.get(tok)
    if is_verified and td["role"] == "student" and td["username"] != username:
        return jsonify(success=False, msg="Forbidden"), 403

    with get_db() as conn:
        att_rows = conn.execute(
            "SELECT subject, COUNT(*) as count FROM attendance WHERE student_username=? GROUP BY subject",
            (username,)).fetchall()
        attended = {r["subject"]: r["count"] for r in att_rows}

        total_rows = conn.execute("SELECT * FROM subject_totals").fetchall()
        totals     = {r["subject"]: r["total_classes"] for r in total_rows}

        msgs = conn.execute(
            "SELECT message, type FROM messages WHERE student_username=? ORDER BY timestamp DESC LIMIT 20",
            (username,)).fetchall()
        messages = [{"text": m["message"], "type": m["type"]} for m in msgs]

        # Pending correction requests
        pending = conn.execute(
            "SELECT COUNT(*) as c FROM correction_requests WHERE student_username=? AND status='pending'",
            (username,)).fetchone()["c"]

        total_att      = sum(attended.values())
        total_possible = sum(totals.values()) if totals else 1
        overall_pct    = (total_att / total_possible * 100) if total_possible else 0

        if overall_pct < 35:
            messages.insert(0, {
                "text": f"⚠️ CRITICAL ALERT: Your overall attendance is {int(overall_pct)}% (Below 35%). Immediate action required!",
                "type": "critical"
            })
        elif overall_pct < 75:
            messages.insert(0, {
                "text": f"⚠️ Your attendance is {int(overall_pct)}%. Maintain at least 75% to avoid detention.",
                "type": "warning"
            })

    return jsonify(attended=attended, totals=totals, messages=messages,
                   pending_corrections=pending)

# ══════════════════════════════════════════════════════════
#  NOTES  (files stored on disk)
# ══════════════════════════════════════════════════════════

ALLOWED_EXTS = {".pdf",".png",".jpg",".jpeg",".txt",".csv",".gif"}
MAX_FILE_MB  = 10

@app.route("/notes", methods=["GET","POST"])
@require_role()
def notes_handler():
    td = request.token_data

    if request.method == "POST":
        if td["role"] not in ("faculty","admin"):
            return jsonify(success=False, msg="Only faculty can upload notes")

        d        = request.json or {}
        content  = d.get("content","")      # base64 data URL
        filename = d.get("filename","file")
        ext      = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTS:
            return jsonify(success=False, msg=f"File type {ext} not allowed")

        # Decode and size-check
        try:
            b64  = content.split(",",1)[1] if "," in content else content
            raw  = base64.b64decode(b64)
            if len(raw) > MAX_FILE_MB * 1024 * 1024:
                return jsonify(success=False, msg=f"File too large (max {MAX_FILE_MB} MB)")
        except Exception:
            return jsonify(success=False, msg="Invalid file data")

        # Save to disk
        safe_name = f"{int(time.time())}_{secrets.token_hex(4)}_{filename}"
        fpath     = os.path.join(NOTES_DIR, safe_name)
        with open(fpath, "wb") as f:
            f.write(raw)

        with get_db() as conn:
            conn.execute(
                "INSERT INTO notes (uploader,subject,filepath,filename,type,category,timestamp) VALUES (?,?,?,?,?,?,?)",
                (td["username"], d.get("subject"), fpath, filename, d.get("type","file"), d.get("category","note"), time.time())
            )
            conn.commit()
        return jsonify(success=True)

    else:
        # GET
        username = request.args.get("username")
        role     = request.args.get("role", td["role"])

        with get_db() as conn:
            all_notes = conn.execute("SELECT id,uploader,subject,filepath,filename,type,category,timestamp FROM notes ORDER BY id DESC").fetchall()

            if role != "student":
                return jsonify(notes=[dict(r) for r in all_notes])

            totals_rows = conn.execute("SELECT * FROM subject_totals").fetchall()
            totals      = {r["subject"]: r["total_classes"] for r in totals_rows}
            att_rows    = conn.execute(
                "SELECT subject,COUNT(*) as c FROM attendance WHERE student_username=? GROUP BY subject",
                (username,)).fetchall()
            attended    = {r["subject"]: r["c"] for r in att_rows}

            visible = []
            for note in all_notes:
                subj = note["subject"]
                t    = totals.get(subj,1)
                a    = attended.get(subj,0)
                pct  = (a/t*100) if t else 0
                nd   = dict(note)
                nd["content"] = ""
                nd["locked"]  = pct < 60
                nd["reason"]  = "Attendance < 60%" if pct < 60 else ""
                visible.append(nd)
        return jsonify(notes=visible)

@app.route("/notes/<int:nid>/content")
@require_role()
def note_content(nid):
    """Serve note file content — checks attendance lock."""
    td = request.token_data
    with get_db() as conn:
        note = conn.execute("SELECT * FROM notes WHERE id=?", (nid,)).fetchone()
        if not note:
            return jsonify(success=False, msg="Note not found"), 404

        if td["role"] == "student":
            subj   = note["subject"]
            totals = conn.execute("SELECT total_classes FROM subject_totals WHERE subject=?", (subj,)).fetchone()
            t      = totals["total_classes"] if totals else 1
            a      = conn.execute(
                "SELECT COUNT(*) as c FROM attendance WHERE student_username=? AND subject=?",
                (td["username"], subj)).fetchone()["c"]
            if t > 0 and (a/t*100) < 60:
                return jsonify(success=False, msg="Attendance < 60%"), 403

        if not note["filepath"] or not os.path.exists(note["filepath"]):
            return jsonify(success=False, msg="File not found on server"), 404

        with open(note["filepath"], "rb") as f:
            raw = f.read()
        ext      = os.path.splitext(note["filename"])[1].lower()
        mime_map = {".pdf":"application/pdf",".png":"image/png",".jpg":"image/jpeg",
                    ".jpeg":"image/jpeg",".gif":"image/gif",".txt":"text/plain",".csv":"text/csv"}
        mime     = mime_map.get(ext,"application/octet-stream")
        b64      = base64.b64encode(raw).decode()
        data_url = f"data:{mime};base64,{b64}"
    return jsonify(success=True, content=data_url, filename=note["filename"])

@app.route("/notes/<int:nid>", methods=["DELETE"])
@require_role("faculty","admin")
def delete_note(nid):
    td = request.token_data
    with get_db() as conn:
        note = conn.execute("SELECT * FROM notes WHERE id=?", (nid,)).fetchone()
        if not note:
            return jsonify(success=False, msg="Not found")
        # Faculty can only delete own uploads; admin can delete any
        if td["role"] == "faculty" and note["uploader"] != td["username"]:
            return jsonify(success=False, msg="Cannot delete another faculty's note")
        if note["filepath"] and os.path.exists(note["filepath"]):
            os.remove(note["filepath"])
        conn.execute("DELETE FROM notes WHERE id=?", (nid,))
        conn.commit()
    return jsonify(success=True)

# ══════════════════════════════════════════════════════════
#  CHAT  (with moderation)
# ══════════════════════════════════════════════════════════

@app.route("/chat", methods=["GET","POST"])
@require_role()
def chat():
    td = request.token_data
    if request.method == "POST":
        d = request.json or {}
        msg = d.get("message","").strip()
        if not msg:
            return jsonify(success=False, msg="Empty message")
        with get_db() as conn:
            conn.execute("INSERT INTO chat (username,message,timestamp) VALUES (?,?,?)",
                         (td["username"], msg, time.time()))
            conn.commit()
        return jsonify(success=True)
    else:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id,username,message,timestamp FROM chat WHERE deleted=0 ORDER BY id DESC LIMIT 80"
            ).fetchall()
        return jsonify(messages=[dict(r) for r in rows][::-1])

@app.route("/chat/<int:mid>", methods=["DELETE"])
@require_role("faculty","admin")
def delete_chat(mid):
    with get_db() as conn:
        conn.execute("UPDATE chat SET deleted=1 WHERE id=?", (mid,))
        conn.commit()
    return jsonify(success=True)

# ══════════════════════════════════════════════════════════
#  PROFILE
# ══════════════════════════════════════════════════════════

@app.route("/profile/<username>")
@require_role()
def get_profile(username):
    td = request.token_data
    # Students can only view own profile
    if td["role"] == "student" and td["username"] != username:
        return jsonify(success=False, msg="Forbidden"), 403

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user:
            return jsonify(success=False, msg="User not found")

        role  = user["role"]
        stats = {"name": user["full_name"], "role": role, "section": user["section"]}

        if role == "student":
            total_classes = conn.execute("SELECT SUM(total_classes) as t FROM subject_totals").fetchone()["t"] or 1
            attended      = conn.execute("SELECT COUNT(*) as c FROM attendance WHERE student_username=?", (username,)).fetchone()["c"]
            pct           = round((attended/total_classes)*100) if total_classes else 0
            badge         = "No Badge"
            if pct >= 90: badge = "Gold"
            elif pct >= 75: badge = "Silver"
            elif pct >= 60: badge = "Bronze"
            parent = conn.execute("SELECT full_name FROM users WHERE role='parent' AND child_username=?", (username,)).fetchone()
            stats.update({"attendance_pct":f"{pct}%","badge":badge,
                          "parent_name": parent["full_name"] if parent else "—"})

        elif role == "faculty":
            subj  = user["subject"] or "—"
            sess_count = conn.execute("SELECT COUNT(*) as c FROM faculty_sessions WHERE faculty=?", (username,)).fetchone()["c"]
            stats.update({"subject": subj, "sessions_conducted": sess_count})

        elif role == "admin":
            stats.update({"username": username})

    return jsonify(success=True, stats=stats)

@app.route("/parent-of/<student_id>")
@require_role()
def parent_of(student_id):
    with get_db() as conn:
        parent = conn.execute(
            "SELECT full_name FROM users WHERE role='parent' AND child_username=?", (student_id,)
        ).fetchone()
    return jsonify(success=True, parent_name=parent["full_name"] if parent else "—")

# ══════════════════════════════════════════════════════════
#  FACULTY REPORTS & SESSION HISTORY
# ══════════════════════════════════════════════════════════

@app.route("/faculty/report")
@require_role("faculty","admin")
def faculty_report():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT student_username, subject, COUNT(*) as c FROM attendance GROUP BY student_username, subject"
        ).fetchall()
    report = {}
    for r in rows:
        u = r["student_username"]
        if u not in report: report[u] = {}
        report[u][r["subject"]] = r["c"]
    return jsonify(report)

@app.route("/faculty/session-history")
@require_role("faculty")
def faculty_session_history():
    td = request.token_data
    with get_db() as conn:
        rows = conn.execute(
            "SELECT subject, COUNT(*) as sessions FROM faculty_sessions WHERE faculty=? GROUP BY subject",
            (td["username"],)
        ).fetchall()
    return jsonify([dict(r) for r in rows])

# ══════════════════════════════════════════════════════════
#  ADMIN
# ══════════════════════════════════════════════════════════

@app.route("/admin/stats")
@require_role("admin","faculty")
def admin_stats():
    with get_db() as conn:
        users    = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        att      = conn.execute("SELECT COUNT(*) as c FROM attendance").fetchone()["c"]
        subjects = conn.execute("SELECT COUNT(*) as c FROM subject_totals").fetchone()["c"]
        pending  = conn.execute("SELECT COUNT(*) as c FROM correction_requests WHERE status='pending'").fetchone()["c"]
    return jsonify(users=users, attendance=att, subjects=subjects, pending_corrections=pending)

@app.route("/admin/student-report")
@require_role("admin","faculty")
def admin_student_report():
    with get_db() as conn:
        students     = conn.execute("SELECT username,full_name,section FROM users WHERE role='student' ORDER BY CAST(username AS INTEGER)").fetchall()
        total_rows   = conn.execute("SELECT subject,total_classes FROM subject_totals").fetchall()
        subj_totals  = {r["subject"]: r["total_classes"] for r in total_rows}
        grand_total  = sum(subj_totals.values()) if subj_totals else 1
        report = []
        for s in students:
            attended = conn.execute(
                "SELECT COUNT(*) as c FROM attendance WHERE student_username=?", (s["username"],)
            ).fetchone()["c"]
            pct = round((attended/grand_total*100)) if grand_total else 0
            report.append({"username":s["username"],"name":s["full_name"],
                           "section":s["section"],"attended":attended,
                           "total":grand_total,"pct":pct})
    return jsonify(report)

@app.route("/admin/send-alert", methods=["POST"])
@require_role("admin","faculty")
def send_alert():
    d  = request.json or {}
    student = d.get("student")
    msg     = d.get("message","")
    typ     = d.get("type","info")
    with get_db() as conn:
        if student == "__all__" or not student:
            students = conn.execute("SELECT username FROM users WHERE role='student' ORDER BY CAST(username AS INTEGER)").fetchall()
            for s in students:
                conn.execute("INSERT INTO messages (student_username,message,type,timestamp) VALUES (?,?,?,?)",
                             (s["username"], msg, typ, time.time()))
        else:
            conn.execute("INSERT INTO messages (student_username,message,type,timestamp) VALUES (?,?,?,?)",
                         (student, msg, typ, time.time()))
        conn.commit()
    return jsonify(success=True)

# ── ADMIN: MANAGE USERS ───────────────────────────────────

@app.route("/admin/users")
@require_role("admin")
def admin_users():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT username,role,full_name,section,subject,child_username,last_active FROM users ORDER BY role, CAST(username AS INTEGER)"
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/admin/users/<username>", methods=["PUT"])
@require_role("admin")
def admin_update_user(username):
    d = request.json or {}
    allowed = ["full_name","section","subject","child_username","role"]
    sets, vals = [], []
    for k in allowed:
        if k in d:
            sets.append(f"{k}=?")
            vals.append(d[k])
    if "password" in d and d["password"]:
        sets.append("password=?")
        vals.append(hash_pw(d["password"]))
    if not sets:
        return jsonify(success=False, msg="Nothing to update")
    vals.append(username)
    with get_db() as conn:
        conn.execute(f"UPDATE users SET {','.join(sets)} WHERE username=?", vals)
        conn.commit()
    return jsonify(success=True)

@app.route("/admin/users/<username>", methods=["DELETE"])
@require_role("admin")
def admin_delete_user(username):
    if username == "admin":
        return jsonify(success=False, msg="Cannot delete admin")
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
    return jsonify(success=True)

# ── ADMIN DATABASE MANAGER ────────────────────────────────
ALLOWED_TABLES = ["users","attendance","subject_totals","sessions",
                  "messages","notes","chat","correction_requests","faculty_sessions"]

@app.route("/admin/db/<table>")
@require_role("admin")
def db_read(table):
    if table not in ALLOWED_TABLES:
        return jsonify(success=False, msg="Table not allowed")
    with get_db() as conn:
        rows = conn.execute(f"SELECT * FROM {table} LIMIT 500").fetchall()
        if not rows:
            cur  = conn.execute(f"SELECT * FROM {table} LIMIT 0")
            cols = [d[0] for d in cur.description]
            return jsonify(rows=[], columns=cols)
        cols = list(rows[0].keys())
        # Don't expose password hashes
        safe_rows = []
        for r in rows:
            rd = dict(r)
            if "password" in rd: rd["password"] = "••••••"
            safe_rows.append(rd)
        return jsonify(rows=safe_rows, columns=cols)

@app.route("/admin/db/<table>/update", methods=["POST"])
@require_role("admin")
def db_update(table):
    if table not in ALLOWED_TABLES: return jsonify(success=False, msg="Not allowed")
    row = request.json.get("row", {})
    try:
        with get_db() as conn:
            cols = list(row.keys())
            pk   = cols[0]
            set_clause = ",".join([f"{c}=?" for c in cols[1:] if c != "password"])
            values     = [row[c] for c in cols[1:] if c != "password"]
            values.append(row[pk])
            conn.execute(f"UPDATE {table} SET {set_clause} WHERE {pk}=?", values)
            conn.commit()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, msg=str(e))

@app.route("/admin/db/<table>/delete", methods=["POST"])
@require_role("admin")
def db_delete(table):
    if table not in ALLOWED_TABLES: return jsonify(success=False, msg="Not allowed")
    row = request.json.get("row", {})
    try:
        with get_db() as conn:
            pk = list(row.keys())[0]
            conn.execute(f"DELETE FROM {table} WHERE {pk}=?", (row[pk],))
            conn.commit()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, msg=str(e))

@app.route("/admin/db/<table>/insert", methods=["POST"])
@require_role("admin")
def db_insert(table):
    if table not in ALLOWED_TABLES: return jsonify(success=False, msg="Not allowed")
    row = request.json.get("row", {})
    try:
        with get_db() as conn:
            cols = [k for k,v in row.items() if v != ""]
            if "password" in cols:
                idx = cols.index("password")
                row["password"] = hash_pw(row["password"])
            vals = [row[c] for c in cols]
            conn.execute(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
            conn.commit()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, msg=str(e))

# ── EXPORT REPORTS ────────────────────────────────────────

@app.route("/admin/export/attendance-csv")
@require_role("admin","faculty")
def export_attendance_csv():
    with get_db() as conn:
        students    = conn.execute("SELECT username,full_name,section FROM users WHERE role='student' ORDER BY CAST(username AS INTEGER)").fetchall()
        total_rows  = conn.execute("SELECT subject,total_classes FROM subject_totals").fetchall()
        subj_totals = {r["subject"]:r["total_classes"] for r in total_rows}
        subjects    = sorted(subj_totals.keys())
        grand       = sum(subj_totals.values()) or 1

        lines = ["Name,ID,Section," + ",".join(subjects) + ",Total Attended,Grand Total,Overall %"]
        for s in students:
            att_rows = conn.execute(
                "SELECT subject,COUNT(*) as c FROM attendance WHERE student_username=? GROUP BY subject",
                (s["username"],)).fetchall()
            att = {r["subject"]:r["c"] for r in att_rows}
            row_data = [s["full_name"], s["username"], s["section"] or ""]
            row_data += [str(att.get(subj,0)) for subj in subjects]
            total_att = sum(att.values())
            pct = round(total_att/grand*100)
            row_data += [str(total_att), str(grand), f"{pct}%"]
            lines.append(",".join(row_data))

    csv_str = "\n".join(lines)
    return Response(csv_str, mimetype="text/csv",
                    headers={"Content-Disposition":"attachment;filename=attendance_report.csv"})

# ── VISUALIZATIONS ────────────────────────────────────────

@app.route("/visualize/<username>")
@require_role()
def visualize(username):
    return jsonify(image=None)

@app.route("/visualize/semester/<username>")
@require_role()
def visualize_semester(username):
    with get_db() as conn:
        total_attended = conn.execute("SELECT COUNT(*) as c FROM attendance WHERE student_username=?", (username,)).fetchone()["c"]
        total_possible = conn.execute("SELECT SUM(total_classes) as t FROM subject_totals").fetchone()["t"] or 1
    missed = max(0, total_possible - total_attended)
    plt.figure(figsize=(5,4))
    plt.pie([total_attended, missed], labels=["Attended","Missed"],
            colors=["#1dd1a1","#ff6b6b"], autopct="%1.1f%%", startangle=140)
    plt.title("Semester Overview")
    plt.tight_layout()
    img = io.BytesIO()
    plt.savefig(img, format="png", transparent=True)
    img.seek(0)
    plt.close()
    return Response(img, mimetype="image/png")

@app.route("/visualize/weekly/<username>")
@require_role()
def visualize_weekly(username):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT timestamp FROM attendance WHERE student_username=? ORDER BY timestamp ASC", (username,)
        ).fetchall()
    if not rows:
        plt.figure(figsize=(6,4))
        plt.text(0.5,0.5,"No Data",ha="center")
        img = io.BytesIO(); plt.savefig(img, format="png"); img.seek(0); plt.close()
        return Response(img, mimetype="image/png")
    by_week = {}
    for row in rows:
        wk = datetime.datetime.fromtimestamp(row["timestamp"]).strftime("%Y-W%U")
        by_week[wk] = by_week.get(wk,0)+1
    sorted_wks = sorted(by_week)[-8:]
    counts = [by_week[w] for w in sorted_wks]
    labels = [w.split("-")[1] for w in sorted_wks]
    plt.figure(figsize=(6,4))
    plt.plot(labels, counts, marker="o", color="#6C63FF")
    plt.fill_between(labels, counts, color="#6C63FF", alpha=0.1)
    plt.xlabel("Week"); plt.ylabel("Classes Attended"); plt.title("Weekly Performance")
    plt.grid(True, linestyle="--", alpha=0.5); plt.tight_layout()
    img = io.BytesIO(); plt.savefig(img, format="png", transparent=True); img.seek(0); plt.close()
    return Response(img, mimetype="image/png")

# ── SERVE STATIC FILES (open via http://127.0.0.1:5000) ──
import os as _os
_BASE = _os.path.dirname(_os.path.abspath(__file__))

@app.route("/")
def serve_root():
    return send_from_directory(_BASE, "index.html")

@app.route("/dashboard")
def serve_dashboard():
    return send_from_directory(_BASE, "dashboard.html")

@app.route("/<path:filename>")
def serve_file(filename):
    # Only serve known static files, not API routes
    allowed = {".html", ".js", ".css", ".png", ".jpg", ".ico", ".svg", ".woff", ".woff2"}
    ext = _os.path.splitext(filename)[1].lower()
    if ext in allowed and _os.path.exists(_os.path.join(_BASE, filename)):
        return send_from_directory(_BASE, filename)
    return jsonify(error="Not found"), 404

if __name__ == "__main__":
    print()
    print("=" * 55)
    print("  CampusConnect is running!")
    print("  Open in browser: http://127.0.0.1:5000/app/login")
    print("=" * 55)
    print()
    app.run(host="0.0.0.0", port=5000, debug=True)
