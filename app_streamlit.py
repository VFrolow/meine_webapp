# main.py
import os
import csv
import io
import json
import zipfile
import bcrypt
import streamlit as st
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

st.set_page_config(page_title="Login + Admin", layout="wide")

# =========================================================
#  DB-Verbindung
# =========================================================
DB_URL = os.getenv("DATABASE_URL") or st.secrets.get("db", {}).get("url")
if not DB_URL:
    st.error("DATABASE_URL fehlt. In Render → Service → Environment setzen.")
    st.stop()

engine = create_engine(DB_URL, pool_pre_ping=True)

# =========================================================
#  Schema / Migration
# =========================================================
with engine.begin() as conn:
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            username   TEXT PRIMARY KEY,
            pwd_hash   BYTEA NOT NULL,
            role       TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT NOW()
        )
    """))
    conn.execute(text("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name='users' AND column_name='role'
            ) THEN
                ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';
            END IF;
        END $$;
    """))

# =========================================================
#  Hilfsfunktionen (DB + Auth)
# =========================================================
def _to_bytes(v):
    return v.tobytes() if hasattr(v, "tobytes") else v

def hash_password(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt())

def check_password(pw: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(pw.encode("utf-8"), pw_hash)

def add_user(username: str, password: str, role: str = "user"):
    if not username or not password:
        return False, "Benutzername/Passwort fehlt."
    try:
        with engine.begin() as conn:
            conn.execute(
                text("INSERT INTO users (username, pwd_hash, role) VALUES (:u, :h, :r)"),
                {"u": username, "h": hash_password(password), "r": role}
            )
        return True, "Benutzer registriert."
    except IntegrityError:
        return False, "Benutzername existiert bereits."

def get_user_hash(username: str):
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT pwd_hash FROM users WHERE username=:u"),
            {"u": username}
        ).fetchone()
    if not row:
        return None
    return _to_bytes(row[0])

def get_user(username: str):
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT username, role, created_at FROM users WHERE username=:u"),
            {"u": username}
        ).fetchone()
    return dict(row._mapping) if row else None

def list_users():
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT username, role, created_at FROM users ORDER BY username")
        ).fetchall()
    return [dict(r._mapping) for r in rows]

def set_user_password(username: str, new_pw: str):
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET pwd_hash=:h WHERE username=:u"),
            {"h": hash_password(new_pw), "u": username}
        )

def set_user_role(username: str, role: str):
    assert role in ("user", "admin")
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET role=:r WHERE username=:u"),
                     {"r": role, "u": username})

def delete_user(username: str):
    me = st.session_state.get("user")
    if username == me:
        return False, "Du kannst dich nicht selbst löschen."
    with engine.begin() as conn:
        role_row = conn.execute(text("SELECT role FROM users WHERE username=:u"),
                                {"u": username}).fetchone()
        if not role_row:
            return False, "Benutzer existiert nicht."
        if role_row[0] == "admin":
            admin_count = conn.execute(text("SELECT COUNT(*) FROM users WHERE role='admin'")).scalar()
            if admin_count <= 1:
                return False, "Letzten Admin darfst du nicht löschen."
        conn.execute(text("DELETE FROM users WHERE username=:u"), {"u": username})
    return True, "Benutzer gelöscht."

# =========================================================
#  Seed-Admin (idempotent)
# =========================================================
SEED_ADMIN_USER = os.getenv("SEED_ADMIN_USER")
SEED_ADMIN_PASS = os.getenv("SEED_ADMIN_PASS")
if SEED_ADMIN_USER and SEED_ADMIN_PASS:
    with engine.begin() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM users WHERE username=:u"),
            {"u": SEED_ADMIN_USER}
        ).fetchone()
        if not exists:
            conn.execute(
                text("INSERT INTO users (username, pwd_hash, role) VALUES (:u, :h, 'admin')"),
                {"u": SEED_ADMIN_USER, "h": hash_password(SEED_ADMIN_PASS)}
            )
            print(f"Seed-Admin '{SEED_ADMIN_USER}' wurde angelegt.")

# =========================================================
#  Seiten (Home = mit ZIP-Upload)
# =========================================================
def scan_folder(base_path: Path) -> dict:
    """Logik A: Nur .py-Dateien mit 'main' oder 'runner' im Dateinamen"""
    result = {
        "base": str(base_path),
        "total_files": 0,
        "matched_files": 0,
        "by_ext": {},
        "files": []
    }
    for p in base_path.rglob("*"):
        if p.is_file():
            result["total_files"] += 1
            ext = p.suffix.lower()
            result["by_ext"][ext] = result["by_ext"].get(ext, 0) + 1
            name = p.name.lower()
            if ext == ".py" and ("main" in name or "runner" in name):
                result["files"].append({
                    "relpath": str(p.relative_to(base_path)),
                    "size_bytes": p.stat().st_size
                })
                result["matched_files"] += 1
    return result

def page_home():
    st.title("🏠 Home")
    st.write(f"Eingeloggt als **{st.session_state['user']}**")

    st.markdown("### Programm auswählen (ZIP-Ordner hochladen)")
    uploaded_zip = st.file_uploader("📦 Ordner als ZIP hochladen", type=["zip"], accept_multiple_files=False)

    if uploaded_zip is not None:
        try:
            tmp_dir = Path("/tmp") / f"user_{st.session_state['user']}"
            if tmp_dir.exists():
                for p in tmp_dir.rglob("*"):
                    try: p.unlink()
                    except IsADirectoryError: pass
            tmp_dir.mkdir(parents=True, exist_ok=True)

            zip_path = tmp_dir / "uploaded.zip"
            with open(zip_path, "wb") as f:
                f.write(uploaded_zip.read())

            extract_dir = tmp_dir / "extracted"
            if extract_dir.exists():
                for p in extract_dir.rglob("*"):
                    try: p.unlink()
                    except IsADirectoryError: pass
            extract_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(extract_dir)

            data = scan_folder(extract_dir)

            st.success(f"Scan fertig – Gesamt: {data['total_files']} Dateien | Treffer: {data['matched_files']}")
            st.write("📂 Basisordner:", data["base"])
            st.json({"by_ext": data["by_ext"], "preview": data["files"][:10]})

            st.download_button(
                "📥 JSON herunterladen",
                data=json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"),
                file_name="scan_result.json",
                mime="application/json",
                use_container_width=True
            )

        except Exception as e:
            st.error(f"Fehler beim Verarbeiten des ZIP: {e}")

def page_auswertung():
    st.title("📊 Auswertung")
    st.metric("KPI", "42", "+5")
    st.progress(0.6)

def page_settings():
    st.title("⚙️ Settings")
    st.text_input("Anzeigename", value=st.session_state.get("user", ""))

def is_admin_current_user() -> bool:
    u = st.session_state.get("user")
    info = get_user(u) if u else None
    return bool(info and info.get("role") == "admin")

def page_admin():
    st.title("🛠️ Admin – Benutzerverwaltung")
    users = list_users()
    if not users:
        st.info("Keine Benutzer vorhanden.")
    else:
        st.dataframe(users, use_container_width=True)

# =========================================================
#  Auth Views
# =========================================================
def login_view():
    st.header("🔑 Login")
    u = st.text_input("Benutzername")
    p = st.text_input("Passwort", type="password")
    if st.button("Einloggen"):
        h = get_user_hash(u)
        if h and check_password(p, h):
            st.session_state.logged_in = True
            st.session_state.user = u
            st.session_state.page = "Home"
            st.rerun()
        else:
            st.error("Ungültige Zugangsdaten.")

# =========================================================
#  App
# =========================================================
def app():
    st.session_state.setdefault("logged_in", False)
    st.session_state.setdefault("page", "Home")

    if not st.session_state["logged_in"]:
        login_view()
        return

    with st.sidebar:
        st.title("🧭 Navigation")
        menu = ["Home", "Auswertung", "Settings"]
        if is_admin_current_user():
            menu.append("Admin")
        choice = st.radio("Menü", options=menu, index=menu.index(st.session_state["page"]))
        st.session_state["page"] = choice
        st.markdown("---")
        st.caption(f"Eingeloggt als **{st.session_state['user']}**")
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()

    if st.session_state["page"] == "Home":
        page_home()
    elif st.session_state["page"] == "Auswertung":
        page_auswertung()
    elif st.session_state["page"] == "Settings":
        page_settings()
    elif st.session_state["page"] == "Admin" and is_admin_current_user():
        page_admin()
    else:
        st.error("Seite nicht verfügbar.")

if __name__ == "__main__":
    app()
