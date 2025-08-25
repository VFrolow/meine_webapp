# main.py
import os
import io
import csv
import json
import time
import zipfile
import bcrypt
import streamlit as st
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

st.set_page_config(page_title="Login + Admin + ZIP-Scan", layout="wide")

# =========================================================
#  DB-Verbindung
# =========================================================
DB_URL = os.getenv("DATABASE_URL") or st.secrets.get("db", {}).get("url")
if not DB_URL:
    st.error("DATABASE_URL fehlt. In Render → Service → Environment setzen.")
    st.stop()
engine = create_engine(DB_URL, pool_pre_ping=True)

# =========================================================
#  Schema / Migration (inkl. must_change_password)
# =========================================================
with engine.begin() as conn:
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            username   TEXT PRIMARY KEY,
            pwd_hash   BYTEA NOT NULL,
            role       TEXT NOT NULL DEFAULT 'user',
            must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """))
    # Nachrüstungen für Bestandsdaten
    conn.execute(text("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name='users' AND column_name='role'
            ) THEN
                ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user';
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name='users' AND column_name='must_change_password'
            ) THEN
                ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
            END IF;
        END $$;
    """))

# =========================================================
#  Auth-Helper
# =========================================================
def _to_bytes(v): return v.tobytes() if hasattr(v, "tobytes") else v
def hash_password(pw: str) -> bytes: return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt())
def check_password(pw: str, pw_hash: bytes) -> bool: return bcrypt.checkpw(pw.encode("utf-8"), pw_hash)
def is_strong(pw: str) -> tuple[bool, str]:
    if len(pw) < 8: return False, "Passwort zu kurz (min. 8 Zeichen)."
    return True, ""

def add_user(username: str, password: str, role: str = "user", must_change: bool = False):
    if not username or not password: return False, "Benutzername/Passwort fehlt."
    ok, msg = is_strong(password)
    if not ok: return False, msg
    try:
        with engine.begin() as conn:
            conn.execute(
                text("""INSERT INTO users (username, pwd_hash, role, must_change_password)
                        VALUES (:u, :h, :r, :m)"""),
                {"u": username, "h": hash_password(password), "r": role, "m": must_change}
            )
        return True, "Benutzer angelegt."
    except IntegrityError:
        return False, "Benutzername existiert bereits."

def get_user(username: str):
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT username, role, must_change_password, created_at FROM users WHERE username=:u"),
            {"u": username}
        ).fetchone()
    return dict(row._mapping) if row else None

def get_user_hash(username: str):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT pwd_hash FROM users WHERE username=:u"), {"u": username}).fetchone()
    if not row: return None
    return _to_bytes(row[0])

def needs_pw_reset(username: str) -> bool:
    with engine.begin() as conn:
        v = conn.execute(text("SELECT must_change_password FROM users WHERE username=:u"), {"u": username}).scalar()
    return bool(v)

def list_users():
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT username, role, must_change_password, created_at FROM users ORDER BY username")
        ).fetchall()
    return [dict(r._mapping) for r in rows]

def set_user_password(username: str, new_pw: str, clear_must_change: bool = True):
    ok, msg = is_strong(new_pw)
    if not ok: return False, msg
    with engine.begin() as conn:
        if clear_must_change:
            conn.execute(
                text("UPDATE users SET pwd_hash=:h, must_change_password=FALSE WHERE username=:u"),
                {"h": hash_password(new_pw), "u": username}
            )
        else:
            conn.execute(text("UPDATE users SET pwd_hash=:h WHERE username=:u"),
                         {"h": hash_password(new_pw), "u": username})
    return True, "Passwort aktualisiert."

def set_user_role(username: str, role: str):
    assert role in ("user", "admin")
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET role=:r WHERE username=:u"), {"r": role, "u": username})

def delete_user(username: str):
    me = st.session_state.get("user")
    if username == me: return False, "Du kannst dich nicht selbst löschen."
    with engine.begin() as conn:
        role_row = conn.execute(text("SELECT role FROM users WHERE username=:u"), {"u": username}).fetchone()
        if not role_row: return False, "Benutzer existiert nicht."
        if role_row[0] == "admin":
            admin_count = conn.execute(text("SELECT COUNT(*) FROM users WHERE role='admin'")).scalar()
            if admin_count <= 1: return False, "Letzten Admin darfst du nicht löschen."
        conn.execute(text("DELETE FROM users WHERE username=:u"), {"u": username})
    return True, "Benutzer gelöscht."

# Seed-Admin (idempotent)
SEED_ADMIN_USER = os.getenv("SEED_ADMIN_USER")
SEED_ADMIN_PASS = os.getenv("SEED_ADMIN_PASS")
if SEED_ADMIN_USER and SEED_ADMIN_PASS:
    with engine.begin() as conn:
        exists = conn.execute(text("SELECT 1 FROM users WHERE username=:u"), {"u": SEED_ADMIN_USER}).fetchone()
        if not exists:
            conn.execute(text("""INSERT INTO users (username, pwd_hash, role, must_change_password)
                                 VALUES (:u, :h, 'admin', FALSE)"""),
                         {"u": SEED_ADMIN_USER, "h": hash_password(SEED_ADMIN_PASS)})
            print(f"Seed-Admin '{SEED_ADMIN_USER}' wurde angelegt.")

# =========================================================
#  ZIP-Scan (Logik A) – Home
# =========================================================
def scan_folder(base_path: Path) -> dict:
    """Nur .py-Dateien, deren Name 'main' oder 'runner' enthält (case-insensitive)."""
    result = {"base": str(base_path), "total_files": 0, "matched_files": 0, "by_ext": {}, "files": []}
    for p in base_path.rglob("*"):
        if p.is_file():
            result["total_files"] += 1
            ext = p.suffix.lower()
            result["by_ext"][ext] = result["by_ext"].get(ext, 0) + 1
            name = p.name.lower()
            if ext == ".py" and ("main" in name or "runner" in name):
                result["files"].append({"relpath": str(p.relative_to(base_path)), "size_bytes": p.stat().st_size})
                result["matched_files"] += 1
    return result

# =========================================================
#  Seiten
# =========================================================
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
            with open(zip_path, "wb") as f: f.write(uploaded_zip.read())

            extract_dir = tmp_dir / "extracted"
            if extract_dir.exists():
                for p in extract_dir.rglob("*"):
                    try: p.unlink()
                    except IsADirectoryError: pass
            extract_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(zip_path, "r") as z: z.extractall(extract_dir)
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
    st.write("Hier kannst du dein Passwort ändern.")
    change_password_form(show_current=True)

def is_admin_current_user() -> bool:
    u = st.session_state.get("user")
    info = get_user(u) if u else None
    return bool(info and info.get("role") == "admin")

# Passwort ändern
def change_password_form(show_current: bool = False):
    user = st.session_state.get("user")
    st.subheader("🔒 Passwort ändern")
    cur = st.text_input("Aktuelles Passwort", type="password") if show_current else None
    n1 = st.text_input("Neues Passwort", type="password")
    n2 = st.text_input("Neues Passwort (wiederholen)", type="password")
    if st.button("Passwort speichern"):
        if n1 != n2:
            st.error("Passwörter stimmen nicht überein."); return
        ok, msg = is_strong(n1)
        if not ok:
            st.error(msg); return
        if show_current:
            h = get_user_hash(user)
            if not (h and check_password(cur or "", h)):
                st.error("Aktuelles Passwort ist falsch."); return
        ok, msg = set_user_password(user, n1, clear_must_change=True)
        st.success("Passwort aktualisiert.") if ok else st.error(msg)
        if ok:
            st.session_state["force_pw_change"] = False
            time.sleep(0.4)
            st.rerun()

def page_admin():
    st.title("🛠️ Admin – Benutzerverwaltung")
    tabs = st.tabs(["👥 Benutzerliste", "➕ Benutzer anlegen (Temp-PW)"])

    # Liste + Aktionen
    with tabs[0]:
        users = list_users()
        if not users:
            st.info("Keine Benutzer vorhanden.")
        else:
            for row in users:
                col1, col2, col3, col4, col5, col6 = st.columns([3,2,3,3,3,2])
                col1.write(f"**{row['username']}**")
                col2.write(row['role'])
                col3.write("🔁 Wechsel nötig" if row['must_change_password'] else "✅ gesetzt")
                col4.write(row['created_at'])

                with col5:
                    with st.popover("Passwort setzen (ohne Zwang)", use_container_width=True):
                        new_pw = st.text_input(f"Neues Passwort für {row['username']}",
                                               type="password", key=f"pw_{row['username']}")
                        if st.button("Speichern", key=f"pwbtn_{row['username']}"):
                            if new_pw:
                                ok, msg = set_user_password(row['username'], new_pw, clear_must_change=False)
                                st.success(msg) if ok else st.error(msg)
                            else:
                                st.error("Bitte Passwort eingeben.")

                with col6:
                    if st.button("Löschen", key=f"del_{row['username']}"):
                        ok, msg = delete_user(row['username'])
                        st.toast(msg, icon="✅" if ok else "⚠️")
                        st.rerun()

            st.markdown("---")
            st.subheader("Rolle ändern")
            if users:
                sel = st.selectbox("Benutzer", [u["username"] for u in users])
                role = st.radio("Rolle", ["user", "admin"], horizontal=True)
                if st.button("Rolle speichern"):
                    if sel == st.session_state.get("user") and role != "admin":
                        st.error("Du kannst dir nicht selbst Admin entziehen.")
                    else:
                        set_user_role(sel, role); st.success("Rolle aktualisiert."); st.rerun()

    # Anlegen mit Temp-PW + Zwangswechsel
    with tabs[1]:
        st.info("Neuer Nutzer bekommt ein temporäres Passwort und muss es beim ersten Login ändern.")
        nu = st.text_input("Benutzername (neu)", key="admin_new_user")
        npw1 = st.text_input("Temporäres Passwort", type="password", key="admin_new_pw1")
        npw2 = st.text_input("Temporäres Passwort (wiederholen)", type="password", key="admin_new_pw2")
        nrole = st.radio("Rolle", ["user", "admin"], horizontal=True, index=0, key="admin_new_role")
        if st.button("Benutzer erstellen"):
            if not nu or not npw1:
                st.error("Bitte Benutzername & Passwort eingeben.")
            elif npw1 != npw2:
                st.error("Passwörter stimmen nicht überein.")
            else:
                ok, msg = add_user(nu, npw1, nrole, must_change=True)
                st.success(msg) if ok else st.error(msg)
                if ok: st.rerun()

# =========================================================
#  Login / App
# =========================================================
def login_view():
    st.header("🔑 Login")
    st.session_state.setdefault("login_attempts", 0)
    st.session_state.setdefault("lock_until", 0)
    now = time.time()
    if now < st.session_state["lock_until"]:
        st.warning(f"Zu viele Versuche. Bitte in {int(st.session_state['lock_until']-now)}s erneut."); return
    u = st.text_input("Benutzername")
    p = st.text_input("Passwort", type="password")
    if st.button("Einloggen"):
        h = get_user_hash(u)
        if h and check_password(p, h):
            st.session_state.update(logged_in=True, user=u, page="Home",
                                    force_pw_change=needs_pw_reset(u))
            st.rerun()
        else:
            st.session_state["login_attempts"] += 1
            if st.session_state["login_attempts"] >= 5:
                st.session_state["lock_until"] = now + 60
                st.session_state["login_attempts"] = 0
                st.error("Zu viele Versuche. 60 Sekunden gesperrt.")
            else:
                st.error("Ungültige Zugangsdaten.")

def app():
    st.session_state.setdefault("logged_in", False)
    st.session_state.setdefault("page", "Home")
    st.session_state.setdefault("force_pw_change", False)

    if not st.session_state["logged_in"]:
        login_view(); return

    # Zwang zum Passwortwechsel
    if st.session_state.get("force_pw_change", False):
        st.sidebar.info("🔁 Bitte zuerst Passwort ändern (erster Login).")
        change_password_form(show_current=False); return

    with st.sidebar:
        st.title("🧭 Navigation")
        menu = ["Home", "Auswertung", "Settings"]
        if is_admin_current_user(): menu.append("Admin")
        choice = st.radio("Menü", options=menu,
                          index=menu.index(st.session_state["page"]) if st.session_state["page"] in menu else 0,
                          label_visibility="collapsed")
        st.session_state["page"] = choice
        st.markdown("---")
        st.caption(f"Eingeloggt als **{st.session_state['user']}**")
        if st.button("Logout"):
            st.session_state.clear(); st.rerun()

    if st.session_state["page"] == "Home": page_home()
    elif st.session_state["page"] == "Auswertung": page_auswertung()
    elif st.session_state["page"] == "Settings": page_settings()
    elif st.session_state["page"] == "Admin" and is_admin_current_user(): page_admin()
    else: st.error("Seite nicht verfügbar.")

if __name__ == "__main__":
    app()

