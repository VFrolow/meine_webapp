# main.py
import os
import csv
import io
import bcrypt
import streamlit as st
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
    # Falls 'role' in Altbestand fehlt → hinzufügen
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
#  Seed-Admin (idempotent) + optionale Elevation
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

# Einmalige Hochstufung per Env (optional; danach Env entfernen)
ELEVATE_USER = os.getenv("ELEVATE_USER")
if ELEVATE_USER:
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET role='admin' WHERE username=:u"),
                     {"u": ELEVATE_USER})
        print(f"User '{ELEVATE_USER}' wurde zu admin erhöht.")

# =========================================================
#  Debug-Panel (aktiv via ?debug=1 oder DEBUG_AUTH=1)
# =========================================================
def debug_enabled() -> bool:
    if os.getenv("DEBUG_AUTH") == "1":
        return True
    try:
        # Streamlit ≥ 1.30
        if "debug" in st.query_params and str(st.query_params["debug"]) in ("1", "true", "True"):
            return True
    except Exception:
        pass
    return False

def debug_panel():
    if not debug_enabled():
        return
    st.sidebar.markdown("### 🧪 Auth-Debug")
    # DB-Probe
    ok = False
    err = None
    try:
        with engine.begin() as c:
            c.execute(text("SELECT 1"))
        ok = True
    except Exception as e:
        err = str(e)
    st.sidebar.write("DB-Verbindung:", "✅" if ok else f"❌ ({err})")
    # Nutzerübersicht
    try:
        data = list_users()
        st.sidebar.write("Users in DB:", len(data))
        st.sidebar.write("Beispiele:", [{"username": u["username"], "role": u["role"]} for u in data[:10]])
    except Exception as e:
        st.sidebar.error(f"users-Check: {e}")

# =========================================================
#  Seiten
# =========================================================
def page_home():
    st.title("🏠 Home")
    st.write(f"Eingeloggt als **{st.session_state['user']}**")

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

    tabs = st.tabs(["👥 Benutzer", "🗂️ DB-Viewer"])
    # ------------ Tab 1: Benutzerverwaltung ------------
    with tabs[0]:
        users = list_users()
        if not users:
            st.info("Keine Benutzer vorhanden.")
        else:
            for row in users:
                col1, col2, col3, col4, col5 = st.columns([3,2,3,3,3])
                col1.write(f"**{row['username']}**")
                col2.write(row['role'])
                col3.write(row['created_at'])

                with col4:
                    with st.popover("Passwort setzen", use_container_width=True):
                        new_pw = st.text_input(
                            f"Neues Passwort für {row['username']}",
                            type="password", key=f"pw_{row['username']}"
                        )
                        if st.button("Speichern", key=f"pwbtn_{row['username']}"):
                            if new_pw:
                                set_user_password(row['username'], new_pw)
                                st.success("Passwort aktualisiert.")
                            else:
                                st.error("Bitte Passwort eingeben.")

                with col5:
                    if st.button("Löschen", key=f"del_{row['username']}"):
                        ok, msg = delete_user(row['username'])
                        st.toast(msg, icon="✅" if ok else "⚠️")
                        st.rerun()

            st.markdown("---")
            st.subheader("Rolle ändern")
            sel = st.selectbox("Benutzer", [u["username"] for u in users])
            role = st.radio("Rolle", ["user", "admin"], horizontal=True)
            if st.button("Rolle speichern"):
                if sel == st.session_state.get("user") and role != "admin":
                    st.error("Du kannst dir nicht selbst Admin entziehen.")
                else:
                    set_user_role(sel, role)
                    st.success("Rolle aktualisiert.")
                    st.rerun()

    # ------------ Tab 2: DB-Viewer (read-only + CSV) ------------
    with tabs[1]:
        data = list_users()
        st.write(f"**Anzahl Benutzer:** {len(data)}")
        if data:
            # Tabelle anzeigen
            st.dataframe(data, use_container_width=True)
            # CSV-Download
            csv_buf = io.StringIO()
            writer = csv.DictWriter(csv_buf, fieldnames=["username", "role", "created_at"])
            writer.writeheader()
            writer.writerows(data)
            st.download_button(
                "CSV exportieren",
                data=csv_buf.getvalue().encode("utf-8"),
                file_name="users.csv",
                mime="text/csv"
            )
        else:
            st.info("Keine Daten.")

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

def register_view():
    st.header("🧾 Registrieren")
    u = st.text_input("Neuer Benutzername", key="reg_user")
    p1 = st.text_input("Passwort", type="password", key="reg_pw1")
    p2 = st.text_input("Passwort wiederholen", type="password", key="reg_pw2")
    if st.button("Registrieren"):
        if p1 != p2:
            st.error("Passwörter stimmen nicht überein.")
        else:
            ok, msg = add_user(u, p1, "user")
            st.success(msg) if ok else st.error(msg)

# =========================================================
#  App
# =========================================================

def debug_enabled() -> bool:
    if os.getenv("DEBUG_AUTH") == "1":
        return True
    try:
        if "debug" in st.query_params and str(st.query_params["debug"]) in ("1","true","True"):
            return True
    except Exception:
        pass
    return False

def debug_panel():
    if not debug_enabled():
        return
    st.sidebar.markdown("### 🧪 Auth-Debug")
    # Quelle der DB-URL anzeigen
    src = "env:DATABASE_URL" if os.getenv("DATABASE_URL") else ("secrets.toml" if st.secrets.get("db", {}).get("url") else "—")
    st.sidebar.write("DB-URL Quelle:", src)
    # Users auflisten
    try:
        with engine.begin() as c:
            n = c.execute(text("SELECT COUNT(*) FROM users")).scalar()
            st.sidebar.write("Users in DB:", n)
            rows = c.execute(text("SELECT username, role FROM users ORDER BY username LIMIT 10")).fetchall()
            st.sidebar.write("Beispiele:", [dict(r._mapping) for r in rows] if rows else "—")
    except Exception as e:
        st.sidebar.error(f"DB-Check: {e}")


def app():
    debug_panel()  # Debug-Infos in der Sidebar (via ?debug=1 oder DEBUG_AUTH=1)

    st.session_state.setdefault("logged_in", False)
    st.session_state.setdefault("page", "Home")

    if not st.session_state["logged_in"]:
        c1, c2 = st.columns(2)
        with c1: login_view()
        with c2: register_view()
        return

    with st.sidebar:
        st.title("🧭 Navigation")
        menu = ["Home", "Auswertung", "Settings"]
        if is_admin_current_user():
            menu.append("Admin")
        choice = st.radio(
            "Menü",
            options=menu,
            index=menu.index(st.session_state["page"]) if st.session_state["page"] in menu else 0,
            label_visibility="collapsed"
        )
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


