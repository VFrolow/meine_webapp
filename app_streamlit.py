# main.py
import os
import json
import time
import re
import shutil
import bcrypt
import zipfile
import streamlit as st
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

st.set_page_config(page_title="Login + Admin + ZIP-Scan + Settings", layout="wide")

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
            must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS user_settings (
            username   TEXT PRIMARY KEY,
            settings   JSONB NOT NULL,
            updated_at TIMESTAMP DEFAULT NOW()
        )
    """))

# =========================================================
#  Auth-Helper
# =========================================================
def hash_password(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt())

def check_password(pw: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(pw.encode("utf-8"), pw_hash)

def _to_bytes(h) -> bytes:
    # memoryview/bytearray/bytes → bytes
    if isinstance(h, bytes):
        return h
    if isinstance(h, bytearray):
        return bytes(h)
    try:
        return bytes(h)
    except Exception:
        return h  # letzte Chance

def get_user_hash(username: str):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT pwd_hash FROM users WHERE username=:u"), {"u": username}).fetchone()
    if not row:
        return None
    return _to_bytes(row[0])

def needs_pw_reset(username: str) -> bool:
    with engine.begin() as conn:
        v = conn.execute(text("SELECT must_change_password FROM users WHERE username=:u"), {"u": username}).scalar()
    return bool(v)

def list_users():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT username, role, must_change_password, created_at FROM users ORDER BY username")).fetchall()
    return [dict(r._mapping) for r in rows]

def add_user(username: str, password: str, role="user", must_change=True):
    try:
        with engine.begin() as conn:
            conn.execute(
                text("""INSERT INTO users (username, pwd_hash, role, must_change_password)
                        VALUES (:u,:h,:r,:m)"""),
                {"u": username, "h": hash_password(password), "r": role, "m": must_change}
            )
        return True, "Benutzer angelegt."
    except IntegrityError:
        return False, "Benutzer existiert bereits."

def delete_user(username: str):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE username=:u"), {"u": username})
    return True, "Benutzer gelöscht."

# Optionaler Seed-Admin für den Erstzugang (Env in Render setzen)
SEED_ADMIN_USER = os.getenv("SEED_ADMIN_USER")
SEED_ADMIN_PASS = os.getenv("SEED_ADMIN_PASS")
if SEED_ADMIN_USER and SEED_ADMIN_PASS:
    with engine.begin() as conn:
        exists = conn.execute(text("SELECT 1 FROM users WHERE username=:u"), {"u": SEED_ADMIN_USER}).fetchone()
        if not exists:
            conn.execute(
                text("""INSERT INTO users (username, pwd_hash, role, must_change_password)
                        VALUES (:u,:h,'admin',FALSE)"""),
                {"u": SEED_ADMIN_USER, "h": hash_password(SEED_ADMIN_PASS)}
            )

# =========================================================
#  Settings (pro User)
# =========================================================
SETTINGS_KEY = "analyze_settings"

def get_default_settings():
    return {
        "npv_hs": "G54",
        "npv_gs": "G55",
        "comment_token": ";",
        "search_start_line": 1,
        "ki_enabled": True,
        "async_assign": True,
        "search_toolname": True,
        "search_edge": True,
    }

def load_settings_from_db(username: str):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT settings FROM user_settings WHERE username=:u"), {"u": username}).fetchone()
    return dict(row._mapping)["settings"] if row else None

def save_settings_to_db(username: str, settings: dict):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO user_settings (username, settings, updated_at)
            VALUES (:u,:s,NOW())
            ON CONFLICT (username) DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()
        """), {"u": username, "s": json.dumps(settings)})

def get_settings():
    st.session_state.setdefault(SETTINGS_KEY, None)
    if st.session_state[SETTINGS_KEY] is None:
        user = st.session_state.get("user")
        st.session_state[SETTINGS_KEY] = load_settings_from_db(user) or get_default_settings()
    return st.session_state[SETTINGS_KEY]

# =========================================================
#  Analyzer (vereinfacht, mit Filter auf L1(101..199)/L2(101..199))
# =========================================================
def user_analyzer(root: Path) -> dict:
    """
    Berücksichtigt NUR Programme L1(101..199) / L2(101..199), z. B. L1101, L2101, ...
    """
    out = {"programs": [], "rowSyncs": []}
    # L + Kanal (1|2) + dreistellig ab 1xx (101..199)
    rx_progname = re.compile(r'^L([12])(1\d{2})(?:\.[A-Za-z0-9]+)?$', re.IGNORECASE)

    jobs: dict[int, dict[str, Path]] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        m = rx_progname.match(p.name)
        if not m:
            continue
        chan = m.group(1)               # "1" oder "2"
        job_num = int(m.group(2))       # 101..199
        if not (101 <= job_num <= 199):
            continue
        jobs.setdefault(job_num, {})
        jobs[job_num].setdefault(chan, p)

    if not jobs:
        return {"programs": [], "rowSyncs": []}

    sorted_jobs = sorted(jobs.keys())
    row_for_job = {num: i+1 for i, num in enumerate(sorted_jobs)}

    # Dummy-Werte für Anzeige (kannst du mit echter Logik ersetzen)
    for job_num in sorted_jobs:
        row_nr = row_for_job[job_num]
        for chan in ("1", "2"):
            fp = jobs[job_num].get(chan)
            if not fp:
                continue
            out["programs"].append({
                "opName": f"Operation {fp.stem}",
                "fileName": fp.name,
                "id": f"prog_{fp.name}",
                "position": {
                    "rowNumber": row_nr,
                    "spindleNumber": 0,                # unzugeordnet als Start
                    "channelNumber": int(chan)
                },
                "tool": {"toolName": "Tool", "cuttingEdgeNo": 1}
            })

    out["rowSyncs"] = [{"rowNumber": i, "syncs": [[1, 2, 3]]} for i in range(1, len(sorted_jobs)+1)]
    return out

# =========================================================
#  Helper für horizontales Verschieben in der UI
# =========================================================
def reassign_spindle(pid, fname, new_spindle):
    res = st.session_state.get("cam_result")
    if not res:
        return
    for p in res.get("programs", []):
        if p.get("id") == pid and p.get("fileName") == fname:
            p["position"]["spindleNumber"] = int(new_spindle)
            break
    st.session_state["cam_result"] = res

# =========================================================
#  Pages
# =========================================================
def page_home():
    st.title("🏠 Home")
    st.markdown("### Programm auswählen (ZIP-Ordner hochladen)")

    # Upload & Entpacken (sauber mit rmtree)
    up = st.file_uploader("📦 ZIP hochladen", type=["zip"])
    if up:
        tmp = Path("/tmp") / f"user_{st.session_state.get('user','anon')}"
        ext = tmp / "ext"
        try:
            shutil.rmtree(tmp, ignore_errors=True)
            tmp.mkdir(parents=True, exist_ok=True)
            zp = tmp / "upload.zip"
            with open(zp, "wb") as f:
                f.write(up.read())
            with zipfile.ZipFile(zp, "r") as z:
                z.extractall(ext)

            with st.spinner("Analysiere Dateien …"):
                st.session_state["cam_result"] = user_analyzer(ext)
            st.success("Analysiert ✅")
        except Exception as e:
            st.error(f"Fehler beim Verarbeiten des ZIP: {e}")
            return

    result = st.session_state.get("cam_result")
    if not result:
        return

    programs = result.get("programs", [])
    if not programs:
        st.info("Keine Programme gefunden.")
        return

    # Karten-Styles
    st.markdown("""
    <style>
      .sm-title{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin:0;}
      .sm-sub{font-size:12px;color:#333;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin:2px 0 0 0;}
      .cardbox{min-height:84px;max-height:84px;display:flex;flex-direction:column;justify-content:center;}
    </style>""", unsafe_allow_html=True)

    # nach rowNumber gruppieren
    by_row = {}
    for p in programs:
        by_row.setdefault(p["position"]["rowNumber"], []).append(p)

    # Kopf (Sp4 | Mitte | Sp3)
    c_idx, c_sp4, c_mid, c_sp3 = st.columns([0.3, 2, 1.2, 2])
    c_idx.markdown("<h3 style='text-align:center'>#</h3>", unsafe_allow_html=True)
    c_sp4.markdown("<h3 style='text-align:center'>🌀 Spindel 4</h3>", unsafe_allow_html=True)
    c_mid.markdown("<h3 style='text-align:center'>Unzugeordnet</h3>", unsafe_allow_html=True)
    c_sp3.markdown("<h3 style='text-align:center'>🌀 Spindel 3</h3>", unsafe_allow_html=True)

    for idx, row_nr in enumerate(sorted(by_row.keys()), start=1):
        row = by_row[row_nr]
        sp4 = [p for p in row if p["position"]["spindleNumber"] == 4]
        mid = [p for p in row if p["position"]["spindleNumber"] == 0]
        sp3 = [p for p in row if p["position"]["spindleNumber"] == 3]

        c_idx, c1, cM, c3 = st.columns([0.3, 2, 1.2, 2])
        c_idx.markdown(f"<div style='text-align:center;font-weight:bold;margin-top:20px'>{idx}</div>", unsafe_allow_html=True)

        def render_card(col, op, where: str):
            opn = (op["opName"] or "").strip()
            tool = (op["tool"]["toolName"] or "").strip()
            pid, fname = op["id"], op["fileName"]
            with col.container(border=True):
                st.markdown(
                    f"<div class='cardbox'><p class='sm-title' title='{opn}'>{opn}</p>"
                    f"<p class='sm-sub' title='{tool}'>🛠️ {tool}</p></div>",
                    unsafe_allow_html=True
                )
                if where == "mid":
                    cl, cr = st.columns(2)
                    if cl.button("← nach Spindel 4", key=f"to4_{pid}_{fname}"):
                        reassign_spindle(pid, fname, 4); st.rerun()
                    if cr.button("nach Spindel 3 →", key=f"to3_{pid}_{fname}"):
                        reassign_spindle(pid, fname, 3); st.rerun()
                elif where == "sp4":
                    if st.button("nach Spindel 3 →", key=f"to3_{pid}_{fname}"):
                        reassign_spindle(pid, fname, 3); st.rerun()
                elif where == "sp3":
                    if st.button("← nach Spindel 4", key=f"to4_{pid}_{fname}"):
                        reassign_spindle(pid, fname, 4); st.rerun()

        for op in sp4: render_card(c1, op, "sp4")
        for op in mid: render_card(cM, op, "mid")
        for op in sp3: render_card(c3, op, "sp3")

    st.markdown("---")
    st.download_button(
        "📥 camExportInfo.json",
        data=json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8"),
        file_name="camExportInfo.json",
        mime="application/json",
        use_container_width=True
    )

def page_settings():
    st.title("⚙️ Settings (pro Benutzer)")
    s = get_settings()
    col1, col2 = st.columns(2)
    with col1:
        s["npv_hs"] = st.text_input("NPV Hauptspindel", value=s["npv_hs"])
        s["npv_gs"] = st.text_input("NPV Gegenspindel", value=s["npv_gs"])
        s["comment_token"] = st.selectbox("Kommentar-Kennung", [";", "MSG"], index=(0 if s["comment_token"] == ";" else 1))
        s["search_start_line"] = st.number_input("Suchen ab (Zeile, 1-basiert)", min_value=1, value=int(s["search_start_line"]), step=1)
    with col2:
        s["ki_enabled"] = st.toggle("KI Analyse", value=bool(s["ki_enabled"]))
        s["async_assign"] = st.toggle("Asynchrone Zuordnung", value=bool(s["async_assign"]))
        s["search_toolname"] = st.toggle("Werkzeugbezeichnung (T = …)", value=bool(s["search_toolname"]))
        s["search_edge"] = st.toggle("Schneidennummer (TC(...))", value=bool(s["search_edge"]))
    if st.button("💾 Speichern", type="primary"):
        save_settings_to_db(st.session_state["user"], s)
        st.success("Settings gespeichert.")

def login_view():
    st.header("🔑 Login")
    u = st.text_input("Benutzername")
    p = st.text_input("Passwort", type="password")
    if st.button("Einloggen"):
        h = get_user_hash(u)
        if h and check_password(p, h):
            st.session_state.update(logged_in=True, user=u, page="Home",
                                    force_pw_change=needs_pw_reset(u))
            # Settings initial laden
            st.session_state[SETTINGS_KEY] = None
            get_settings()
            st.rerun()
        else:
            st.error("Ungültige Zugangsdaten.")

# =========================================================
#  App
# =========================================================
def app():
    if not st.session_state.get("logged_in"):
        login_view()
        return

    if st.session_state.get("force_pw_change", False):
        st.warning("Beim ersten Login bitte Passwort ändern (Feature kann später ergänzt werden).")

    with st.sidebar:
        choice = st.radio("Menü", ["Home", "Settings"])
        st.session_state["page"] = choice
        st.markdown("---")
        st.caption(f"Eingeloggt als **{st.session_state.get('user','?')}**")
        if st.button("Logout"):
            st.session_state.clear()
            st.rerun()

    if st.session_state["page"] == "Home":
        page_home()
    elif st.session_state["page"] == "Settings":
        page_settings()

if __name__ == "__main__":
    app()
