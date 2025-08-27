# main.py
import os
import json
import re
import shutil
import zipfile
import bcrypt
import streamlit as st
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

st.set_page_config(page_title="Login + Settings + ZIP-Scan", layout="wide")

# =========================================================
#  DB-VERBINDUNG
# =========================================================
DB_URL = os.getenv("DATABASE_URL") or st.secrets.get("db", {}).get("url")
if not DB_URL:
    st.error("DATABASE_URL fehlt. In Render → Service → Environment setzen.")
    st.stop()
engine = create_engine(DB_URL, pool_pre_ping=True)

# =========================================================
#  SCHEMA / MIGRATION
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
#  AUTH-HELPER
# =========================================================
def hash_password(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt())

def check_password(pw: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(pw.encode("utf-8"), pw_hash)

def _to_bytes(h) -> bytes:
    if isinstance(h, bytes): return h
    if isinstance(h, bytearray): return bytes(h)
    try: return bytes(h)
    except Exception: return h

def get_user_hash(username: str):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT pwd_hash FROM users WHERE username=:u"), {"u": username}).fetchone()
    if not row: return None
    return _to_bytes(row[0])

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
        return False, "Benutzername existiert bereits."

# Optionaler Seed-Admin (Env in Render setzen)
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
#  SETTINGS (pro User)
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
#  ANALYZER – nur L1(101..199)/L2(101..199), ZUORDNUNG: K1→SP4, K2→SP3
# =========================================================
def user_analyzer(root: Path) -> dict:
    """
    Berücksichtigt NUR Programme L1(101..199) / L2(101..199), z. B. L1101, L2101, ...
    Spindel-Zuordnung (ohne Mittelspalte/Manuell):
      Kanal 1 → Spindel 4
      Kanal 2 → Spindel 3
    """
    out = {"programs": [], "rowSyncs": []}
    rx_progname = re.compile(r'^L([12])(1\d{2})(?:\.[A-Za-z0-9]+)?$', re.IGNORECASE)

    jobs: dict[int, dict[str, Path]] = {}
    for p in root.rglob("*"):
        if not p.is_file(): continue
        m = rx_progname.match(p.name)
        if not m: continue
        chan = m.group(1)               # "1" oder "2"
        job_num = int(m.group(2))       # 101..199
        if not (101 <= job_num <= 199): continue
        jobs.setdefault(job_num, {})
        jobs[job_num].setdefault(chan, p)

    if not jobs:
        return {"programs": [], "rowSyncs": []}

    sorted_jobs = sorted(jobs.keys())
    row_for_job = {num: i+1 for i, num in enumerate(sorted_jobs)}

    for job_num in sorted_jobs:
        row_nr = row_for_job[job_num]
        for chan in ("1", "2"):
            fp = jobs[job_num].get(chan)
            if not fp: continue
            spindle = 4 if chan == "1" else 3  # feste Logik, kein „Unzugeordnet“
            out["programs"].append({
                "opName": f"Operation {fp.stem}",
                "fileName": fp.name,
                "id": f"prog_{fp.name}",
                "position": {
                    "rowNumber": row_nr,
                    "spindleNumber": spindle,
                    "channelNumber": int(chan)
                },
                "tool": {"toolName": "Tool", "cuttingEdgeNo": 1}
            })

    # rowSyncs – pro Zeile
    out["rowSyncs"] = [{"rowNumber": i, "syncs": [[1, 2, 3]]} for i in range(1, len(sorted_jobs)+1)]
    return out

# =========================================================
#  PAGES
# =========================================================
def page_home():
    st.title("🏠 Home")
    st.markdown("### Programm auswählen (ZIP-Ordner hochladen)")

    # Upload & Entpacken
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

    # Kopfzeile: Spindel 4 | Spindel 3
    c_idx, c_sp4, c_sp3 = st.columns([0.3, 2, 2])
    c_idx.markdown("<h3 style='text-align:center'>#</h3>", unsafe_allow_html=True)
    c_sp4.markdown("<h3 style='text-align:center'>🌀 Spindel 4</h3>", unsafe_allow_html=True)
    c_sp3.markdown("<h3 style='text-align:center'>🌀 Spindel 3</h3>", unsafe_allow_html=True)

    # Unterzeile: Kanäle
    c_idx, c_sp4_k1, c_sp4_k2, c_sp3_k1, c_sp3_k2 = st.columns([0.3, 1, 1, 1, 1])
    c_sp4_k1.markdown("<h4 style='text-align:center'>Kanal 1</h4>", unsafe_allow_html=True)
    c_sp4_k2.markdown("<h4 style='text-align:center'>Kanal 2</h4>", unsafe_allow_html=True)
    c_sp3_k1.markdown("<h4 style='text-align:center'>Kanal 1</h4>", unsafe_allow_html=True)
    c_sp3_k2.markdown("<h4 style='text-align:center'>Kanal 2</h4>", unsafe_allow_html=True)

    # Renderer
    def render_card(col, op):
        opn = (op["opName"] or "").strip()
        tool = (op["tool"]["toolName"] or "").strip()
        with col.container(border=True):
            st.markdown(
                f"<div class='cardbox'><p class='sm-title' title='{opn}'>{opn}</p>"
                f"<p class='sm-sub' title='{tool}'>🛠️ {tool}</p></div>",
                unsafe_allow_html=True
            )

    # Zeilen darstellen
    for idx, row_nr in enumerate(sorted(by_row.keys()), start=1):
        row = by_row[row_nr]
        sp4_k1 = [p for p in row if p["position"]["spindleNumber"] == 4 and p["position"]["channelNumber"] == 1]
        sp4_k2 = [p for p in row if p["position"]["spindleNumber"] == 4 and p["position"]["channelNumber"] == 2]
        sp3_k1 = [p for p in row if p["position"]["spindleNumber"] == 3 and p["position"]["channelNumber"] == 1]
        sp3_k2 = [p for p in row if p["position"]["spindleNumber"] == 3 and p["position"]["channelNumber"] == 2]

        c_idx, c1, c2, c3, c4 = st.columns([0.3, 1, 1, 1, 1])
        c_idx.markdown(f"<div style='text-align:center;font-weight:bold;margin-top:20px'>{idx}</div>", unsafe_allow_html=True)

        for op in sp4_k1: render_card(c1, op)
        for op in sp4_k2: render_card(c2, op)
        for op in sp3_k1: render_card(c3, op)
        for op in sp3_k2: render_card(c4, op)

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
            st.session_state.update(logged_in=True, user=u, page="Home")
            st.session_state[SETTINGS_KEY] = None
            get_settings()
            st.rerun()
        else:
            st.error("Ungültige Zugangsdaten.")

# =========================================================
#  APP
# =========================================================
def app():
    if not st.session_state.get("logged_in"):
        login_view()
        return

    with st.sidebar:
        choice = st.radio("Menü", ["Home", "Settings"])
        st.session_state["page"] = choice
        st.markdown("---")
        st.caption(f"Eingeloggt als **{st.session_state.get('user','?')}**")
        if st.button("Logout"):
            st.session_state.clear(); st.rerun()

    if st.session_state["page"] == "Home":
        page_home()
    elif st.session_state["page"] == "Settings":
        page_settings()

if __name__ == "__main__":
    app()
