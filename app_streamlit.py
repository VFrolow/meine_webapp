# main.py
import os
import json
import time
import re
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
def hash_password(pw: str) -> bytes: return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt())
def check_password(pw: str, pw_hash: bytes) -> bool: return bcrypt.checkpw(pw.encode("utf-8"), pw_hash)

def get_user_hash(username: str):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT pwd_hash FROM users WHERE username=:u"), {"u": username}).fetchone()
    return row[0] if row else None

def needs_pw_reset(username: str) -> bool:
    with engine.begin() as conn:
        v = conn.execute(text("SELECT must_change_password FROM users WHERE username=:u"), {"u": username}).scalar()
    return bool(v)

def list_users():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT username, role, must_change_password, created_at FROM users")).fetchall()
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
#  Analyzer
# =========================================================
def user_analyzer(root: Path) -> dict:
    # hier vereinfachte Logik, wie zuvor mit Filtern auf L1101 etc.
    out = {"programs": [], "rowSyncs": []}
    rx_prog = re.compile(r'^L([12])1\d{2}', re.I)
    for p in root.rglob("*"):
        if not p.is_file(): continue
        if not rx_prog.match(p.name): continue
        out["programs"].append({
            "opName": "Operation",
            "fileName": p.name,
            "id": f"prog_{p.name}",
            "position": {"rowNumber": 1, "spindleNumber": 4, "channelNumber": 1},
            "tool": {"toolName": "Tool", "cuttingEdgeNo": 1}
        })
    out["rowSyncs"] = [{"rowNumber": 1, "syncs": [[1,2,3]]}]
    return out

# =========================================================
#  Helpers
# =========================================================
def reassign_spindle(pid, fname, new_spindle):
    res = st.session_state.get("cam_result")
    if not res: return
    for p in res.get("programs", []):
        if p.get("id")==pid and p.get("fileName")==fname:
            p["position"]["spindleNumber"]=new_spindle
            break
    st.session_state["cam_result"]=res

# =========================================================
#  Pages
# =========================================================
def page_home():
    st.title("🏠 Home")
    up = st.file_uploader("📦 ZIP hochladen", type=["zip"])
    if up:
        tmp = Path("/tmp")/"upload"
        if tmp.exists():
            for f in tmp.rglob("*"):
                try: f.unlink()
                except: pass
        tmp.mkdir(parents=True, exist_ok=True)
        zp = tmp/"up.zip"
        with open(zp,"wb") as f: f.write(up.read())
        with zipfile.ZipFile(zp,"r") as z: z.extractall(tmp/"ext")
        st.session_state["cam_result"]=user_analyzer(tmp/"ext")
        st.success("Analysiert ✅")

    result = st.session_state.get("cam_result")
    if not result: return

    st.markdown("""
    <style>
      .sm-title{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
      .sm-sub{font-size:12px;color:#333;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
      .cardbox{min-height:84px;max-height:84px;display:flex;flex-direction:column;justify-content:center;}
    </style>""", unsafe_allow_html=True)

    by_row = {}
    for p in result["programs"]:
        by_row.setdefault(p["position"]["rowNumber"], []).append(p)

    # Kopf
    c_idx,c_sp4,c_mid,c_sp3=st.columns([0.3,2,1.2,2])
    c_idx.markdown("<h3 style='text-align:center'>#</h3>",unsafe_allow_html=True)
    c_sp4.markdown("<h3 style='text-align:center'>🌀 Spindel 4</h3>",unsafe_allow_html=True)
    c_mid.markdown("<h3 style='text-align:center'>Unzugeordnet</h3>",unsafe_allow_html=True)
    c_sp3.markdown("<h3 style='text-align:center'>🌀 Spindel 3</h3>",unsafe_allow_html=True)

    for idx,row_nr in enumerate(sorted(by_row.keys()),start=1):
        row = by_row[row_nr]
        c_idx,c1,c2,cM,c3,c4=st.columns([0.3,1,1,1.2,1,1])
        c_idx.markdown(f"<div style='text-align:center;font-weight:bold;margin-top:20px'>{idx}</div>",unsafe_allow_html=True)

        for op in row:
            col = c1
            if op["position"]["spindleNumber"]==4: col=c1
            elif op["position"]["spindleNumber"]==0: col=cM
            elif op["position"]["spindleNumber"]==3: col=c3
            with col.container(border=True):
                opn=op["opName"]; tool=op["tool"]["toolName"]
                st.markdown(f"<div class='cardbox'><p class='sm-title' title='{opn}'>{opn}</p><p class='sm-sub'>{tool}</p></div>",unsafe_allow_html=True)
                if op["position"]["spindleNumber"]==0:
                    cl,cr=st.columns(2)
                    if cl.button("← Sp4",key=f"to4_{op['id']}"): reassign_spindle(op["id"],op["fileName"],4);st.rerun()
                    if cr.button("Sp3 →",key=f"to3_{op['id']}"): reassign_spindle(op["id"],op["fileName"],3);st.rerun()

    st.download_button("📥 camExportInfo.json",data=json.dumps(result,indent=2).encode(),
                       file_name="camExportInfo.json",mime="application/json")

def page_settings():
    st.title("⚙️ Settings")
    s=get_settings()
    s["npv_hs"]=st.text_input("NPV HS",value=s["npv_hs"])
    s["npv_gs"]=st.text_input("NPV GS",value=s["npv_gs"])
    if st.button("Speichern"): save_settings_to_db(st.session_state["user"],s);st.success("Gespeichert")

def login_view():
    st.header("🔑 Login")
    u=st.text_input("User"); p=st.text_input("Passwort",type="password")
    if st.button("Login"):
        h=get_user_hash(u)
        if h and check_password(p,h):
            st.session_state.update(logged_in=True,user=u,page="Home")
            st.session_state[SETTINGS_KEY]=None; get_settings(); st.rerun()
        else: st.error("Login fehlgeschlagen")

def app():
    if not st.session_state.get("logged_in"): login_view(); return
    with st.sidebar:
        choice=st.radio("Menü",["Home","Settings"])
        st.session_state["page"]=choice
        if st.button("Logout"): st.session_state.clear(); st.rerun()
    if st.session_state["page"]=="Home": page_home()
    elif st.session_state["page"]=="Settings": page_settings()

if __name__=="__main__": app()
