# main.py
import os
import io
import csv
import json
import time
import zipfile
import re
import bcrypt
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
    # Users (inkl. must_change_password)
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            username   TEXT PRIMARY KEY,
            pwd_hash   BYTEA NOT NULL,
            role       TEXT NOT NULL DEFAULT 'user',
            must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """))
    # User-Settings (pro Benutzer gespeichert)
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
#  Settings – Defaults, Laden/Speichern (pro Benutzer)
# =========================================================
SETTINGS_KEY = "analyze_settings"

def get_default_settings():
    return {
        "npv_hs": "G54",            # NPV Hauptspindel
        "npv_gs": "G55",            # NPV Gegenspindel
        "comment_token": ";",       # Kommentar-Kennung: ";" oder "MSG"
        "search_start_line": 1,     # ab welcher Zeile (1-basiert)
        "ki_enabled": True,         # KI Analyse aktiv
        "async_assign": True,       # Asynchrone Zuordnung
        "search_toolname": True,    # Werkzeugname (T=...)
        "search_edge": True,        # Schneidennummer (TC(...))
    }

def load_settings_from_db(username: str):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT settings FROM user_settings WHERE username=:u"), {"u": username}).fetchone()
    return dict(row._mapping)["settings"] if row else None

def save_settings_to_db(username: str, settings: dict):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO user_settings (username, settings, updated_at)
            VALUES (:u, :s, NOW())
            ON CONFLICT (username) DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()
        """), {"u": username, "s": json.dumps(settings)})

def get_settings():
    st.session_state.setdefault(SETTINGS_KEY, None)
    if st.session_state[SETTINGS_KEY] is None:
        user = st.session_state.get("user")
        loaded = load_settings_from_db(user) if user else None
        st.session_state[SETTINGS_KEY] = loaded or get_default_settings()
    return st.session_state[SETTINGS_KEY]

# =========================================================
#  Analyzer (deine Logik) – nutzt die Settings
# =========================================================
def user_analyzer(root: Path) -> dict:
    """
    Analysiert rekursiv alle Dateien, berücksichtigt aber NUR Programme:
      L1(101..199) / L2(101..199)  -> z.B. L1101, L2101, L1102, L2102, ...
    Alles andere wird ignoriert.
    """
    s = get_settings()
    npv_hs = s["npv_hs"].upper().strip()
    npv_gs = s["npv_gs"].upper().strip()
    comment_token = s["comment_token"]  # ";" oder "MSG"
    start_idx = max(1, int(s["search_start_line"])) - 1  # 0-basiert
    use_ki = bool(s["ki_enabled"])
    use_async = bool(s["async_assign"])
    want_tool = bool(s["search_toolname"])
    want_edge = bool(s["search_edge"])

    project_name = root.name
    out = {
        "version": "1.0",
        "cam": {"name": "VV", "version": "1.0"},
        "postProcessor": {"name": "pto_opw", "version": "1.0", "producer": "VV"},
        "project": {
            "name": project_name,
            "author": "VV",
            "workpiece": {"name": "none", "material": "none", "referenceId": "none"},
        },
        "machine": {"isMetric": True, "machineType": 2},
        "programs": [],
        "rowSyncs": [],
    }

    # Verbots-/Prüflisten & KI wie zuvor
    verboten_npv = [";", "E_CON", "TCARR", "MSG", "TCTOOL", "CALL", "HEAD", "PS_", "GROUP_BEGIN", "F_CON"]
    verboten_end = [";", "MSG"]
    prg_end_opt  = ["M17", "M30", "RET"]
    rx_prefix_npv = re.compile(r"^\s*(?:" + "|".join(map(re.escape, verboten_npv)) + r")", re.I)
    rx_prefix_end = re.compile(r"^\s*(?:" + "|".join(map(re.escape, verboten_end)) + r")", re.I)
    rx_end        = re.compile(r"^\s*(?:" + "|".join(map(re.escape, prg_end_opt)) + r")(?!\d)", re.I)

    merkmale_hs = ["M814", "SETMS(4)", "L707", "SPOS[4]", "C4", "S4", "M4"]
    merkmale_gs = ["M813", "SETMS(3)", "L705", "SPOS[3]", "C3", "S3", "M3"]
    rx_ki_hs    = re.compile(r"^\s*(?:" + "|".join(map(re.escape, merkmale_hs)) + r")(?!\d)", re.I)
    rx_ki_gs    = re.compile(r"^\s*(?:" + "|".join(map(re.escape, merkmale_gs)) + r")(?!\d)", re.I)

    # ---------------- NUR L1/2 + 101..199 zulassen ----------------
    # Regex erzwingt: L, Kanal 1/2, und genau drei Ziffern beginnend mit 1 (=> 1xx)
    rx_progname = re.compile(r'^L([12])(1\d{2})(?:\.[A-Za-z0-9]+)?$', re.IGNORECASE)

    # Map: job_num -> { "1": Path, "2": Path }
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
            continue  # hart filtern
        jobs.setdefault(job_num, {})
        jobs[job_num].setdefault(chan, p)  # erstes Vorkommen nehmen

    if not jobs:
        return out

    # Reihen/rowNumber aus den vorhandenen Job-Nummern
    sorted_jobs = sorted(jobs.keys())  # z.B. [101, 102, ...]
    row_for_job = {num: idx+1 for idx, num in enumerate(sorted_jobs)}

    # ---------------- Dateien je Job verarbeiten ----------------
    for job_num in sorted_jobs:
        row_nr = row_for_job[job_num]

        for chan_no in ("1", "2"):
            match_path = jobs[job_num].get(chan_no)
            if not match_path:
                continue

            # Datei lesen
            try:
                with open(match_path, "r", encoding="utf-8", errors="ignore") as f:
                    first = f.readline()
                    rest  = f.readlines()
                lines = [first] + rest
            except Exception:
                lines = []

            # opName
            op_name = "no comment"
            if lines:
                if comment_token == ";" and ";" in lines[0]:
                    op_name = lines[0].split(";", 1)[1].strip()
                elif comment_token == "MSG":
                    up0 = lines[0].upper()
                    if "MSG" in up0:
                        op_name = lines[0].split("MSG", 1)[1].strip(" :\t\r\n")
                    elif ";" in lines[0]:
                        op_name = lines[0].split(";", 1)[1].strip()

            # Werkzeugname
            toolname = ""
            if want_tool:
                for raw in lines:
                    if rx_prefix_npv.search(raw):
                        continue
                    m_t = re.search(r'T\s*=\s*(.*)', raw, re.I)
                    if m_t:
                        toolname = m_t.group(1).rstrip("\r\n").replace('"', "")
                        break

            # Schneidennummer
            cutting_edge = 0
            if want_edge:
                for raw in lines:
                    if rx_prefix_npv.search(raw):
                        continue
                    m_e = re.search(r'TC\s*\(\s*(\d+)', raw, re.I)
                    if m_e:
                        cutting_edge = int(m_e.group(1))
                        break

            # Spindelzuordnung
            gxx = 99
            g54_found = False
            g55_found = False
            ki_hs_hit = False
            ki_gs_hit = False

            seq = lines[max(1, start_idx):]
            for zeile in seq:
                up = zeile.upper()
                if rx_end.search(up) and not rx_prefix_end.search(up):
                    break
                if re.search(re.escape(npv_hs), up) and not rx_prefix_npv.search(up):
                    g54_found = True; gxx = 4; break
                if re.search(re.escape(npv_gs), up) and not rx_prefix_npv.search(up):
                    g55_found = True; gxx = 3; break
                if use_ki:
                    if rx_ki_hs.search(up) and not rx_prefix_end.search(up):
                        ki_hs_hit = True
                    if rx_ki_gs.search(up) and not rx_prefix_end.search(up):
                        ki_gs_hit = True

            if use_ki and not (g54_found or g55_found):
                if   ki_hs_hit and not ki_gs_hit: gxx = 4
                elif ki_gs_hit and not ki_hs_hit: gxx = 3

            if gxx == 99 and use_async:
                gxx = 4 if chan_no == "1" else 3
            if gxx == 99:
                gxx = 0

            stem_id = f"L{chan_no}{job_num}"  # z.B. L1101/L2101
            out["programs"].append({
                "opName": op_name,
                "fileName": match_path.name,
                "id": f"vv_{project_name}_{stem_id}",
                "isTransformationOf": "",
                "position": {
                    "channelNumber": int(chan_no),
                    "spindleNumber": int(gxx),
                    "rowNumber": row_nr,
                },
                "tool": {
                    "toolName": toolname,
                    "cuttingEdgeNo": int(cutting_edge),
                },
            })

    # rowSyncs: für jede tatsächliche Zeile ein Eintrag
    max_row = len(sorted_jobs)
    out["rowSyncs"] = [{"rowNumber": i, "syncs": [[1,2,3]]} for i in range(1, max_row + 1)]
    return out



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

            with st.spinner("Analysiere Dateien mit deinen Settings…"):
                result = user_analyzer(extract_dir)

            st.success("camExportInfo.json erzeugt ✅")

            # Vorschau-Tabelle (ohne pandas)
            rows = []
            for p in result.get("programs", []):
                rows.append({
                    "opName": p.get("opName",""),
                    "fileName": p.get("fileName",""),
                    "channel": p.get("position",{}).get("channelNumber",0),
                    "spindle": p.get("position",{}).get("spindleNumber",0),
                    "toolName": p.get("tool",{}).get("toolName",""),
                    "edge": p.get("tool",{}).get("cuttingEdgeNo",0),
                    "row": p.get("position",{}).get("rowNumber",0),
                })
            if rows:
                # Programme nach rowNumber gruppieren
                by_row = {}
                for p in result["programs"]:
                    r = p["position"]["rowNumber"]
                    by_row.setdefault(r, []).append(p)
            
                # Kopfzeile
                c_sp4_k1, c_sp4_k2, c_sp3_k1, c_sp3_k2 = st.columns(4)
                with c_sp4_k1: st.subheader("🌀 Spindel 4 – Kanal 1")
                with c_sp4_k2: st.subheader("🌀 Spindel 4 – Kanal 2")
                with c_sp3_k1: st.subheader("🌀 Spindel 3 – Kanal 1")
                with c_sp3_k2: st.subheader("🌀 Spindel 3 – Kanal 2")
            
                # Zeilen nacheinander
                for row_nr in sorted(by_row.keys()):
                    progs = by_row[row_nr]
                    sp4_k1 = [p for p in progs if p["position"]["channelNumber"] == 1 and p["position"]["spindleNumber"] == 4]
                    sp4_k2 = [p for p in progs if p["position"]["channelNumber"] == 2 and p["position"]["spindleNumber"] == 4]
                    sp3_k1 = [p for p in progs if p["position"]["channelNumber"] == 1 and p["position"]["spindleNumber"] == 3]
                    sp3_k2 = [p for p in progs if p["position"]["channelNumber"] == 2 and p["position"]["spindleNumber"] == 3]
            
                    c_sp4_k1, c_sp4_k2, c_sp3_k1, c_sp3_k2 = st.columns(4)
            
                    def render_ops(col, ops):
                        for op in ops:
                            col.markdown(
                                f"""
                                <div style="background-color:#f5f5f5; border:1px solid #ddd; 
                                            padding:8px; border-radius:8px; margin-bottom:8px;">
                                    <b>Row {op['position']['rowNumber']}</b> – {op['opName']}<br>
                                    <small>📄 {op['fileName']}<br>
                                    🛠️ {op['tool']['toolName']} / Schneide {op['tool']['cuttingEdgeNo']}</small>
                                </div>
                                """,
                                unsafe_allow_html=True
                            )
            
                    render_ops(c_sp4_k1, sp4_k1)
                    render_ops(c_sp4_k2, sp4_k2)
                    render_ops(c_sp3_k1, sp3_k1)
                    render_ops(c_sp3_k2, sp3_k2)
            else:
                st.info("Keine Programme gefunden.")


            st.download_button(
                "📥 camExportInfo.json herunterladen",
                data=json.dumps(result, indent=2, ensure_ascii=False, separators=(',', ':')).encode("utf-8"),
                file_name="camExportInfo.json",
                mime="application/json",
                use_container_width=True
            )
        except Exception as e:
            st.error(f"Fehler beim Verarbeiten des ZIP: {e}")

def page_auswertung():
    st.title("📊 Auswertung")
    st.info("Hier kannst du später Analysen/Reports auf Basis der camExportInfo einbauen.")

def page_settings():
    st.title("⚙️ Settings (werden pro Benutzer gespeichert)")
    s = get_settings()

    col1, col2 = st.columns(2)
    with col1:
        s["npv_hs"] = st.text_input(
            "NPV Hauptspindel",
            value=s["npv_hs"],
            help="Marker für Hauptspindel (Standard: G54)."
        )
        s["npv_gs"] = st.text_input(
            "NPV Gegenspindel",
            value=s["npv_gs"],
            help="Marker für Gegenspindel (Standard: G55)."
        )
        s["comment_token"] = st.selectbox(
            "Kommentar-Kennung",
            [";", "MSG"],
            index=(0 if s["comment_token"] == ";" else 1),
            help="Wie wird der Operationsname in Zeile 1 erkannt? ';' oder 'MSG'."
        )
        s["search_start_line"] = st.number_input(
            "Suchen ab (Zeile, 1-basiert)",
            min_value=1, value=int(s["search_start_line"]), step=1,
            help="Ab welcher Zeile der Datei die Analyse beginnt."
        )
    with col2:
        s["ki_enabled"] = st.toggle(
            "KI Analyse",
            value=bool(s["ki_enabled"]),
            help="Heuristiken (z. B. M814→HS / M813→GS), wenn keine NPV (G54/G55) erkannt wird."
        )
        s["async_assign"] = st.toggle(
            "Asynchrone Zuordnung",
            value=bool(s["async_assign"]),
            help="Fallback: Wenn keine Marker gefunden werden: K1→SP4, K2→SP3."
        )
        s["search_toolname"] = st.toggle(
            "Werkzeugbezeichnung (T = …)",
            value=bool(s["search_toolname"]),
            help="Werkzeugname aus 'T = ...' Zeilen extrahieren."
        )
        s["search_edge"] = st.toggle(
            "Schneidennummer (TC(...))",
            value=bool(s["search_edge"]),
            help="Schneidennummer aus 'TC(n)' extrahieren."
        )

    c1, c2 = st.columns([1,3])
    with c1:
        if st.button("💾 Speichern", type="primary"):
            save_settings_to_db(st.session_state["user"], s)
            st.success("Settings gespeichert.")
    with c2:
        if st.button("↩️ Auf Standard zurücksetzen"):
            defaults = get_default_settings()
            st.session_state[SETTINGS_KEY] = defaults
            save_settings_to_db(st.session_state["user"], defaults)
            st.info("Auf Standard zurückgesetzt und gespeichert.")

def is_admin_current_user() -> bool:
    u = st.session_state.get("user")
    info = get_user(u) if u else None
    return bool(info and info.get("role") == "admin")

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

    # Liste
    with tabs[0]:
        users = list_users()
        if not users:
            st.info("Keine Benutzer vorhanden.")
        else:
            for row in users:
                col1, col2, col3, col4, col5, col6 = st.columns([3,2,3,3,3,2])
                col1.write(f"**{row['username']}**")
                col2.write(row['role'])
                col3.write("🔁 Wechsel nötig" if row.get('must_change_password') else "✅ gesetzt")
                col4.write(row.get('created_at'))

                with col5:
                    with st.popover("Passwort setzen (ohne Zwang)", use_container_width=True):
                        new_pw = st.text_input(
                            f"Neues Passwort für {row['username']}",
                            type="password", key=f"pw_{row['username']}"
                        )
                        if st.button("Speichern", key=f"pwbtn_{row['username']}"):
                            if new_pw:
                                ok, msg = set_user_password(row['username'], new_pw, clear_must_change=False)
                                st.success(msg) if ok else st.error(msg)
                            else:
                                st.error("Bitte Passwort eingeben.")

                with col6:
                    if st.button("Löschen", key=f"del_inline_{row['username']}"):
                        ok, msg = delete_user(row['username'])
                        if ok:
                            st.success(msg); st.rerun()
                        else:
                            st.warning(msg)

            st.markdown("---")
            st.subheader("Rolle ändern")
            sel_user = st.selectbox("Benutzer", [u["username"] for u in users], key="role_sel_user")
            sel_role = st.radio("Rolle", ["user", "admin"], horizontal=True, key="role_sel_role")
            if st.button("Rolle speichern", key="save_role_btn"):
                if sel_user == st.session_state.get("user") and sel_role != "admin":
                    st.error("Du kannst dir nicht selbst Admin entziehen.")
                else:
                    set_user_role(sel_user, sel_role); st.success("Rolle aktualisiert."); st.rerun()

            st.markdown("---")
            st.subheader("🗑️ Danger Zone – Benutzer löschen")
            del_user = st.selectbox("Benutzer auswählen", [u["username"] for u in users], key="danger_del_user")
            c1, c2 = st.columns([1, 3])
            with c1:
                confirm = st.checkbox("Ich bestätige das Löschen", key="danger_del_confirm")
            with c2:
                if st.button("Benutzer endgültig löschen", type="primary", key="danger_del_btn"):
                    if not confirm:
                        st.error("Bitte erst die Checkbox bestätigen.")
                    else:
                        ok, msg = delete_user(del_user)
                        if ok:
                            st.success(msg); st.rerun()
                        else:
                            st.warning(msg)

    # Neu anlegen (Temp-PW)
    with tabs[1]:
        st.info("Neuer Nutzer bekommt ein temporäres Passwort und muss es beim ersten Login ändern.")
        nu = st.text_input("Benutzername (neu)", key="admin_new_user")
        npw1 = st.text_input("Temporäres Passwort", type="password", key="admin_new_pw1")
        npw2 = st.text_input("Temporäres Passwort (wiederholen)", type="password", key="admin_new_pw2")
        nrole = st.radio("Rolle", ["user", "admin"], horizontal=True, index=0, key="admin_new_role")
        if st.button("Benutzer erstellen", key="admin_create_user_btn"):
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
            # Settings für Benutzer initial laden
            st.session_state[SETTINGS_KEY] = None
            get_settings()
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

    # Passwortwechsel erzwingen
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





