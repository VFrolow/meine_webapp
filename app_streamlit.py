import streamlit as st

st.set_page_config(page_title="Login + Navigation", layout="wide")

# --- Demo-User (in echt: Hash + DB) ---
USER_CREDENTIALS = {
    "bratan": "1234",
    "admin": "secret"
}

# --- Seiten ---
def page_home():
    st.title("🏠 Home")
    st.write("Willkommen auf der Startseite!")

def page_auswertung():
    st.title("📊 Auswertung")
    st.write("Hier könnte deine Auswertung stehen…")
    # Beispiel-Content
    st.metric("KPI A", "42", "+5")
    st.progress(0.6)

def page_settings():
    st.title("⚙️ Settings")
    st.write("Einstellungen deines Accounts.")
    st.text_input("Anzeigename", value=st.session_state.get("user", ""))
    st.checkbox("Dark Mode (nur Demo)")

# --- Login ---
def login_view():
    st.title("🔑 Login")
    u = st.text_input("Benutzername")
    p = st.text_input("Passwort", type="password")
    if st.button("Login"):
        if u in USER_CREDENTIALS and USER_CREDENTIALS[u] == p:
            st.session_state.logged_in = True
            st.session_state.user = u
            st.session_state.page = "Home"  # Startseite nach Login
            st.rerun()
        else:
            st.error("❌ Falscher Benutzername oder Passwort")

# --- App-Routing ---
def app():
    # Session Defaults
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "page" not in st.session_state:
        st.session_state.page = "Home"

    if not st.session_state.logged_in:
        # Keine Sidebar vor dem Login
        login_view()
        return

    # --- Sidebar-Navigation (nur wenn eingeloggt) ---
    with st.sidebar:
        st.title("🧭 Navigation")
        choice = st.radio(
            "Menü",
            options=["Home", "Auswertung", "Settings"],
            index=["Home", "Auswertung", "Settings"].index(st.session_state.page),
            label_visibility="collapsed"
        )
        st.session_state.page = choice

        st.markdown("---")
        st.caption(f"Eingeloggt als **{st.session_state.user}**")
        if st.button("Logout"):
            st.session_state.logged_in = False
            st.session_state.user = None
            st.session_state.page = "Home"
            st.rerun()

    # --- Seiten-Content ---
    if st.session_state.page == "Home":
        page_home()
    elif st.session_state.page == "Auswertung":
        page_auswertung()
    elif st.session_state.page == "Settings":
        page_settings()

if __name__ == "__main__":
    app()
