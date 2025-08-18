import streamlit as st

# Dummy-Userdaten (nur für Demo)
USER_CREDENTIALS = {
    "bratan": "1234",
    "admin": "secret",
    "marina" : "1234"
}

# Login-Funktion
def login():
    st.title("🔑 Login Beispiel")

    username = st.text_input("Benutzername")
    password = st.text_input("Passwort", type="password")

    if st.button("Login"):
        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
            st.session_state["logged_in"] = True
            st.session_state["user"] = username
            st.success(f"Willkommen, {username} 👋")
            # 👉 Sofort Hauptseite laden
            st.rerun()
        else:
            st.error("❌ Falscher Benutzername oder Passwort")

# Hauptseite
def main_page():
    st.title("🎉 Hauptseite")
    st.write(f"Hallo {st.session_state['user']}, du bist eingeloggt!")

    if st.button("Logout"):
        st.session_state["logged_in"] = False
        st.session_state["user"] = None
        st.experimental_rerun()

# Routing
def main():
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False

    if st.session_state["logged_in"]:
        main_page()
    else:
        login()

if __name__ == "__main__":
    main()
