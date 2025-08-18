import streamlit as st

def run_model(text: str) -> str:
    # Hier könnte dein eigener Code stehen
    return text.upper()

st.set_page_config(page_title="Meine Python App")
st.title("Meine Python App")

user_input = st.text_input("Gib Text ein")
if st.button("Ausführen"):
    if user_input:
        result = run_model(user_input)
        st.success(f"Ergebnis: {result}")
    else:
        st.warning("Bitte Text eingeben.")
