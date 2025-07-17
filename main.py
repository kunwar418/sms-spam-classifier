import streamlit as st
import requests
from dotenv import load_dotenv
import os

# Load the API key
load_dotenv()
FASTAPI_URL = "http://localhost:8000/predict"  # Update this if deployed elsewhere

st.set_page_config(page_title="SMS Spam Classifier", layout="centered")
st.title("📱 SMS Spam Classifier")
st.write( "This app uses an ensemble model along with the Google Safe Browsing API to detect spam messages. ")

# Text input
sms = st.text_area("Enter your message:", height=150)

if st.button("🔍 Check Spam"):
    if not sms.strip():
        st.warning("Please enter a message.")
    else:
        try:
            with st.spinner("Analyzing..."):
                response = requests.post(FASTAPI_URL, json={"text": sms})
                result = response.json()

                if result["result"] == "spam":
                    st.error("🚫 This message is classified as **SPAM**.")
                else:
                    st.success("✅ This message is classified as **HAM** (Safe).")

                # Show model confidences (Optional)
                with st.expander("🔍 Model Details"):
                    st.json(result)
        except Exception as e:
            st.error(f"Failed to contact API: {e}")
