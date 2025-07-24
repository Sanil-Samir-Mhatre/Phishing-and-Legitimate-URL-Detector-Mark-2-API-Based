
import streamlit as st
import requests
import base64
import time
import os
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv(dotenv_path="phish.env")
API_KEY = os.getenv("VT_API_KEY")

def submit_url_to_virustotal(url):
    headers = {"x-apikey": API_KEY}
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    return response.json()["data"]["id"] if response.status_code == 200 else None

def get_scan_report(analysis_id):
    headers = {"x-apikey": API_KEY}
    for _ in range(20):  # Retry for up to ~20 seconds
        response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if response.status_code == 200:
            status = response.json()["data"]["attributes"]["status"]
            if status == "completed":
                return response.json()
        time.sleep(1)
    return None

# Streamlit UI
st.set_page_config(page_title="Phishing URL Detector", page_icon=" Search ")
st.title("Phishing Link Detector (Mark 2)")
st.write("Check whether a URL is safe or malicious using VirusTotal's threat engines.")

# Input URL
url = st.text_input("Enter a URL to scan")

# Scan Button
if st.button("Scan URL"):
    if not API_KEY:
        st.error("API key not found. Please create a `.env` file with your VirusTotal key.")
    elif not url.strip():
        st.warning("Please enter a valid URL.")
    else:
        with st.spinner("Submitting and scanning the URL..."):
            analysis_id = submit_url_to_virustotal(url)
            if analysis_id:
                report = get_scan_report(analysis_id)
                if report:
                    stats = report["data"]["attributes"]["stats"]
                    harmless = stats.get("harmless", 0)
                    suspicious = stats.get("suspicious", 0)
                    malicious = stats.get("malicious", 0)

                    st.subheader("Scan Results")
                    st.write(f"- **Harmless engines:** {harmless}")
                    st.write(f"- **Suspicious engines:** {suspicious}")
                    st.write(f"- **Malicious engines:** {malicious}")

                    if malicious > 0 or suspicious > 2:
                        st.error("Verdict: **Phishing / Malicious**")
                    else:
                        st.success("Verdict: **Looks Legitimate**")
                else:
                    st.error("Failed to retrieve the scan report.")
            else:
                st.error("Failed to submit URL for scanning.")
