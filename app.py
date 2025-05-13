import streamlit as st
import pandas as pd
import requests
from datetime import datetime

st.set_page_config(page_title="Sentinel Threat Automation", layout="wide")
st.title("🔐 Microsoft Sentinel Threat Response Automation")

# Load secrets
sentinel_api_url = st.secrets["SENTINEL_API_URL"]
auth_token = st.secrets["SENTINEL_AUTH_TOKEN"]
playbook_activation_url = st.secrets["PLAYBOOK_ACTIVATION_URL"]
playbook_activation_auth_token = st.secrets["PLAYBOOK_ACTIVATION_AUTH_TOKEN"]

# Sidebar filters
st.sidebar.header("Filters")
min_anomaly_threshold = st.sidebar.slider("Anomaly threshold", 1, 100, 10)
log_date_range = st.sidebar.date_input("Log date range", [])

# Step 1: Ingest logs
st.header("🧪 Step 1: Ingest Sentinel Logs")

if st.button("Ingest Logs"):
    headers = {'Authorization': f'Bearer {auth_token}'}
    response = requests.get(sentinel_api_url, headers=headers)
    logs = response.json()
    df_logs = pd.DataFrame(logs)
    st.session_state.logs = df_logs
    st.success("Logs ingested successfully!")
    st.dataframe(df_logs)

# Step 2: Analyze threats
st.header("📊 Step 2: Analyze Threats")

def match_indicators(logs, file_path):
    indicators = pd.read_csv(file_path)
    matches = logs[logs.astype(str).apply(lambda x: x.str.contains('|'.join(indicators['value']), case=False)).any(axis=1)]
    return matches

def detect_anomalies(logs, threshold):
    counts = logs['ip'].value_counts()
    anomalies = counts[counts > threshold].reset_index()
    anomalies.columns = ['ip', 'count']
    return anomalies

if st.button("Run Threat Analysis"):
    if "logs" not in st.session_state:
        st.warning("Please ingest logs first.")
    else:
        matches = match_indicators(st.session_state.logs, "indicators.csv")
        anomalies = detect_anomalies(st.session_state.logs, min_anomaly_threshold)
        st.session_state.matches = matches
        st.session_state.anomalies = anomalies

        st.success("Threats analyzed.")
        st.subheader("🔍 Matched Indicators")
        st.dataframe(matches)
        st.subheader("🚨 Anomalous IPs")
        st.dataframe(anomalies)

# Step 3: Generate and activate playbook
st.header("📜 Step 3: Generate & Activate Playbook")

def generate_playbook(summary, template_path):
    with open(template_path, "r") as f:
        template = f.read()
    return template.replace("{{THREAT_SUMMARY}}", summary)

def activate_playbook(payload):
    headers = {
        "Authorization": f"Bearer {playbook_activation_auth_token}",
        "Content-Type": "application/json"
    }
    response = requests.post(playbook_activation_url, headers=headers, json=payload)
    return response.status_code, response.text

if st.button("Generate & Activate Playbook"):
    if "matches" not in st.session_state:
        st.warning("Run analysis first.")
    else:
        summary = f"{len(st.session_state.matches)} matches, {len(st.session_state.anomalies)} anomalies."
        playbook_data = generate_playbook(summary, "playbook_template.json")
        code, text = activate_playbook({"summary": summary, "playbook": playbook_data})
        if code == 200:
            st.success("Playbook activated!")
        else:
            st.error(f"Playbook activation failed: {text}")

# Step 4: Notify team
st.header("📨 Step 4: Notify Team")

if st.button("Send Alert Email"):
    if "matches" in st.session_state:
        summary = f"{len(st.session_state.matches)} matched indicators, {len(st.session_state.anomalies)} anomalies"
        st.info(f"📧 Alert: {summary}")
    else:
        st.warning("Run analysis first.")

# Step 5: Reports
st.header("📈 Step 5: Dashboard & Export")

if "matches" in st.session_state:
    st.download_button("Download Threat Report (CSV)", st.session_state.matches.to_csv(index=False), "threat_report.csv")
    st.line_chart(st.session_state.logs["timestamp"].value_counts().sort_index())
else:
    st.info("Run steps above to populate the dashboard.")
