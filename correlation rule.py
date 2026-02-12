import streamlit as st
import json
import pandas as pd
from falconpy import CorrelationRules
from datetime import datetime
import base64

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="Correlation Rules Export", layout="wide")
st.title("📤 CrowdStrike Correlation Rules – Full Export")

# ---------------- SIDEBAR AUTH ----------------
st.sidebar.header("🔐 API Authentication")

client_id = st.sidebar.text_input("Client ID", type="password")
client_secret = st.sidebar.text_input("Client Secret", type="password")

# Session state flag
if "auth_valid" not in st.session_state:
    st.session_state.auth_valid = False

# Submit button for authentication
if st.sidebar.button("Submit API Credentials"):

    if not client_id or not client_secret:
        st.sidebar.error("Both fields are required.")
    else:
        try:
            falcon_test = CorrelationRules(
                client_id=client_id,
                client_secret=client_secret
            )

            # Simple validation call
            test = falcon_test.queries_rules_get_v1(limit=1)

            if test["status_code"] == 200:
                st.session_state.auth_valid = True
                st.sidebar.success("Authentication Successful")
            else:
                st.sidebar.error("Authentication Failed")
                st.sidebar.json(test)

        except Exception as e:
            st.sidebar.error(f"Error: {e}")

# Stop execution if auth not validated
if not st.session_state.auth_valid:
    st.info("Provide API credentials and click Submit.")
    st.stop()

# Create falcon instance after validation
falcon = CorrelationRules(
    client_id=client_id,
    client_secret=client_secret
)

# ---------------- FILTER SECTION ----------------
st.subheader("⚙️ Export Filters")

status_option = st.selectbox(
    "Rule Status",
    ["All", "active", "inactive"]
)

additional_filter = st.text_input(
    "Additional FQL Filter (Optional)",
    placeholder='severity:>=50'
)

# Build FQL filter
fql_parts = []

if status_option != "All":
    fql_parts.append(f'status:"{status_option}"')

if additional_filter:
    fql_parts.append(additional_filter)

final_fql = "+".join(fql_parts)

st.code(final_fql if final_fql else "No Filter Applied")

# ---------------- EXPORT BUTTON ----------------
if st.button("🚀 Export All Rules (Full Details)"):

    all_rule_ids = []
    offset = 0
    limit = 100

    # -------- STEP 1: Fetch Rule IDs --------
    with st.spinner("Fetching rule IDs..."):

        while True:
            response = falcon.queries_rules_get_v1(
                filter=final_fql if final_fql else None,
                offset=offset,
                limit=limit
            )

            if response["status_code"] != 200:
                st.error("Failed retrieving rule IDs")
                st.json(response)
                st.stop()

            ids = response["body"]["resources"]
            all_rule_ids.extend(ids)

            if len(ids) < limit:
                break

            offset += limit

    if not all_rule_ids:
        st.warning("No rules found.")
        st.stop()

    st.success(f"Found {len(all_rule_ids)} rules.")

    # -------- STEP 2: Fetch Full Rule Details --------
    full_rules = []

    with st.spinner("Fetching full rule details..."):

        for i in range(0, len(all_rule_ids), 100):
            batch = all_rule_ids[i:i+100]

            details = falcon.entities_latest_rules_get_v1(
                rule_ids=batch
            )

            if details["status_code"] == 200:
                full_rules.extend(details["body"]["resources"])
            else:
                st.error("Error retrieving rule details")
                st.json(details)
                st.stop()

    # -------- STEP 3: Export --------
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"correlation_rules_full_export_{timestamp}.json"

    export_json = json.dumps(full_rules, indent=2)

    b64 = base64.b64encode(export_json.encode()).decode()
    download_link = f'<a href="data:file/json;base64,{b64}" download="{filename}">📥 Download JSON Export</a>'

    st.success("Export Completed Successfully")
    st.markdown(download_link, unsafe_allow_html=True)

    # -------- SUMMARY TABLE --------
    df = pd.json_normalize(full_rules)

    summary_columns = [
        "name",
        "severity",
        "status",
        "tactic",
        "technique",
        "last_updated_on"
    ]

    available_cols = [c for c in summary_columns if c in df.columns]

    st.subheader("📊 Rule Summary")
    st.dataframe(df[available_cols])