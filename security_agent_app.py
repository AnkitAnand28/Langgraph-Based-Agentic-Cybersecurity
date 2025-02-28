import streamlit as st
import json
import time
from datetime import datetime
from security_agent import run_cybersecurity_agent, ScopeConfig

st.set_page_config(page_title="Cybersecurity Agent", layout="wide")

st.title("🔒 AI-Powered Cybersecurity Scanner")
st.markdown("""
Automate security scans with AI-driven tools like Nmap, Gobuster, FFUF, and SQLMap.
This tool helps identify vulnerabilities and generate comprehensive reports.
""")

st.sidebar.header("🔍 Scan Configuration")
target = st.sidebar.text_input("Enter Target Domain/IP",key="placeholder")
allowed_domains = st.sidebar.text_input("Allowed Domains (comma-separated)", key="placeholder1")
allowed_ip_ranges = st.sidebar.text_input("Allowed IP Ranges (comma-separated)", key="placeholder2")

scope = ScopeConfig(
    domains=[d.strip() for d in allowed_domains.split(",")],
    ip_ranges=[ip.strip() for ip in allowed_ip_ranges.split(",")]
)

if st.sidebar.button("🚀 Run Security Scan"):
    st.sidebar.success("Running security scans... Please wait.")
    
    with st.spinner("🔍 Running security scan... This may take a while."):
        start_time = time.time()

        result = run_cybersecurity_agent(
            f"Scan the {target} for open ports and directories",
            scope
        )

        end_time = time.time()
        execution_time = round(end_time - start_time, 2)

    st.subheader("📝 Execution Logs")
    with st.expander("📜 View Logs"):
        for log in result.execution_logs:
            st.write(f"**{log['timestamp']}** - {log['event']}")

    st.subheader("📋 Security Scan Report")
    if result.final_report:
        st.json(result.final_report)

        st.download_button(
            label="📥 Download Report",
            data=json.dumps(result.final_report, indent=2),
            file_name=f"security_scan_report_{target}.json",
            mime="application/json"
        )
    else:
        st.warning("⚠️ No final report generated.")

    st.sidebar.info(f"✅ Scan Completed in {execution_time} seconds.")
