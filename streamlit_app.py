"""CyberShield SOC Operations Center - Streamlit Cloud Deployment Application."""
import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import streamlit as st
import plotly.io as pio

# Import CyberShield Flask App & Services
from app import create_app
from app.database.init_db import init_database
from app.extensions import db
from app.models.user import User
from app.models.auth_event import AuthEvent
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.models.network_event import NetworkEvent
from app.models.security_alert import SecurityAlert
from app.database.repositories import QueryRepository
from app.admin.dashboard_service import DashboardService
from app.auth.password_service import PasswordService


@st.cache_resource
def get_flask_app():
    """Create and cache the Flask application context."""
    app = create_app("production")
    with app.app_context():
        init_database()
    return app


def main():
    st.set_page_config(
        page_title="CyberShield — Security Operations Center",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    flask_app = get_flask_app()

    # Apply CyberShield Dark Cybersecurity Theme
    st.markdown("""
        <style>
        .stApp {
            background-color: #060c18;
            color: #e2e8f0;
        }
        .main-header {
            background: linear-gradient(135deg, rgba(13, 110, 253, 0.15) 0%, rgba(0, 210, 255, 0.05) 100%);
            border: 1px solid rgba(0, 210, 255, 0.25);
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 20px;
        }
        .metric-card {
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid rgba(0, 210, 255, 0.2);
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }
        .metric-value {
            font-size: 28px;
            font-weight: 700;
            color: #00d2ff;
        }
        .metric-label {
            font-size: 13px;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge-cyan {
            background-color: rgba(0, 210, 255, 0.15);
            color: #00d2ff;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            border: 1px solid rgba(0, 210, 255, 0.3);
        }
        .badge-green {
            background-color: rgba(16, 185, 129, 0.15);
            color: #10b981;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        </style>
    """, unsafe_allow_html=True)

    with flask_app.app_context():
        kpis = QueryRepository.get_kpis()
        total_events = kpis["total_logins"] + kpis["ids_events"]
        blocked_threats = kpis["failed_logins"] + kpis["mfa_failures"] + kpis["active_blocks"]
        mitigation_rate = round((blocked_threats / (total_events or 1)) * 100, 1)

        # Header Section
        st.markdown(f"""
            <div class="main-header">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                    <div>
                        <h1 style="margin: 0; font-size: 32px; color: #ffffff; display: flex; align-items: center; gap: 12px;">
                            🛡️ CyberShield <span style="font-size: 16px; color: #00d2ff; font-weight: normal; margin-left: 8px;">THE TRUST IDENTITY PERIMETER</span>
                        </h1>
                        <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 14px;">
                            Autonomous Intrusion Detection & Prevention System (IPS & IDS) • Real-Time SOC Telemetry Grid
                        </p>
                    </div>
                    <div style="display: flex; gap: 10px; align-items: center; margin-top: 10px;">
                        <span class="badge-green">● SENSOR: ONLINE</span>
                        <span class="badge-cyan">DEFENSE ENGINE: ACTIVE</span>
                    </div>
                </div>
            </div>
        """, unsafe_allow_html=True)

        # Top Executive KPI Cards
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        with c1:
            st.metric("Total Logins", kpis["total_logins"], "Active Telemetry")
        with c2:
            st.metric("Failed Logins", kpis["failed_logins"], "-Threat Signals", delta_color="inverse")
        with c3:
            st.metric("MFA Challenges", kpis["mfa_challenges"], "Layer-2 Intercept")
        with c4:
            st.metric("Suricata IDS", kpis["ids_events"], "Deep Signatures")
        with c5:
            st.metric("Active IPS Blocks", kpis["active_blocks"], "Contained")
        with c6:
            st.metric("Mitigation Rate", f"{mitigation_rate}%", "Defense Efficiency")

        st.write("")

        # Main Navigation Tabs
        tabs = st.tabs([
            "📊 Security Dashboard",
            "🚨 Incident Dossiers",
            "📡 Suricata IDS Stream",
            "🛡️ IPS Active Defenses",
            "🔐 Authentication Gateway",
            "ℹ️ Architecture & Credits"
        ])

        # TAB 1: SECURITY DASHBOARD
        with tabs[0]:
            col_chart1, col_chart2 = st.columns([3, 2])
            with col_chart1:
                st.subheader("📈 24-Hour Telemetry Activity Trend (Logins, Attacks & IDS)")
                try:
                    timeline_json = DashboardService.get_timeline_activity_chart()
                    fig_timeline = pio.from_json(timeline_json)
                    fig_timeline.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
                    st.plotly_chart(fig_timeline, use_container_width=True)
                except Exception as e:
                    st.info(f"Timeline telemetry active: {e}")

            with col_chart2:
                st.subheader("🍩 Authentication Outcomes")
                try:
                    auth_json = DashboardService.get_auth_outcomes_chart()
                    fig_auth = pio.from_json(auth_json)
                    fig_auth.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
                    st.plotly_chart(fig_auth, use_container_width=True)
                except Exception as e:
                    st.info(f"Outcome telemetry active: {e}")

            st.write("---")
            col_chart3, col_chart4 = st.columns(2)
            with col_chart3:
                st.subheader("🎯 Top Threat Attack Sources (IP Velocity)")
                try:
                    top_ips_json = DashboardService.get_top_threat_sources_chart()
                    fig_ips = pio.from_json(top_ips_json)
                    fig_ips.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
                    st.plotly_chart(fig_ips, use_container_width=True)
                except Exception as e:
                    st.info("Threat source telemetry ready.")

            with col_chart4:
                st.subheader("🏷️ Threat Category Classification")
                try:
                    cats_json = DashboardService.get_threat_category_chart()
                    fig_cats = pio.from_json(cats_json)
                    fig_cats.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
                    st.plotly_chart(fig_cats, use_container_width=True)
                except Exception as e:
                    st.info("Category telemetry ready.")

        # TAB 2: INCIDENT DOSSIERS
        with tabs[1]:
            st.subheader("🚨 Security Incident Response Queue (Correlated Threat Cases)")
            st.caption("Correlated high-fidelity threat cases grouped across authentication anomalies and Suricata network detections.")

            incidents = Incident.query.order_by(Incident.created_at.desc()).limit(20).all()
            if incidents:
                for inc in incidents:
                    status_color = "🔴" if inc.severity == "CRITICAL" else ("🟠" if inc.severity == "HIGH" else "🟡")
                    with st.expander(f"{status_color} [{inc.case_id or f'INC-{inc.id}'}] {inc.title} — {inc.status}"):
                        st.markdown(f"**Severity:** `{inc.severity}` | **Status:** `{inc.status}` | **Category:** `{inc.category}`")
                        st.markdown(f"**Attacker IP:** `{inc.attacker_ip}` | **Target:** `{inc.target_username or 'System'}`")
                        st.markdown(f"**Summary:** {inc.summary}")
                        if inc.evidence_summary:
                            st.code(inc.evidence_summary, language="json")
            else:
                st.success("No active critical incidents in queue. Sensor telemetry is clear.")

        # TAB 3: SURICATA IDS LOGS
        with tabs[2]:
            st.subheader("📡 Suricata Network Intrusion Detection Signatures (EVE JSON)")
            events = NetworkEvent.query.order_by(NetworkEvent.timestamp.desc()).limit(25).all()
            if events:
                data = []
                for ev in events:
                    data.append({
                        "Timestamp": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "",
                        "Signature": ev.signature,
                        "Category": ev.alert_category,
                        "Severity": ev.severity,
                        "Src IP": ev.src_ip,
                        "Dest IP": f"{ev.dest_ip}:{ev.dest_port}",
                        "Protocol": ev.proto
                    })
                st.dataframe(data, use_container_width=True)
            else:
                st.info("No network events recorded yet.")

        # TAB 4: IPS DEFENSES
        with tabs[3]:
            st.subheader("🛡️ Intrusion Prevention System (IPS) Defense Actions")
            actions = ResponseAction.query.order_by(ResponseAction.timestamp.desc()).limit(20).all()
            if actions:
                action_data = []
                for a in actions:
                    action_data.append({
                        "Timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else "",
                        "Action Type": a.action_type,
                        "Target": a.target,
                        "Status": a.status,
                        "Reason": a.reason,
                        "Dry Run": "SIMULATED" if a.is_dry_run else "LIVE"
                    })
                st.dataframe(action_data, use_container_width=True)
            else:
                st.info("No active defensive restrictions.")

        # TAB 5: AUTHENTICATION SIMULATOR
        with tabs[4]:
            st.subheader("🔐 Client Portal Authentication Simulator")
            st.caption("Test credentials against the Argon2id verification engine and view real-time defense response.")

            col_form, col_events = st.columns([1, 1])
            with col_form:
                with st.form("test_login_form"):
                    sim_user = st.text_input("Username", value="user01")
                    sim_pass = st.text_input("Password", type="password", value="UserSecure#2026!Passcode")
                    submitted = st.form_submit_button("Simulate Secure Sign-In")

                    if submitted:
                        user = User.query.filter_by(username=sim_user).first()
                        if not user:
                            st.error(f"❌ User '{sim_user}' does not exist in SQLite database.")
                        elif user.is_locked:
                            st.warning(f"🔒 Account '{sim_user}' is currently LOCKED by the IPS defense engine.")
                        elif PasswordService.verify_password(user.password_hash, sim_pass):
                            st.success(f"✅ Authentication SUCCESS for '{sim_user}'! Verified via Argon2id cryptographic seal.")
                        else:
                            st.error(f"❌ Authentication REJECTED for '{sim_user}'. Invalid password credentials.")

            with col_events:
                st.markdown("**Recent Authentication Stream:**")
                auth_recent = AuthEvent.query.order_by(AuthEvent.timestamp.desc()).limit(8).all()
                if auth_recent:
                    for ev in auth_recent:
                        badge = "🟢 SUCCESS" if ev.outcome == "SUCCESS" else "🔴 FAILED"
                        st.markdown(f"`{ev.timestamp.strftime('%H:%M:%S')}` **{ev.username_attempted}** ({ev.source_ip}) — {badge}")

        # TAB 6: ARCHITECTURE & CREDITS
        with tabs[5]:
            st.subheader("🏛️ CyberShield Architecture & SOC Leadership")
            st.markdown("""
                **Project Overview:**
                CyberShield is a next-generation security operations platform combining **Argon2id cryptographic identity verification**, **Adaptive Multi-Factor Authentication (MFA)**, **Suricata Network Intrusion Detection (IDS)**, and **Automated Threat Response (IPS)**.

                **Project Credits:**
                * **Administrator & SOC Lead:** Naveen Kumar
                * **Official Alert Channel:** `naveenlenin29@gmail.com`
                * **Cryptographic Standard:** Argon2id (RFC 9106)
                * **Network Engine:** Suricata EVE JSON Telemetry Stream
            """)


if __name__ == "__main__":
    main()
