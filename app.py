import streamlit as st
import requests

st.set_page_config(page_title="Ticket Scam Hunter", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
.topbar {background: #1a237e; padding: 16px 24px; border-radius: 12px; margin-bottom: 24px; display: flex; align-items: center; gap: 12px;}
.verdict-scam {background: #FCEBEB; color: #A32D2D; padding: 6px 16px; border-radius: 20px; font-weight: 500; display: inline-block;}
.verdict-suspicious {background: #FAEEDA; color: #854F0B; padding: 6px 16px; border-radius: 20px; font-weight: 500; display: inline-block;}
.verdict-legit {background: #EAF3DE; color: #3B6D11; padding: 6px 16px; border-radius: 20px; font-weight: 500; display: inline-block;}
.flag-box {background: #FCEBEB; color: #A32D2D; padding: 8px 14px; border-radius: 8px; margin: 4px 0; font-size: 14px;}
.trust-box {background: #EAF3DE; color: #3B6D11; padding: 8px 14px; border-radius: 8px; margin: 4px 0; font-size: 14px;}
.recent-item {padding: 8px 0; border-bottom: 1px solid #eee; font-size: 13px;}
</style>
""", unsafe_allow_html=True)

API_URL = "https://ticket-scam-hunter.onrender.com"

st.markdown("""
<div class="topbar">
  <span style="color:white; font-size:24px;">🛡️</span>
  <div>
    <div style="color:white; font-size:18px; font-weight:600;">Ticket Scam Hunter</div>
    <div style="color:#90caf9; font-size:13px;">FIFA World Cup 2026 fraud detection</div>
  </div>
</div>
""", unsafe_allow_html=True)

st.markdown("### Is this ticket site safe?")
st.caption("Paste any ticket website URL below. Our AI agent analyzes it for fraud signals using Google Gemini and Elasticsearch.")

col1, col2 = st.columns([5, 1])
with col1:
    url = st.text_input("", placeholder="https://cheapworldcuptickets2026.com", label_visibility="collapsed")
with col2:
    scan = st.button("🔍 Scan", use_container_width=True)

if scan and url:
    with st.spinner("Analyzing with Gemini AI + Elasticsearch..."):
        try:
            r = requests.post(f"{API_URL}/v1/scans", json={"url": url}, timeout=120)
            res = r.json()
            verdict = res.get("verdict", "UNKNOWN")
            score = res.get("score", 0)
            reasons = res.get("reasons", [])
            red_flags = res.get("red_flags", [])
            trust_signals = res.get("trust_signals", [])

            st.divider()
            c1, c2, c3 = st.columns([2, 1, 1])
            with c1:
                css = "verdict-scam" if verdict=="SCAM" else "verdict-suspicious" if verdict=="SUSPICIOUS" else "verdict-legit"
                icon = "🔴" if verdict=="SCAM" else "🟡" if verdict=="SUSPICIOUS" else "🟢"
                st.markdown(f'<span class="{css}">{icon} {verdict}</span>', unsafe_allow_html=True)
            with c2:
                st.metric("Scam Score", f"{score}/10")
            with c3:
                cached = res.get("cached", False)
                st.metric("Source", "Cached" if cached else "Fresh scan")

            st.progress(float(score)/10)

            if reasons:
                st.markdown("**Analysis**")
                for r in reasons:
                    st.write(f"• {r}")

            if red_flags:
                st.markdown("**Red Flags**")
                for f in red_flags:
                    st.markdown(f'<div class="flag-box">⚠️ {f}</div>', unsafe_allow_html=True)

            if trust_signals:
                st.markdown("**Trust Signals**")
                for t in trust_signals:
                    st.markdown(f'<div class="trust-box">✅ {t}</div>', unsafe_allow_html=True)

        except Exception as e:
            st.error(f"Error: {e}")

elif scan and not url:
    st.warning("Please enter a URL.")

with st.sidebar:
    st.markdown("### 🕵️ Recent Scans")
    try:
        r = requests.get(f"{API_URL}/v1/scans", timeout=10)
        data = r.json()
        for item in data.get("results", [])[:5]:
            v = item.get("verdict","")
            icon = "🔴" if v=="SCAM" else "🟡" if v=="SUSPICIOUS" else "🟢"
            url_short = item.get("url","")[:35] + "..."
            st.markdown(f'<div class="recent-item">{icon} {url_short}<br><small>Score: {item.get("score")}/10</small></div>', unsafe_allow_html=True)
    except:
        st.caption("No recent scans yet.")

    st.divider()
    st.caption("Powered by Google Gemini + Elasticsearch")
    st.markdown("[GitHub Repo](https://github.com/thanprasad123/ticket-scam-hunter)")
