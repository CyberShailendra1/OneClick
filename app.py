"""
OneClick APK Analyzer — full dashboard (Dark Theme)
  Layer 1: SHA-256 + VirusTotal signature lookup (with local caching)
  Layer 2: Androguard static feature extraction
  Layer 2b: Advanced static analysis (IOCs, obfuscation, native libs, SDKs, exported components)
  Layer 3: Random Forest risk scoring + rule-based AND SHAP explainability
  Layer 4: This Streamlit UI (single scan, batch scan, scan history, report export)
  Layer 5: Optional dynamic analysis (requires Android SDK/emulator on your machine)
"""

import os
import tempfile

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from modules.pipeline import scan_apk
from modules.ml_classifier import MODEL_PATH
from modules import database
from modules.report_generator import build_report_dict, export_json, export_pdf
from modules.dynamic_analysis import check_environment as check_dynamic_env, run_dynamic_analysis
from modules.phishing_scanner import scan_url, extract_urls_from_text, investigate_url
from modules.otp_guard import redact_message
from modules.scam_pattern_detector import detect_scam_patterns
from modules.scam_lookup import check_phone_number, check_upi_id, add_report
from modules.breach_checker import check_password_pwned, check_email_breaches

# --- Optional features that depend on system packages beyond plain pip installs.
# If these aren't set up (e.g. libzbar0 / tesseract-ocr missing), the app must
# still start - only the affected tab is disabled with a clear message,
# instead of the whole dashboard crashing on import. This was a real cause of
# "streamlit starts then immediately exits" bugs before this fix.
try:
    from modules.qr_scanner import scan_qr_image
    QR_AVAILABLE = True
    QR_IMPORT_ERROR = None
except ImportError as e:
    QR_AVAILABLE = False
    QR_IMPORT_ERROR = str(e)

try:
    from modules.ocr_scanner import scan_screenshot
    OCR_AVAILABLE = True
    OCR_IMPORT_ERROR = None
except ImportError as e:
    OCR_AVAILABLE = False
    OCR_IMPORT_ERROR = str(e)

try:
    from modules.shap_explainer import explain_with_shap
    SHAP_AVAILABLE = True
except Exception:
    SHAP_AVAILABLE = False

st.set_page_config(page_title="OneClick APK Analyzer", page_icon="🛡️", layout="wide")

# ---------------------------------------------------------------------------
# Design tokens — Dark "Cyber Guard" theme
# ---------------------------------------------------------------------------
BG_APP = "#070B14"        # page background — near-black navy
BG_SIDEBAR_TOP = "#0B1220"
BG_SIDEBAR_BOTTOM = "#050810"
BG_CARD = "#111A2E"        # card surface
BG_CARD_ALT = "#161F38"    # slightly raised surface (inputs, chips)
BORDER = "rgba(255,255,255,0.08)"
BORDER_SOFT = "rgba(255,255,255,0.05)"
TEXT_LIGHT = "#EAF0FA"
TEXT_MUTED = "#8C9BB5"
GREEN = "#22C55E"
AMBER = "#F59E0B"
RED = "#EF4444"
TEAL = "#22D3EE"
VIOLET = "#A78BFA"

LABEL_COLOR = {
    "Safe": GREEN, "Suspicious": AMBER, "Malicious": RED, "Known Threat": RED,
    "Likely Safe": GREEN, "Phishing / Malicious": RED,
}
LABEL_GLOW = {
    "Safe": "34,197,94", "Suspicious": "245,158,11", "Malicious": "239,68,68", "Known Threat": "239,68,68",
    "Likely Safe": "34,197,94", "Phishing / Malicious": "239,68,68",
}

PLOTLY_TEMPLATE = "plotly_dark"


def inject_css():
    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

        html, body, [class*="css"] {{ font-family: 'Inter', sans-serif; }}

        #MainMenu {{visibility: hidden;}}
        footer {{visibility: hidden;}}
        header[data-testid="stHeader"] {{background: transparent;}}

        .stApp {{
            background: radial-gradient(120% 100% at 15% 0%, #0E1730 0%, {BG_APP} 45%) fixed;
            color: {TEXT_LIGHT};
        }}

        h1, h2, h3, h4, h5, h6, p, span, label, div {{ color: {TEXT_LIGHT}; }}

        section[data-testid="stSidebar"] {{
            background: linear-gradient(180deg, {BG_SIDEBAR_TOP} 0%, {BG_SIDEBAR_BOTTOM} 100%);
            border-right: 1px solid {BORDER};
        }}
        section[data-testid="stSidebar"] * {{ color: #DCE6F5 !important; }}
        section[data-testid="stSidebar"] input {{
            color: {TEXT_LIGHT} !important;
            background: {BG_CARD_ALT} !important;
            border: 1px solid {BORDER} !important;
        }}
        section[data-testid="stSidebar"] hr {{ border-color: {BORDER}; }}

        .oc-hero {{
            background: linear-gradient(120deg, #0C1428 0%, #101B36 55%, #0B2233 100%);
            border: 1px solid {BORDER};
            border-radius: 18px;
            padding: 28px 34px;
            margin-bottom: 22px;
            box-shadow: 0 12px 34px rgba(0,0,0,0.45);
        }}
        .oc-hero h1 {{
            color: #FFFFFF; font-size: 30px; font-weight: 800; margin: 0 0 6px 0; letter-spacing: -0.3px;
        }}
        .oc-hero p {{ color: {TEXT_MUTED}; font-size: 14.5px; margin: 0; }}
        .oc-hero .oc-badges {{ margin-top: 14px; }}
        .oc-badge {{
            display: inline-block; background: rgba(255,255,255,0.05);
            border: 1px solid {BORDER}; color: #CFE3F5; font-size: 11.5px; font-weight: 600;
            padding: 5px 12px; border-radius: 999px; margin-right: 8px;
        }}

        .oc-section {{ display: flex; align-items: center; gap: 10px; margin: 20px 0 12px 0; }}
        .oc-section .oc-dot {{
            width: 32px; height: 32px; border-radius: 9px;
            display: flex; align-items: center; justify-content: center; font-size: 16px;
        }}
        .oc-section h3 {{ margin: 0; font-size: 17px; font-weight: 700; color: {TEXT_LIGHT}; }}

        .oc-card {{
            background: {BG_CARD};
            border-radius: 14px;
            padding: 18px 20px;
            box-shadow: 0 4px 18px rgba(0,0,0,0.35);
            border: 1px solid {BORDER};
            margin-bottom: 12px;
        }}

        div[data-testid="stMetric"] {{
            background: {BG_CARD};
            border-radius: 12px;
            padding: 14px 16px 10px 16px;
            box-shadow: 0 4px 14px rgba(0,0,0,0.3);
            border: 1px solid {BORDER};
        }}
        div[data-testid="stMetricLabel"] {{ color: {TEXT_MUTED} !important; font-weight: 600 !important; }}
        div[data-testid="stMetricValue"] {{ color: {TEXT_LIGHT} !important; }}

        .stTabs [data-baseweb="tab-list"] {{ gap: 6px; background: transparent; }}
        .stTabs [data-baseweb="tab"] {{
            background: {BG_CARD};
            border-radius: 10px 10px 0 0;
            padding: 10px 18px;
            font-weight: 600;
            color: {TEXT_MUTED};
            border: 1px solid {BORDER};
            border-bottom: none;
        }}
        .stTabs [aria-selected="true"] {{
            color: {TEAL} !important;
            background: {BG_CARD} !important;
            border-bottom: 3px solid {TEAL} !important;
        }}

        .stButton>button, .stDownloadButton>button {{
            border-radius: 10px; font-weight: 600;
            border: 1px solid {BORDER};
            padding: 0.5rem 1.1rem;
            background: {BG_CARD_ALT};
            color: {TEXT_LIGHT};
        }}
        .stButton>button[kind="primary"] {{
            background: linear-gradient(120deg, {TEAL} 0%, #0EA5E9 100%);
            color: #04121C; border: none;
        }}
        .stDownloadButton>button {{
            background: linear-gradient(120deg, {TEAL} 0%, #0EA5E9 100%);
            color: #04121C; border: none;
        }}
        .stDownloadButton>button:hover {{ filter: brightness(1.08); color: #04121C; }}

        [data-testid="stFileUploaderDropzone"] {{
            background: {BG_CARD};
            border: 1.5px dashed rgba(34,211,238,0.35);
            border-radius: 14px;
        }}
        [data-testid="stFileUploaderDropzone"] * {{ color: {TEXT_MUTED} !important; }}

        details {{
            background: {BG_CARD};
            border-radius: 10px;
            border: 1px solid {BORDER};
        }}
        details summary {{ color: {TEXT_LIGHT} !important; }}

        .stProgress > div > div {{ background-color: {TEAL}; }}

        [data-testid="stDataFrame"] {{ border-radius: 10px; overflow: hidden; }}

        code {{ color: {TEAL} !important; background: {BG_CARD_ALT} !important; }}

        .stAlert {{ background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 12px; }}

        hr {{ border-color: {BORDER}; }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def hero_banner():
    st.markdown(
        f"""
        <div class="oc-hero">
            <h1>🛡️ OneClick APK Analyzer</h1>
            <p>Multi-layer Android malware detection — signatures, static analysis, AI risk scoring &amp; optional dynamic analysis, all in one click.</p>
            <div class="oc-badges">
                <span class="oc-badge">🔎 VirusTotal Signatures</span>
                <span class="oc-badge">🧬 Static Analysis</span>
                <span class="oc-badge">🤖 AI Risk Scoring</span>
                <span class="oc-badge">🏃 Dynamic Analysis</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_header(icon: str, title: str, color: str = TEAL):
    st.markdown(
        f"""
        <div class="oc-section">
            <div class="oc-dot" style="background:{color}22;">{icon}</div>
            <h3>{title}</h3>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
def risk_gauge(label: str, score: float):
    """Curved semi-circle gauge showing the 0-100 risk score with colored zones."""
    color = LABEL_COLOR.get(label, TEXT_MUTED)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": "%", "font": {"size": 40, "color": TEXT_LIGHT}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": TEXT_MUTED, "tickfont": {"color": TEXT_MUTED, "size": 10}},
            "bar": {"color": color, "thickness": 0.28},
            "bgcolor": BG_CARD_ALT,
            "borderwidth": 0,
            "steps": [
                {"range": [0, 35], "color": "rgba(34,197,94,0.18)"},
                {"range": [35, 70], "color": "rgba(245,158,11,0.18)"},
                {"range": [70, 100], "color": "rgba(239,68,68,0.18)"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.9, "value": score},
        },
    ))
    fig.update_layout(
        template=PLOTLY_TEMPLATE, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        height=260, margin=dict(l=20, r=20, t=30, b=10),
        font={"color": TEXT_LIGHT},
    )
    st.plotly_chart(fig, width='stretch', config={"displayModeBar": False})
    st.markdown(
        f"<div style='text-align:center;margin-top:-10px;'>"
        f"<span style='background:{color}22;color:{color};padding:5px 16px;border-radius:999px;"
        f"font-weight:700;font-size:15px;'>{label}</span></div>",
        unsafe_allow_html=True,
    )


def permission_pie(features: dict):
    """Donut chart categorizing requested permissions into risk-relevant buckets."""
    perms = features.get("requested_permissions", [])
    if not perms:
        st.caption("No permissions declared.")
        return

    categories = {
        "Messaging (SMS)": ["SMS", "MMS"],
        "Camera / Mic": ["CAMERA", "RECORD_AUDIO"],
        "Location": ["LOCATION"],
        "Contacts / Calendar": ["CONTACTS", "CALENDAR", "CALL_LOG"],
        "Storage": ["STORAGE"],
        "Phone / Call": ["PHONE", "CALL_PHONE"],
        "System / Admin": ["SYSTEM_ALERT_WINDOW", "ACCESSIBILITY", "DEVICE_ADMIN", "INSTALL_PACKAGES", "BOOT_COMPLETED"],
        "Network": ["INTERNET", "NETWORK_STATE"],
    }
    counts = {k: 0 for k in categories}
    other = 0
    for p in perms:
        matched = False
        for cat, keywords in categories.items():
            if any(kw in p for kw in keywords):
                counts[cat] += 1
                matched = True
                break
        if not matched:
            other += 1
    if other:
        counts["Other"] = other
    counts = {k: v for k, v in counts.items() if v > 0}

    palette = [TEAL, VIOLET, AMBER, RED, GREEN, "#38BDF8", "#F472B6", "#FACC15", "#94A3B8"]
    fig = go.Figure(go.Pie(
        labels=list(counts.keys()), values=list(counts.values()), hole=0.55,
        marker=dict(colors=palette[:len(counts)], line=dict(color=BG_APP, width=2)),
        textfont={"color": TEXT_LIGHT, "size": 11},
        textinfo="label+value",
    ))
    fig.update_layout(
        template=PLOTLY_TEMPLATE, paper_bgcolor="rgba(0,0,0,0)", showlegend=False,
        height=300, margin=dict(l=10, r=10, t=10, b=10),
        annotations=[dict(text=f"{len(perms)}<br>total", x=0.5, y=0.5, font_size=16,
                           font_color=TEXT_LIGHT, showarrow=False)],
    )
    st.plotly_chart(fig, width='stretch', config={"displayModeBar": False})


def shap_radar(features: dict):
    """Spline (curved) radar chart of the top SHAP feature attributions for this scan."""
    try:
        impacts = explain_with_shap(features, top_k=8)
    except Exception as e:
        st.caption(f"SHAP chart unavailable: {e}")
        return

    labels = [i["feature"].replace("_", " ") for i in impacts]
    values = [i["impact"] for i in impacts]
    # close the loop for a continuous curve
    labels_closed = labels + [labels[0]]
    values_closed = values + [values[0]]

    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=values_closed, theta=labels_closed, fill="toself", fillcolor="rgba(34,211,238,0.18)",
        line=dict(color=TEAL, shape="spline", width=2.5),
        marker=dict(size=5, color=TEAL),
        name="SHAP impact",
    ))
    fig.update_layout(
        template=PLOTLY_TEMPLATE, paper_bgcolor="rgba(0,0,0,0)",
        polar=dict(
            bgcolor="rgba(255,255,255,0.02)",
            radialaxis=dict(showticklabels=False, gridcolor=BORDER, linecolor=BORDER),
            angularaxis=dict(gridcolor=BORDER, linecolor=BORDER, tickfont={"size": 10, "color": TEXT_MUTED}),
        ),
        height=340, margin=dict(l=40, r=40, t=20, b=20), showlegend=False,
    )
    st.plotly_chart(fig, width='stretch', config={"displayModeBar": False})
    st.caption("Outward = pushed toward Malicious · Inward = pushed toward Safe")


def verdict_donut(rows_or_records):
    """Donut chart of Safe/Suspicious/Malicious counts, used in batch scan + history."""
    counts = {"Safe": 0, "Suspicious": 0, "Malicious": 0, "Known Threat": 0}
    for v in rows_or_records:
        if v in counts:
            counts[v] += 1
    counts["Malicious"] += counts.pop("Known Threat")
    counts = {k: v for k, v in counts.items() if v > 0}
    if not counts:
        st.caption("No data yet.")
        return

    colors = [LABEL_COLOR.get(k, TEXT_MUTED) for k in counts]
    fig = go.Figure(go.Pie(
        labels=list(counts.keys()), values=list(counts.values()), hole=0.6,
        marker=dict(colors=colors, line=dict(color=BG_APP, width=2)),
        textfont={"color": TEXT_LIGHT, "size": 12}, textinfo="label+percent",
    ))
    total = sum(counts.values())
    fig.update_layout(
        template=PLOTLY_TEMPLATE, paper_bgcolor="rgba(0,0,0,0)", showlegend=False,
        height=300, margin=dict(l=10, r=10, t=10, b=10),
        annotations=[dict(text=f"{total}<br>scans", x=0.5, y=0.5, font_size=16,
                           font_color=TEXT_LIGHT, showarrow=False)],
    )
    st.plotly_chart(fig, width='stretch', config={"displayModeBar": False})


def risk_trend_curve(records: list):
    """Smooth spline curve of risk score over time, from scan history."""
    if len(records) < 2:
        st.caption("Need at least 2 scans to show a trend.")
        return
    ordered = list(reversed(records))
    x = [r["timestamp"][:19].replace("T", " ") for r in ordered]
    y = [r["risk_score"] if r["risk_score"] is not None else 0 for r in ordered]
    colors = [LABEL_COLOR.get(r["verdict"], TEAL) for r in ordered]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=x, y=y, mode="lines+markers", line=dict(color=TEAL, shape="spline", width=3),
        marker=dict(size=8, color=colors, line=dict(color=BG_APP, width=1)),
        fill="tozeroy", fillcolor="rgba(34,211,238,0.10)",
    ))
    fig.update_layout(
        template=PLOTLY_TEMPLATE, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        height=300, margin=dict(l=10, r=10, t=20, b=40),
        xaxis=dict(showgrid=False, tickfont={"size": 9, "color": TEXT_MUTED}, tickangle=-30),
        yaxis=dict(range=[0, 100], gridcolor=BORDER, title="Risk Score", tickfont={"color": TEXT_MUTED}),
    )
    st.plotly_chart(fig, width='stretch', config={"displayModeBar": False})


# ---------------------------------------------------------------------------
# Result rendering
# ---------------------------------------------------------------------------
def mitigation_advice(label: str) -> str:
    return {
        "Known Threat": "⚠️ Delete this file immediately — it's a confirmed known threat on VirusTotal.",
        "Malicious": "⚠️ Delete this file immediately and do not install it. Consider a full device scan if it was already installed.",
        "Suspicious": "⚠️ Proceed with caution. Review the permissions below; only install if you trust the source and understand why it needs these permissions.",
        "Safe": "✅ No significant threats detected. App appears safe based on static analysis.",
    }.get(label, "No advice available.")


def render_single_result(result: dict, filename: str):
    vt = result.get("vt_result") or {}

    section_header("🔍", "Layer 1 — Signature-Based Scan", TEAL)
    st.code(result["sha256"], language=None)

    if vt.get("error") == "NO_API_KEY":
        st.warning("No VirusTotal API key provided — skipping Layer 1, proceeding to static analysis (Layer 2).")
    elif vt.get("error"):
        st.warning(f"VirusTotal lookup issue: {vt['error']} — proceeding to Layer 2.")
    elif vt.get("found"):
        st.error(f"🔴 KNOWN THREAT — flagged malicious by {vt['malicious']}/{vt['total_engines']} security engines on VirusTotal.")
        st.markdown(f"[View full VirusTotal report]({vt['permalink']})")
        st.markdown("**Mitigation:** Delete this file immediately.")
        return
    else:
        st.success("Hash not found in VirusTotal's database — not a known signature. Proceeding to static analysis (possible zero-day).")

    if result.get("error"):
        st.error(result["error"])
        return

    features = result["features"]
    section_header("🧬", "Layer 2 — Static Feature Extraction", TEAL)

    fake_app = result.get("fake_app_check") or {}
    if fake_app.get("is_suspicious"):
        st.error(f"🚨 Possible fake/clone of **{fake_app['matched_brand']}** — this looks like it's impersonating a known banking/payment app.")
        for reason in fake_app["reasons"]:
            st.markdown(f"- {reason}")

    col1, col2 = st.columns([1.3, 1])
    with col1:
        c1, c2, c3 = st.columns(3)
        c1.metric("Package", (features["package_name"] or "Unknown")[:18])
        c2.metric("Dangerous Permissions", features["num_dangerous_permissions"])
        c3.metric("Suspicious API Calls", features["num_suspicious_apis"])

        with st.expander("📋 Full permission list"):
            st.write(features["requested_permissions"] or "None declared")
        with st.expander("⚠️ Suspicious API calls detected"):
            st.write(features["suspicious_apis"] or "None detected")
        with st.expander("📄 Certificate & metadata"):
            st.json({
                "self_signed": features["is_self_signed"],
                "debuggable": features["is_debuggable"],
                "cert_issuer": features["cert_issuer"],
                "min_sdk": features["min_sdk"],
                "target_sdk": features["target_sdk"],
            })
    with col2:
        st.markdown("**Permission Breakdown**")
        permission_pie(features)

    adv = result.get("advanced") or {}
    if adv and not adv.get("error"):
        section_header("🧪", "Layer 2b — Advanced Static Analysis", AMBER)
        obf = adv.get("obfuscation", {})
        iocs = adv.get("iocs", {})
        native = adv.get("native_libs", {})
        exported = adv.get("exported_components", {})
        sdks = adv.get("detected_sdks", [])

        c1, c2, c3 = st.columns(3)
        c1.metric("Max entropy (obfuscation)", obf.get("max_entropy", "-"), help="Above ~7.2 suggests packed/encrypted code")
        c2.metric("URLs/IPs found", f"{iocs.get('num_urls', 0)}/{iocs.get('num_ips', 0)}")
        c3.metric("Native libraries", native.get("num_native_libs", 0))

        if obf.get("likely_obfuscated"):
            st.warning(f"⚠️ {obf.get('note')}")
        if iocs.get("urls_found"):
            with st.expander(f"🌐 URLs found in binary ({len(iocs['urls_found'])})"):
                st.write(iocs["urls_found"])
        if iocs.get("ips_found"):
            with st.expander(f"🖧 IP addresses found ({len(iocs['ips_found'])})"):
                st.write(iocs["ips_found"])
        if exported.get("num_exported_unprotected", 0) > 0:
            st.warning(f"⚠️ {exported['num_exported_unprotected']} exported component(s) without permission protection.")
            with st.expander("Exported unprotected components"):
                st.write(exported["exported_unprotected_components"])
        if sdks:
            st.info("📦 Third-party SDKs detected: " + ", ".join(sdks))

    ml_result = result.get("ml_result")
    if not ml_result:
        return

    section_header("🤖", "Layer 3 — AI Risk Scoring", AMBER)
    c1, c2, c3 = st.columns([1, 1, 1.3])
    with c1:
        st.markdown("**Risk Meter**")
        risk_gauge(ml_result["label"], ml_result["risk_score"])
    with c2:
        if SHAP_AVAILABLE:
            st.markdown("**Feature Impact (SHAP)**")
            shap_radar(features)
        else:
            st.caption("SHAP not installed — showing rule-based reasons only.")
    with c3:
        st.markdown("**🔎 Explainability — why this verdict?**")
        for reason in ml_result["reasons"]:
            st.markdown(f"- {reason}")
        st.markdown("**🩺 Mitigation advice**")
        st.info(mitigation_advice(ml_result["label"]))

    section_header("📄", "Export Report", GREEN)
    report = build_report_dict(
        filename=filename, sha256=result["sha256"], layer1=vt,
        features=features, ml_result=ml_result, advanced=adv,
    )
    colA, colB = st.columns(2)
    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = export_json(report, os.path.join(tmpdir, "report.json"))
        pdf_path = export_pdf(report, os.path.join(tmpdir, "report.pdf"))
        with open(json_path, "rb") as f:
            colA.download_button("⬇️ Download JSON report", f, file_name="oneclick_report.json", mime="application/json", width='stretch')
        with open(pdf_path, "rb") as f:
            colB.download_button("⬇️ Download PDF report", f, file_name="oneclick_report.pdf", mime="application/pdf", width='stretch')

    st.caption(
        "Note: Risk score comes from a demo Random Forest model trained on synthetic "
        "behavior patterns (see README). Retrain on a real labeled dataset for production accuracy."
    )


def tab_single_scan(vt_api_key):
    st.markdown(
        f"""<div class="oc-card"><b>Single File Scan</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Upload one APK to run the full pipeline: signature check, static analysis, and AI risk scoring.
        </span></div>""",
        unsafe_allow_html=True,
    )
    uploaded = st.file_uploader("Upload an .apk file", type=["apk"], key="single")
    run_advanced = st.checkbox("Run advanced static analysis (strings/URLs, obfuscation, SDKs)", value=True)

    if uploaded is None:
        st.info("Upload an APK to begin analysis.")
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    try:
        with st.spinner("Running full OneClick pipeline..."):
            result = scan_apk(tmp_path, uploaded.name, vt_api_key=vt_api_key, run_advanced=run_advanced)
        render_single_result(result, uploaded.name)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def tab_batch_scan(vt_api_key):
    st.markdown(
        f"""<div class="oc-card"><b>Batch Scan</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Upload multiple APKs to scan them all in one go — results summarized in a table and chart below.
        </span></div>""",
        unsafe_allow_html=True,
    )
    uploaded_files = st.file_uploader("Upload .apk files", type=["apk"], accept_multiple_files=True, key="batch")
    run_advanced = st.checkbox("Run advanced static analysis", value=False, key="batch_adv",
                                 help="Slower but more thorough; disable for faster bulk scans")

    if not uploaded_files:
        st.info("Upload one or more APKs to batch scan.")
        return

    if st.button(f"Scan all {len(uploaded_files)} file(s)", type="primary"):
        rows = []
        progress = st.progress(0)
        for i, uploaded in enumerate(uploaded_files):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
                tmp.write(uploaded.read())
                tmp_path = tmp.name
            try:
                result = scan_apk(tmp_path, uploaded.name, vt_api_key=vt_api_key, run_advanced=run_advanced)
                if result.get("known_threat"):
                    verdict, score = "Known Threat", 100.0
                elif result.get("error"):
                    verdict, score = f"Error: {result['error']}", None
                else:
                    verdict = result["ml_result"]["label"]
                    score = result["ml_result"]["risk_score"]
                rows.append({"File": uploaded.name, "SHA-256": result["sha256"][:16] + "...",
                             "Verdict": verdict, "Risk Score": score})
            except Exception as e:
                rows.append({"File": uploaded.name, "SHA-256": "-", "Verdict": f"Error: {e}", "Risk Score": None})
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            progress.progress((i + 1) / len(uploaded_files))

        col1, col2 = st.columns([1.6, 1])
        with col1:
            df = pd.DataFrame(rows)
            st.dataframe(df, width='stretch')
        with col2:
            st.markdown("**Verdict Breakdown**")
            verdict_donut([r["Verdict"] for r in rows])


def tab_history():
    st.markdown(
        f"""<div class="oc-card"><b>Scan History</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Recent scans stored locally in <code>oneclick.db</code> (SQLite).
        </span></div>""",
        unsafe_allow_html=True,
    )
    limit = st.slider("Number of records to show", 10, 200, 50)
    records = database.get_history(limit=limit)

    if not records:
        st.info("No scan history yet — run a scan first.")
        return

    col1, col2 = st.columns([1.6, 1])
    with col1:
        df = pd.DataFrame([{
            "Time": r["timestamp"][:19],
            "File": r["filename"],
            "Package": r["package_name"] or "-",
            "SHA-256": r["sha256"][:16] + "...",
            "Verdict": r["verdict"],
            "Risk Score": r["risk_score"],
            "Source": r["source"],
        } for r in records])
        st.dataframe(df, width='stretch')

        st.markdown("**Risk Score Trend**")
        risk_trend_curve(records)
    with col2:
        st.markdown("**Verdict Breakdown**")
        verdict_donut([r["verdict"] for r in records])

    if st.button("🗑️ Clear history", type="secondary"):
        database.clear_history()
        st.success("History cleared.")
        st.rerun()


def tab_dynamic_analysis():
    st.markdown(
        f"""<div class="oc-card"><b>Layer 5 — Dynamic Analysis</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Runs the APK in a real Android emulator/device and observes runtime behavior
        (SMS sends, dynamic code loading, network calls) using ADB + Frida hooks.
        </span></div>""",
        unsafe_allow_html=True,
    )
    st.warning(
        "⚠️ This requires Android SDK platform-tools + a running emulator/device + Frida "
        "installed on **this machine**. It was not testable in the environment this project "
        "was built in — verify it works on your Kali box before relying on it."
    )

    env = check_dynamic_env()
    c1, c2, c3 = st.columns(3)
    c1.metric("adb available", "✅" if env["adb_available"] else "❌")
    c2.metric("Device/emulator connected", "✅" if env["device_connected"] else "❌")
    c3.metric("frida available", "✅" if env["frida_available"] else "❌")

    if env["notes"]:
        for note in env["notes"]:
            st.caption(f"• {note}")

    if not (env["adb_available"] and env["device_connected"]):
        st.info(
            "Setup steps:\n"
            "```bash\n"
            "sudo apt install android-tools-adb android-tools-fastboot\n"
            "pip install frida-tools frida\n"
            "# then start an AVD emulator or connect a rooted device\n"
            "```"
        )
        return

    uploaded = st.file_uploader("Upload an .apk file to dynamically analyze", type=["apk"], key="dynamic")
    duration = st.slider("Observation duration (seconds)", 10, 120, 30)

    if uploaded and st.button("Run dynamic analysis", type="primary"):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name
        try:
            with st.spinner(f"Installing, launching, and observing for {duration}s..."):
                result = run_dynamic_analysis(tmp_path, duration_seconds=duration)
            st.json(result)
        finally:
            os.unlink(tmp_path)


def tab_phishing_scanner(vt_api_key):
    st.markdown(
        f"""<div class="oc-card"><b>🎣 Phishing &amp; Malicious URL Scanner</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Paste a suspicious link, or an entire SMS/email/WhatsApp message — links inside it are
        extracted automatically. Every result is a <b>flag for you to review</b>; OneClick never
        deletes or blocks anything on its own.
        </span></div>""",
        unsafe_allow_html=True,
    )

    if "phish_results" not in st.session_state:
        st.session_state.phish_results = []  # list of (row_id, result_dict)

    mode = st.radio("Input type", ["Single URL", "Paste a message (auto-extract links)"], horizontal=True)

    urls_to_scan = []
    if mode == "Single URL":
        single = st.text_input("URL", placeholder="https://example.com/login")
        if single.strip():
            urls_to_scan = [single.strip()]
    else:
        blob = st.text_area(
            "Paste message text",
            placeholder="Your account is suspended! Verify now: http://paypa1-secure.tk/verify",
            height=110,
        )
        if blob.strip():
            urls_to_scan = extract_urls_from_text(blob)
            redaction = redact_message(blob)
            if redaction["codes_hidden"] > 0:
                st.warning(f"🔒 Auto-hid {redaction['codes_hidden']} OTP/code-like value(s) in the preview below — they are never stored or shown in full.")
                st.text_area("Safe preview (codes hidden)", value=redaction["redacted_text"], height=110, disabled=True)
            if urls_to_scan:
                st.caption(f"Found {len(urls_to_scan)} link(s): " + ", ".join(urls_to_scan))
            else:
                st.caption("No links found in the pasted text.")

    if not vt_api_key:
        st.info("No VirusTotal API key set (sidebar) — running heuristic-only analysis. Add a key for reputation-based checks too.")

    if urls_to_scan and st.button(f"🔍 Scan {len(urls_to_scan)} link(s)", type="primary"):
        st.session_state.phish_results = []  # fresh scan replaces the previous batch
        for url in urls_to_scan:
            with st.spinner(f"Analyzing {url} ..."):
                result = scan_url(url, vt_api_key=vt_api_key)
            row_id = database.save_url_scan(
                url=result["url"], verdict=result["label"],
                risk_score=result["score"], reasons=result["reasons"],
            )
            st.session_state.phish_results.append((row_id, result))

    # Rendered from session_state (NOT nested inside the Scan button's if-block)
    # so that the per-result action buttons keep working across reruns.
    for row_id, result in st.session_state.phish_results:
        render_url_result(result, row_id)


def render_url_result(result: dict, row_id: int):
    color = LABEL_COLOR.get(result["label"], TEXT_MUTED)
    glow = LABEL_GLOW.get(result["label"], "140,150,170")

    st.markdown(
        f"""<div class="oc-card" style="border-color: rgba({glow},0.45);
             box-shadow: 0 0 24px rgba({glow},0.12);">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <code style="font-size:13px;word-break:break-all;">{result['url']}</code>
                <span style="background:{color}22;color:{color};padding:4px 14px;border-radius:999px;
                             font-weight:700;font-size:13px;white-space:nowrap;margin-left:12px;">
                    {result['label']} · {result['score']}%
                </span>
            </div>
        </div>""",
        unsafe_allow_html=True,
    )

    with st.expander("Why was this flagged?", expanded=(result["score"] >= 35)):
        for reason in result["reasons"]:
            st.markdown(f"- {reason}")
        vt = result.get("virustotal", {})
        if vt.get("found") and vt.get("permalink"):
            st.markdown(f"[View full VirusTotal report]({vt['permalink']})")

    # --- Optional deep-dive: where does this link actually lead, and what does it do? ---
    investigate_key = f"investigate_{row_id}"
    if st.button("🔬 Investigate: where does this lead & what does it do?", key=f"btn_{investigate_key}"):
        with st.spinner("Safely following redirects and inspecting the landing page (read-only, no scripts executed)..."):
            try:
                report = investigate_url(result["url"])
            except Exception as e:
                report = {"error": str(e)}
        st.session_state[investigate_key] = report

    if investigate_key in st.session_state:
        render_investigation(st.session_state[investigate_key])

    current_action = result.get("_user_action", "none")

    if current_action != "none":
        badge = {"deleted_by_user": "🗑️ You marked this as deleted", "dismissed": "✅ You dismissed this (reviewed, kept)"}
        st.info(badge.get(current_action, current_action))
    elif result["score"] >= 35:
        st.warning(
            "⚠️ This link looks risky. OneClick does **not** delete or block anything automatically — "
            "review it yourself and decide what to do next."
        )
        c1, c2, c3 = st.columns(3)
        if c1.button("🗑️ I deleted this myself", key=f"del_{row_id}"):
            database.set_url_scan_action(row_id, "deleted_by_user")
            _update_session_action(row_id, "deleted_by_user")
            st.rerun()
        if c2.button("✅ Dismiss (false positive)", key=f"dismiss_{row_id}"):
            database.set_url_scan_action(row_id, "dismissed")
            _update_session_action(row_id, "dismissed")
            st.rerun()
        if c3.button("🚩 Report to authorities info", key=f"report_{row_id}"):
            st.info(
                "In India, phishing/cybercrime can be reported at "
                "**cybercrime.gov.in** or by calling **1930**."
            )
    else:
        st.success("✅ No strong phishing indicators found.")

    st.markdown("<hr style='opacity:0.08;'>", unsafe_allow_html=True)


def render_investigation(report: dict):
    if report.get("error"):
        st.error(f"Investigation failed: {report['error']}")
        return

    if report.get("blocked"):
        st.error(f"🚫 {report.get('block_reason', 'Blocked for safety.')}")
        return

    st.markdown(
        f"""<div class="oc-card" style="margin-top:8px;">
        <b>🔬 Landing Page Investigation</b> <span style="color:{TEXT_MUTED};font-size:12.5px;">(read-only — no scripts were executed, nothing was submitted)</span>
        </div>""",
        unsafe_allow_html=True,
    )

    hops = report.get("redirect_chain", [])
    if len(hops) > 1:
        st.markdown("**Redirect chain:**")
        st.code(" → ".join(hops + [report["final_url"]]), language=None)
    st.markdown(f"**Final destination:** `{report['final_url']}`")
    if report.get("page_title"):
        st.markdown(f"**Page title:** {report['page_title']}")

    if report.get("meta_refresh_redirect"):
        st.warning(f"⚠️ Page auto-redirects again to: `{report['meta_refresh_redirect']}`")

    forms = report.get("forms", [])
    if forms:
        st.markdown(f"**Forms on this page ({len(forms)}):**")
        for f in forms:
            flag = "🔴" if (f["has_credential_field"] and f["cross_domain_submit"]) else ("🟡" if f["has_credential_field"] else "⚪")
            st.markdown(
                f"{flag} `{f['method']}` → `{f['action']}` "
                f"{'— **collects credentials, cross-domain!**' if f['has_credential_field'] and f['cross_domain_submit'] else ('— collects credentials' if f['has_credential_field'] else '')}"
            )

    if report.get("suspicious_scripts"):
        st.markdown("**Suspicious script behavior detected:**")
        for s in report["suspicious_scripts"]:
            st.markdown(f"- {s}")

    if report.get("external_script_domains"):
        with st.expander(f"External script domains ({len(report['external_script_domains'])})"):
            st.write(report["external_script_domains"])

    st.markdown("**Summary:**")
    for a in report.get("likely_actions", []):
        st.markdown(f"- {a}")

    st.caption(
        "This is a static read-only analysis — JavaScript was never executed, so behavior that only "
        "triggers after a script runs (or after you interact with the page) cannot be fully captured."
    )


def _update_session_action(row_id: int, action: str):
    """Updates the in-memory session copy of a result so the UI reflects the
    user's decision immediately, without needing to re-scan."""
    for i, (rid, res) in enumerate(st.session_state.get("phish_results", [])):
        if rid == row_id:
            res["_user_action"] = action
            st.session_state.phish_results[i] = (rid, res)
            break


def tab_otp_guard():
    st.markdown(
        f"""<div class="oc-card"><b>🔒 OTP / Code Guard</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Paste any SMS, email, or WhatsApp message. If it contains an OTP or verification
        code, OneClick <b>automatically hides it</b> in the preview — the real code is
        never displayed back, stored in history, or included in any export.
        </span></div>""",
        unsafe_allow_html=True,
    )

    st.info(
        "ℹ️ **Scope note:** OneClick is a web tool, not a phone app — it can't read your "
        "live SMS/email inbox automatically. This works on text you paste in (e.g. before "
        "forwarding a message to support, or pasting it here to check a link). For "
        "protecting OTPs the moment they *arrive* on your phone, that would need a native "
        "Android app with notification access — a possible future extension, tracked "
        "separately from this web tool."
    )

    msg = st.text_area(
        "Paste a message",
        placeholder="Your OTP is 483920. Do not share this with anyone, including bank staff.",
        height=130,
        key="otp_guard_input",
    )

    if msg.strip():
        result = redact_message(msg)
        if result["codes_hidden"] > 0:
            st.success(f"🔒 Hid {result['codes_hidden']} code(s) — triggered by: {', '.join(result['keywords_matched'])}")
        else:
            st.caption("No OTP/verification code patterns detected in this message.")

        st.markdown("**Safe version (share/copy this, not the original):**")
        st.text_area("Redacted output", value=result["redacted_text"], height=130, disabled=True, label_visibility="collapsed")

        c1, c2 = st.columns(2)
        c1.metric("Codes hidden", result["codes_hidden"])
        c2.metric("Keywords matched", len(result["keywords_matched"]))

        with st.expander("Why this design?"):
            st.markdown(
                "- The actual code is **never** returned by the detection function itself — only "
                "a count and the trigger keyword — so it can't leak even through logs or history.\n"
                "- Detection is **keyword-anchored**: a bare 6-digit number isn't touched unless "
                "it appears near a phrase like *OTP*, *verification code*, *PIN is*, etc. This "
                "keeps phone numbers, order IDs, and amounts from being masked unnecessarily.\n"
                "- Covers common Hinglish phrasing too (*'aapka OTP hai'*, *'code hai'*) since "
                "Indian SMS are often code-mixed."
            )
    else:
        st.caption("Paste a message above to see it with OTPs/codes automatically hidden.")


def tab_qr_scanner(vt_api_key):
    st.markdown(
        f"""<div class="oc-card"><b>📷 QR Code Scanner</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Upload a photo/screenshot of a QR code ("quishing" protection). If it contains a
        link, it's run through the same phishing checks; if it's a UPI payment QR, the
        payee VPA is checked against reported scam IDs before you approve anything.
        </span></div>""",
        unsafe_allow_html=True,
    )

    if not QR_AVAILABLE:
        st.error(
            "⚠️ QR scanning isn't available — a system dependency is missing.\n\n"
            f"Import error: `{QR_IMPORT_ERROR}`\n\n"
            "**Fix (Debian/Ubuntu/Kali):**\n"
            "```bash\nsudo apt install libzbar0\npip install pyzbar\n```\n"
            "Run `python3 doctor.py` for a full dependency check, then restart the app."
        )
        return

    uploaded = st.file_uploader("Upload a QR code image", type=["png", "jpg", "jpeg"], key="qr_upload")
    if not uploaded:
        st.info("Upload a QR code image to decode and check it.")
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    try:
        with st.spinner("Decoding QR code..."):
            result = scan_qr_image(tmp_path, vt_api_key=vt_api_key)
    finally:
        os.unlink(tmp_path)

    if not result["found"]:
        st.warning("No QR code detected in this image.")
        return

    st.success(f"Decoded {len(result['payloads'])} code(s).")
    for payload in result["payloads"]:
        st.code(payload, language=None)

    for url_result in result["url_results"]:
        if url_result.get("is_upi"):
            color = "#ef4444" if url_result["score"] >= 70 else "#0EA5E9"
            st.markdown(
                f"""<div class="oc-card" style="border-color:{color}66;">
                <b>💸 UPI Payment Request</b> — <span style="color:{color};font-weight:700;">{url_result['label']}</span>
                </div>""", unsafe_allow_html=True,
            )
            for reason in url_result["reasons"]:
                st.markdown(f"- {reason}")
        else:
            row_id = database.save_url_scan(
                url=url_result["url"], verdict=url_result["label"],
                risk_score=url_result["score"], reasons=url_result["reasons"],
            )
            render_url_result(url_result, row_id)


def tab_screenshot_scanner(vt_api_key):
    st.markdown(
        f"""<div class="oc-card"><b>📋 Screenshot Scam Scanner</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Most scam messages get forwarded as <b>screenshots</b>, not typed text. Upload one and
        OneClick reads it (OCR), then checks any links, hides any OTPs, and flags known scam
        script patterns (fake courier, digital arrest, lottery, etc.) — all in one pass.
        </span></div>""",
        unsafe_allow_html=True,
    )

    if not OCR_AVAILABLE:
        st.error(
            "⚠️ Screenshot OCR isn't available — a system dependency is missing.\n\n"
            f"Import error: `{OCR_IMPORT_ERROR}`\n\n"
            "**Fix (Debian/Ubuntu/Kali):**\n"
            "```bash\nsudo apt install tesseract-ocr\npip install pytesseract\n```\n"
            "Run `python3 doctor.py` for a full dependency check, then restart the app."
        )
        return

    uploaded = st.file_uploader("Upload a screenshot", type=["png", "jpg", "jpeg"], key="screenshot_upload")
    if not uploaded:
        st.info("Upload a screenshot to scan it.")
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    try:
        with st.spinner("Reading screenshot (OCR) and analyzing..."):
            result = scan_screenshot(tmp_path, vt_api_key=vt_api_key)
    finally:
        os.unlink(tmp_path)

    if not result["raw_text"].strip():
        st.warning(result.get("ocr_confidence_note", "No readable text found."))
        return

    if result["redaction"]["codes_hidden"] > 0:
        st.warning(f"🔒 Hid {result['redaction']['codes_hidden']} OTP/code-like value(s) in the text below.")
    st.markdown("**Extracted text (OTPs hidden):**")
    st.text_area("OCR output", value=result["redaction"]["redacted_text"], height=140, disabled=True, label_visibility="collapsed")

    if result["scam_patterns"]:
        st.error(f"⚠️ Matches {len(result['scam_patterns'])} known scam pattern(s):")
        for p in result["scam_patterns"]:
            with st.expander(f"🚩 {p['category']}"):
                st.markdown(p["explanation"])
                st.caption("Matched phrases: " + ", ".join(p["matched_phrases"]))
    else:
        st.success("✅ No known scam-script patterns detected in the text.")

    if result["urls_found"]:
        st.markdown(f"**Links found ({len(result['urls_found'])}):**")
        for url_result in result["url_results"]:
            row_id = database.save_url_scan(
                url=url_result["url"], verdict=url_result["label"],
                risk_score=url_result["score"], reasons=url_result["reasons"],
            )
            render_url_result(url_result, row_id)


def tab_scam_lookup():
    st.markdown(
        f"""<div class="oc-card"><b>📞 Scam Number / UPI ID Lookup</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Checks a phone number or UPI ID against OneClick's local reported-scam list, and lets
        you add your own report. This is a <b>local list bundled with this installation</b>,
        not a live crowdsourced service — treat a "clean" result as "not yet reported", not
        "verified safe".
        </span></div>""",
        unsafe_allow_html=True,
    )

    lookup_type = st.radio("Check a", ["Phone number", "UPI ID"], horizontal=True, key="scam_lookup_type")

    if lookup_type == "Phone number":
        number = st.text_input("Phone number", placeholder="9876543210")
        if number.strip() and st.button("🔍 Check number"):
            r = check_phone_number(number)
            _render_scam_lookup_result(r)
            with st.expander("🚩 Report this number as a scam"):
                cat = st.selectbox("Category", ["Fake Customer Care", "Digital Arrest Scam", "Lottery Scam",
                                                  "Fake Job Offer", "Loan Scam", "Other"], key="report_cat_phone")
                note = st.text_input("Note (optional)", key="report_note_phone")
                if st.button("Submit report", key="submit_phone_report"):
                    add_report("phone", number, cat, note)
                    st.success("Added to your local report list.")

    else:
        vpa = st.text_input("UPI ID", placeholder="example@upi")
        if vpa.strip() and st.button("🔍 Check UPI ID"):
            r = check_upi_id(vpa)
            _render_scam_lookup_result(r)
            with st.expander("🚩 Report this UPI ID as a scam"):
                cat = st.selectbox("Category", ["Fake Store / Non-Delivery", "Fake Investment", "Impersonation",
                                                  "Romance Scam", "Other"], key="report_cat_upi")
                note = st.text_input("Note (optional)", key="report_note_upi")
                if st.button("Submit report", key="submit_upi_report"):
                    add_report("upi", vpa, cat, note)
                    st.success("Added to your local report list.")


def _render_scam_lookup_result(r: dict):
    if r["is_reported"]:
        st.error(f"⚠️ Reported {r['report_count']} time(s) — Category: **{r['category']}**")
        if r["note"]:
            st.caption(r["note"])
    else:
        st.info("Not found in the local report list. This does not guarantee it's safe — just that it hasn't been reported here yet.")


def tab_domain_age_lookup():
    st.markdown(
        f"""<div class="oc-card"><b>🕐 Domain Age Checker</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Phishing sites are almost always registered days (sometimes hours) before use.
        Checks a domain's WHOIS registration date directly — independent of VirusTotal.
        </span></div>""",
        unsafe_allow_html=True,
    )
    st.caption(
        "⚠️ Requires WHOIS (port 43) access from wherever OneClick is running. Some "
        "locked-down networks block this even when normal web browsing works — if so, "
        "you'll see a clear 'lookup failed' message rather than a wrong result."
    )
    domain = st.text_input("Domain", placeholder="example.com")
    if domain.strip() and st.button("🔍 Check domain age"):
        from modules.domain_age import check_domain_age
        with st.spinner("Querying WHOIS..."):
            r = check_domain_age(domain.strip())
        if r["error"]:
            st.warning(f"Lookup unavailable: {r['error']}")
        elif r["is_newly_registered"]:
            st.error(f"⚠️ {r['reason']}")
        else:
            st.success(f"✅ Domain registered {r['age_days']} days ago ({r['creation_date'][:10]}) — not newly registered.")


def tab_breach_checker():
    st.markdown(
        f"""<div class="oc-card"><b>🕵️ Data Breach Checker</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Check if a password has appeared in known breach dumps (free, via HaveIBeenPwned's
        k-anonymity API — your password is never sent in full), or if an email appears in
        known breaches (needs your own HIBP API key — their email-lookup API is paid).
        </span></div>""",
        unsafe_allow_html=True,
    )

    sub = st.radio("Check", ["Password", "Email"], horizontal=True, key="breach_check_type")

    if sub == "Password":
        pw = st.text_input("Password to check", type="password")
        if pw and st.button("🔍 Check password"):
            with st.spinner("Checking (only a partial hash is sent, never the password itself)..."):
                r = check_password_pwned(pw)
            if r["error"]:
                st.warning(f"Check unavailable: {r['error']}")
            elif r["is_pwned"]:
                st.error(f"⚠️ This password has appeared in breaches {r['times_seen']:,} time(s). Do not use it.")
            else:
                st.success("✅ Not found in known breach dumps.")
    else:
        email = st.text_input("Email to check")
        hibp_key = st.text_input("HIBP API key (required, paid)", type="password")
        if email and st.button("🔍 Check email"):
            with st.spinner("Checking..."):
                r = check_email_breaches(email, api_key=hibp_key)
            if r["error"] == "NO_API_KEY":
                st.info("This check needs your own HaveIBeenPwned API key (paid) — get one at haveibeenpwned.com/API/Key.")
            elif r["error"]:
                st.warning(f"Check failed: {r['error']}")
            elif r["found"]:
                st.error(f"⚠️ Found in {len(r['breaches'])} breach(es):")
                for b in r["breaches"]:
                    st.markdown(f"- **{b['name']}** ({b['breach_date']}) — exposed: {', '.join(b['data_classes'])}")
            else:
                st.success("✅ Not found in known breaches.")


def tab_url_history():
    st.markdown(
        f"""<div class="oc-card"><b>URL Scan History</b><br>
        <span style="color:{TEXT_MUTED};font-size:13.5px;">
        Every link you've scanned, and what you decided to do about it. Nothing here was
        auto-deleted — <code>user_action</code> only changes when you click a button yourself.
        </span></div>""",
        unsafe_allow_html=True,
    )
    records = database.get_url_history(limit=100)
    if not records:
        st.info("No URL scans yet — try the Phishing Scanner tab.")
        return

    df = pd.DataFrame([{
        "Time": r["timestamp"][:19],
        "URL": r["url"],
        "Verdict": r["verdict"],
        "Risk Score": r["risk_score"],
        "Your Action": r["user_action"],
    } for r in records])
    st.dataframe(df, width='stretch')

    if st.button("🗑️ Clear URL history", type="secondary"):
        database.clear_url_history()
        st.success("URL history cleared.")
        st.rerun()


def main():
    inject_css()
    hero_banner()

    with st.sidebar:
        st.markdown(
            """
            <div style="text-align:center; padding: 6px 0 16px 0;">
                <div style="font-size:34px;">🛡️</div>
                <div style="font-weight:800; font-size:17px; color:#FFFFFF; letter-spacing:0.5px;">ONECLICK</div>
                <div style="font-size:11px; color:#8FA3B8; letter-spacing:1.5px; margin-top:-2px;">APK ANALYZER</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("#### ⚙️ Settings")
        vt_api_key = st.text_input("VirusTotal API key", type="password", help="Get a free key at virustotal.com")
        st.markdown("---")
        st.markdown(
            "**Pipeline**\n"
            "1. SHA-256 hash → VirusTotal lookup (cached)\n"
            "2. Androguard static analysis\n"
            "2b. Advanced static analysis (IOCs, obfuscation, SDKs)\n"
            "3. Random Forest risk scoring + SHAP\n"
            "4. Dashboard, batch scan, history, reports\n"
            "5. Optional dynamic analysis (needs Android SDK)\n"
            "6. Phishing/URL scanner (flag-only, no auto-delete)\n"
            "7. OTP/code auto-redaction (flag-only, no auto-delete)"
        )
        st.markdown("---")
        if not os.path.exists(MODEL_PATH):
            st.warning("ML model not trained yet.\nRun: `python models/train_model.py`")
        else:
            st.success("✅ AI model loaded")
        if not SHAP_AVAILABLE:
            st.caption("SHAP not installed — using rule-based explanations only.")
        if not QR_AVAILABLE:
            st.caption("⚠️ QR Scanner tab disabled (missing libzbar0/pyzbar). Run `python3 doctor.py`.")
        if not OCR_AVAILABLE:
            st.caption("⚠️ Screenshot Scanner tab disabled (missing tesseract-ocr/pytesseract). Run `python3 doctor.py`.")

    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10, tab11 = st.tabs([
        "🔍 Single Scan", "📦 Batch Scan", "🕓 History", "🏃 Dynamic Analysis",
        "🎣 Phishing Scanner", "🔗 URL History", "🔒 OTP Guard",
        "📷 QR Scanner", "📋 Screenshot Scanner", "📞 Scam Lookup", "🕵️ Breach Checker",
    ])
    with tab1:
        tab_single_scan(vt_api_key)
    with tab2:
        tab_batch_scan(vt_api_key)
    with tab3:
        tab_history()
    with tab4:
        tab_dynamic_analysis()
    with tab5:
        tab_phishing_scanner(vt_api_key)
    with tab6:
        tab_url_history()
    with tab7:
        tab_otp_guard()
    with tab8:
        tab_qr_scanner(vt_api_key)
    with tab9:
        tab_screenshot_scanner(vt_api_key)
    with tab10:
        tab_scam_lookup()
        st.markdown("---")
        tab_domain_age_lookup()
    with tab11:
        tab_breach_checker()


if __name__ == "__main__":
    main()
