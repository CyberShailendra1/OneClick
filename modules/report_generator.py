"""
Export scan results as JSON (machine-readable) or PDF (client-friendly report).
"""

import json
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem
)

VERDICT_COLOR = {
    "Safe": colors.HexColor("#22c55e"),
    "Suspicious": colors.HexColor("#eab308"),
    "Malicious": colors.HexColor("#ef4444"),
    "Known Threat": colors.HexColor("#ef4444"),
}


def build_report_dict(filename, sha256, layer1, features, ml_result, advanced=None) -> dict:
    """Assembles one unified JSON-serializable report dict from all layers."""
    return {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "file": filename,
        "sha256": sha256,
        "layer1_virustotal": layer1,
        "layer2_static_features": features,
        "layer3_ai_risk": ml_result,
        "layer2b_advanced": advanced or {},
    }


def export_json(report: dict, out_path: str):
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    return out_path


def export_pdf(report: dict, out_path: str):
    doc = SimpleDocTemplate(out_path, pagesize=letter,
                             topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleC", parent=styles["Title"], textColor=colors.HexColor("#1e293b"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=14, textColor=colors.HexColor("#1e293b"))
    normal = styles["Normal"]
    mono = ParagraphStyle("Mono", parent=styles["Normal"], fontName="Courier", fontSize=8)

    story = []
    story.append(Paragraph("OneClick APK Analyzer &mdash; Threat Report", title_style))
    story.append(Paragraph(f"Generated: {report['report_generated']}", normal))
    story.append(Spacer(1, 12))

    story.append(Paragraph("File Information", h2))
    story.append(Table(
        [["Filename", report.get("file", "-")],
         ["SHA-256", report.get("sha256", "-")]],
        colWidths=[1.3 * inch, 5 * inch],
        style=TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (1, 1), (1, 1), "Courier"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ]),
    ))

    ml = report.get("layer3_ai_risk", {})
    label = ml.get("label", "Unknown")
    risk_score = ml.get("risk_score", 0)
    verdict_color = VERDICT_COLOR.get(label, colors.grey)

    story.append(Paragraph("Verdict", h2))
    story.append(Table(
        [[f"{label}", f"Risk Score: {risk_score}%"]],
        colWidths=[3 * inch, 3.3 * inch],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 13),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]),
    ))

    vt = report.get("layer1_virustotal", {}) or {}
    story.append(Paragraph("Layer 1 &mdash; VirusTotal Signature Check", h2))
    if vt.get("found"):
        story.append(Paragraph(
            f"Flagged malicious by {vt.get('malicious', 0)}/{vt.get('total_engines', 0)} engines.", normal))
    else:
        story.append(Paragraph("No known signature match found (not in VirusTotal database).", normal))

    feats = report.get("layer2_static_features", {}) or {}
    story.append(Paragraph("Layer 2 &mdash; Static Analysis Summary", h2))
    story.append(Table(
        [["Package", str(feats.get("package_name", "-"))],
         ["Dangerous permissions", str(feats.get("num_dangerous_permissions", 0))],
         ["Suspicious API calls", str(feats.get("num_suspicious_apis", 0))],
         ["Self-signed cert", str(feats.get("is_self_signed", "-"))],
         ["Debuggable", str(feats.get("is_debuggable", "-"))]],
        colWidths=[2 * inch, 4.3 * inch],
        style=TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ]),
    ))

    adv = report.get("layer2b_advanced", {}) or {}
    if adv:
        story.append(Paragraph("Advanced Static Analysis", h2))
        obf = adv.get("obfuscation", {})
        if obf:
            story.append(Paragraph(
                f"Obfuscation check: max entropy {obf.get('max_entropy')} &mdash; "
                f"{'likely obfuscated/packed' if obf.get('likely_obfuscated') else 'normal range'}.",
                normal))
        iocs = adv.get("iocs", {})
        if iocs.get("urls_found"):
            story.append(Paragraph(f"URLs found in binary ({iocs.get('num_urls')}):", normal))
            story.append(ListFlowable(
                [ListItem(Paragraph(u, mono)) for u in iocs["urls_found"][:15]], bulletType="bullet"))
        native = adv.get("native_libs", {})
        if native.get("has_native_code"):
            story.append(Paragraph(
                f"Native libraries bundled: {native.get('num_native_libs')} "
                f"(ABIs: {', '.join(native.get('abis_present', []))})", normal))
        sdks = adv.get("detected_sdks", [])
        if sdks:
            story.append(Paragraph("Third-party SDKs detected: " + ", ".join(sdks), normal))

    story.append(Paragraph("Layer 3 &mdash; Explainability", h2))
    reasons = ml.get("reasons", [])
    if reasons:
        story.append(ListFlowable(
            [ListItem(Paragraph(r, normal)) for r in reasons], bulletType="bullet"))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Note: AI risk score is generated by a Random Forest model. See project README "
        "for details on training data and accuracy limitations.",
        ParagraphStyle("Small", parent=normal, fontSize=7, textColor=colors.grey)))

    doc.build(story)
    return out_path
