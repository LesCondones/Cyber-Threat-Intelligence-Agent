"""
PDF Report Generator

Generates professional threat intelligence reports with:
- Executive summary
- Key intelligence findings with source citations
- Intelligence assessment (confidence, reliability)
- Diamond Model analysis
- Cyber Kill Chain mapping
- Detailed findings with source-grounded analysis
- Threat actor profiles
- IOC enrichment results
- MITRE ATT&CK mappings (validated, deduplicated)
- Consolidated IOC summary
"""

import io
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image,
    PageBreak, HRFlowable,
)

from agents.subagent import ResearchFinding
from agents.mitre_mapper import MITREMapping


def _strip_markdown(text: str) -> str:
    """Remove markdown formatting from LLM output for clean PDF text."""
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"\*{1,3}(.+?)\*{1,3}", r"\1", text)
    text = re.sub(r"_{1,3}(.+?)_{1,3}", r"\1", text)
    text = re.sub(r"^[\-\*_]{3,}\s*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^- ", "  \u2022 ", text, flags=re.MULTILINE)
    text = re.sub(r"`(.+?)`", r"\1", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _escape_xml(text: str) -> str:
    """Escape XML-special chars for ReportLab."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


# Maximum IOCs to display per type in each report section
MAX_IOCS_PER_TYPE_PER_FINDING = 15
MAX_IOCS_PER_TYPE_CONSOLIDATED = 30


SEVERITY_COLORS = {
    "Critical": colors.HexColor("#FF0000"),
    "High": colors.HexColor("#FF8C00"),
    "Medium": colors.HexColor("#FFD700"),
    "Low": colors.HexColor("#32CD32"),
    "Unknown": colors.HexColor("#D3D3D3"),
}

SEVERITY_HEX = {
    "Critical": "#FF0000",
    "High": "#FF8C00",
    "Medium": "#FFD700",
    "Low": "#32CD32",
    "Unknown": "#D3D3D3",
}


def _build_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"],
        fontSize=22, spaceAfter=6, textColor=colors.HexColor("#1a1a2e"),
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", parent=styles["Heading1"],
        fontSize=16, spaceBefore=18, spaceAfter=8,
        textColor=colors.HexColor("#16213e"),
    ))
    styles.add(ParagraphStyle(
        name="SubHeading", parent=styles["Heading2"],
        fontSize=13, spaceBefore=12, spaceAfter=6,
        textColor=colors.HexColor("#0f3460"),
    ))
    styles.add(ParagraphStyle(
        name="BodyWrap", parent=styles["BodyText"],
        fontSize=10, leading=14, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="SourceLink", parent=styles["BodyText"],
        fontSize=9, textColor=colors.HexColor("#0000FF"), spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="IOCText", parent=styles["BodyText"],
        fontSize=9, fontName="Courier", textColor=colors.HexColor("#CC0000"),
        spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="Timestamp", parent=styles["BodyText"],
        fontSize=9, italic=True, textColor=colors.gray,
    ))
    styles.add(ParagraphStyle(
        name="ActorField", parent=styles["BodyText"],
        fontSize=10, leading=13, spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="KeyFinding", parent=styles["BodyText"],
        fontSize=10, leading=14, spaceAfter=4,
        leftIndent=12, borderColor=colors.HexColor("#4472C4"),
        borderWidth=0, borderPadding=4,
    ))
    styles.add(ParagraphStyle(
        name="FrameworkField", parent=styles["BodyText"],
        fontSize=10, leading=14, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="TableCell", parent=styles["BodyText"],
        fontSize=9, leading=12, spaceAfter=0, spaceBefore=0,
    ))
    styles.add(ParagraphStyle(
        name="TableCellBold", parent=styles["BodyText"],
        fontSize=9, leading=12, spaceAfter=0, spaceBefore=0,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="TableCellMono", parent=styles["BodyText"],
        fontSize=8, leading=11, spaceAfter=0, spaceBefore=0,
        fontName="Courier",
    ))
    styles.add(ParagraphStyle(
        name="TableHeaderCell", parent=styles["BodyText"],
        fontSize=9, leading=12, spaceAfter=0, spaceBefore=0,
        fontName="Helvetica-Bold", textColor=colors.white,
    ))

    return styles


def _build_severity_chart(findings: List[ResearchFinding]) -> Image:
    severity_order = ["Critical", "High", "Medium", "Low", "Unknown"]
    counts = {s: 0 for s in severity_order}
    for f in findings:
        key = f.severity if f.severity in counts else "Unknown"
        counts[key] += 1

    labels = [s for s in severity_order if counts[s] > 0]
    values = [counts[s] for s in labels]
    bar_colors = [SEVERITY_HEX.get(s, "#D3D3D3") for s in labels]

    fig, ax = plt.subplots(figsize=(5, 2.8))
    bars = ax.bar(labels, values, color=bar_colors, edgecolor="#333333", linewidth=0.8)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                str(val), ha="center", va="bottom", fontweight="bold", fontsize=11)
    ax.set_ylabel("Number of Findings", fontsize=10)
    ax.set_title("Threat Severity Distribution", fontsize=12, fontweight="bold")
    ax.set_ylim(0, max(values) + 1.5)
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return Image(buf, width=5 * inch, height=2.8 * inch)


@dataclass
class ReportGenerator:
    output_dir: Path = Path("reports")

    def __post_init__(self):
        self.output_dir.mkdir(exist_ok=True)

    def create_report(
        self,
        title: str,
        findings: List[ResearchFinding],
        executive_summary: Optional[str] = None,
        mitre_mappings: Optional[List[MITREMapping]] = None,
        threat_actor_profiles: Optional[list] = None,
        enrichment_summary: Optional[object] = None,
        framework_analysis: Optional[object] = None,
    ) -> str:
        filename = (
            f"{title.replace(' ', '_').replace(':', '')}"
            f"_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )
        filepath = self.output_dir / filename
        styles = _build_styles()

        doc = SimpleDocTemplate(
            str(filepath), pagesize=letter,
            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
            topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        )

        elements = []

        # ── Title & Timestamp ──
        elements.append(Paragraph(title, styles["ReportTitle"]))
        elements.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Timestamp"],
        ))
        elements.append(Spacer(1, 12))

        # ── Intelligence Assessment (if available) ──
        if framework_analysis and hasattr(framework_analysis, "assessment"):
            a = framework_analysis.assessment
            if a.overall_confidence != "Low" or a.key_judgments:
                elements.append(Paragraph("Intelligence Assessment", styles["SectionHeading"]))
                elements.append(Paragraph(
                    f"<b>Overall Confidence:</b> {_escape_xml(a.overall_confidence)}",
                    styles["FrameworkField"],
                ))
                elements.append(Paragraph(
                    f"<b>Source Reliability:</b> {_escape_xml(a.source_reliability)}",
                    styles["FrameworkField"],
                ))
                elements.append(Paragraph(
                    f"<b>Information Credibility:</b> {_escape_xml(a.information_credibility)}",
                    styles["FrameworkField"],
                ))
                if a.key_judgments:
                    elements.append(Spacer(1, 4))
                    elements.append(Paragraph("<b>Key Judgments:</b>", styles["FrameworkField"]))
                    for j in a.key_judgments:
                        elements.append(Paragraph(
                            f"  \u2022 {_escape_xml(j)}", styles["FrameworkField"]
                        ))
                if a.intelligence_gaps:
                    elements.append(Spacer(1, 4))
                    elements.append(Paragraph("<b>Intelligence Gaps:</b>", styles["FrameworkField"]))
                    for g in a.intelligence_gaps:
                        elements.append(Paragraph(
                            f"  \u2022 {_escape_xml(g)}", styles["FrameworkField"]
                        ))
                if a.collection_priorities:
                    elements.append(Spacer(1, 4))
                    elements.append(Paragraph(
                        "<b>Collection Priorities:</b>", styles["FrameworkField"]
                    ))
                    for p in a.collection_priorities:
                        elements.append(Paragraph(
                            f"  \u2022 {_escape_xml(p)}", styles["FrameworkField"]
                        ))
                elements.append(Spacer(1, 8))

        # ── Executive Summary ──
        if executive_summary:
            elements.append(Paragraph("Executive Summary", styles["SectionHeading"]))
            cleaned = _strip_markdown(executive_summary)
            for para in cleaned.split("\n\n"):
                if para.strip():
                    elements.append(Paragraph(_escape_xml(para.strip()), styles["BodyWrap"]))
            elements.append(Spacer(1, 6))

        # ── Key Intelligence Findings ──
        all_key_findings = []
        for f in findings:
            all_key_findings.extend(f.key_findings)

        if all_key_findings:
            elements.append(Paragraph(
                "Key Intelligence Findings", styles["SectionHeading"]
            ))
            for kf in all_key_findings:
                confidence_color = {
                    "High": "#228B22", "Moderate": "#DAA520", "Low": "#CC0000"
                }.get(kf.confidence, "#666666")

                elements.append(Paragraph(
                    f'\u2022 {_escape_xml(kf.finding)}<br/>'
                    f'<font size="8" color="#666666">'
                    f'Source: <a href="{kf.source_url}" color="blue">{_escape_xml(kf.source_title)}</a>'
                    f' | Confidence: <font color="{confidence_color}">{kf.confidence}</font>'
                    f'</font>',
                    styles["KeyFinding"],
                ))
            elements.append(Spacer(1, 8))

        # ── Severity Overview ──
        elements.append(Paragraph("Threat Severity Overview", styles["SectionHeading"]))

        table_data = [[
            Paragraph("Finding", styles["TableHeaderCell"]),
            Paragraph("Severity", styles["TableHeaderCell"]),
        ]]
        row_colors = []
        for f in findings:
            table_data.append([
                Paragraph(_escape_xml(f.topic), styles["TableCell"]),
                Paragraph(f.severity, styles["TableCellBold"]),
            ])
            row_colors.append(SEVERITY_COLORS.get(f.severity, colors.lightgrey))

        table = Table(table_data, colWidths=[5.0 * inch, 1.5 * inch])
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4472C4")),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#F2F2F2"), colors.white]),
        ]
        for i, color in enumerate(row_colors, start=1):
            style_cmds.append(("BACKGROUND", (1, i), (1, i), color))
            style_cmds.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
        table.setStyle(TableStyle(style_cmds))
        elements.append(table)
        elements.append(Spacer(1, 12))

        chart_img = _build_severity_chart(findings)
        elements.append(chart_img)

        # ── Diamond Model ──
        if framework_analysis and hasattr(framework_analysis, "diamond_model"):
            dm = framework_analysis.diamond_model
            if dm.adversary != "Unknown":
                elements.append(PageBreak())
                elements.append(Paragraph(
                    "Diamond Model Analysis", styles["SectionHeading"]
                ))
                for label, value in [
                    ("Adversary", dm.adversary),
                    ("Capability", dm.capability),
                    ("Infrastructure", dm.infrastructure),
                    ("Victim", dm.victim),
                    ("Meta-Features", dm.meta_features),
                ]:
                    if value:
                        elements.append(Paragraph(
                            f"<b>{label}:</b> {_escape_xml(value)}",
                            styles["FrameworkField"],
                        ))
                elements.append(Spacer(1, 8))

        # ── Cyber Kill Chain ──
        if framework_analysis and hasattr(framework_analysis, "kill_chain"):
            kc = framework_analysis.kill_chain
            if kc:
                elements.append(Paragraph(
                    "Cyber Kill Chain Analysis", styles["SectionHeading"]
                ))
                for phase in kc:
                    elements.append(Paragraph(
                        f"<b>{_escape_xml(phase.phase)}</b>", styles["SubHeading"]
                    ))
                    elements.append(Paragraph(
                        _escape_xml(phase.description), styles["FrameworkField"]
                    ))
                    if phase.evidence:
                        elements.append(Paragraph(
                            f"<i>Evidence:</i> {_escape_xml(phase.evidence)}",
                            styles["FrameworkField"],
                        ))
                    elements.append(Spacer(1, 4))

        # ── Detailed Findings ──
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Findings", styles["SectionHeading"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        elements.append(Spacer(1, 6))

        for finding in findings:
            elements.append(Paragraph(
                f'{finding.topic} '
                f'<font color="white" backColor="{SEVERITY_HEX.get(finding.severity, "#D3D3D3")}">'
                f'&nbsp;{finding.severity}&nbsp;</font>',
                styles["SubHeading"],
            ))

            elements.append(Paragraph("<b>Analysis:</b>", styles["BodyWrap"]))
            cleaned = _strip_markdown(finding.analysis)
            for para in cleaned.split("\n\n"):
                if para.strip():
                    elements.append(Paragraph(
                        _escape_xml(para.strip()), styles["BodyWrap"]
                    ))

            # IOCs
            iocs = finding.iocs
            ioc_pairs = [
                ("IPv4 Addresses", iocs.ipv4_addresses),
                ("Domains", iocs.domains),
                ("MD5 Hashes", iocs.md5_hashes),
                ("SHA-256 Hashes", iocs.sha256_hashes),
                ("CVE IDs", iocs.cve_ids),
                ("Emails", iocs.emails),
            ]
            if iocs.urls:
                ioc_pairs.append(("URLs", iocs.urls))
            if iocs.malware_names:
                ioc_pairs.append(("Malware Names", iocs.malware_names))

            if any(items for _, items in ioc_pairs):
                elements.append(Spacer(1, 4))
                elements.append(Paragraph(
                    "<b>Indicators of Compromise:</b>", styles["BodyWrap"]
                ))
                for label, items in ioc_pairs:
                    if items:
                        display_items = items[:MAX_IOCS_PER_TYPE_PER_FINDING]
                        suffix = ""
                        if len(items) > MAX_IOCS_PER_TYPE_PER_FINDING:
                            suffix = f" ... (+{len(items) - MAX_IOCS_PER_TYPE_PER_FINDING} more)"
                        elements.append(Paragraph(
                            f"<i>{label}:</i>  {', '.join(display_items)}{suffix}",
                            styles["IOCText"],
                        ))

            if finding.sources:
                elements.append(Spacer(1, 4))
                elements.append(Paragraph("<b>Sources:</b>", styles["BodyWrap"]))
                for idx, source in enumerate(finding.sources, 1):
                    safe_title = _escape_xml(source.title)
                    elements.append(Paragraph(
                        f'[{idx}] {safe_title} — '
                        f'<a href="{source.url}" color="blue">{source.url}</a>',
                        styles["SourceLink"],
                    ))

            elements.append(Spacer(1, 8))
            elements.append(HRFlowable(
                width="100%", thickness=0.5, color=colors.lightgrey,
            ))
            elements.append(Spacer(1, 8))

        # ── Threat Actor Profiles ──
        if threat_actor_profiles:
            elements.append(PageBreak())
            elements.append(Paragraph("Threat Actor Profiles", styles["SectionHeading"]))

            for profile in threat_actor_profiles:
                elements.append(Paragraph(
                    _escape_xml(profile.name), styles["SubHeading"]
                ))
                if profile.aliases:
                    elements.append(Paragraph(
                        f"<b>Aliases:</b> {_escape_xml(', '.join(profile.aliases))}",
                        styles["ActorField"],
                    ))
                elements.append(Paragraph(
                    f"<b>Motivation:</b> {_escape_xml(profile.motivation)}",
                    styles["ActorField"],
                ))
                elements.append(Paragraph(
                    f"<b>Sophistication:</b> {_escape_xml(profile.sophistication)}",
                    styles["ActorField"],
                ))
                if profile.primary_targets:
                    elements.append(Paragraph(
                        f"<b>Primary Targets:</b> {_escape_xml(', '.join(profile.primary_targets))}",
                        styles["ActorField"],
                    ))
                if profile.target_regions:
                    elements.append(Paragraph(
                        f"<b>Target Regions:</b> {_escape_xml(', '.join(profile.target_regions))}",
                        styles["ActorField"],
                    ))
                if profile.techniques:
                    elements.append(Paragraph(
                        f"<b>Techniques:</b> {_escape_xml(', '.join(profile.techniques))}",
                        styles["ActorField"],
                    ))
                if profile.malware_used:
                    elements.append(Paragraph(
                        f"<b>Malware Used:</b> {_escape_xml(', '.join(profile.malware_used))}",
                        styles["ActorField"],
                    ))
                elements.append(Paragraph(
                    f"<b>First Seen:</b> {_escape_xml(profile.first_seen)}",
                    styles["ActorField"],
                ))
                if profile.description:
                    elements.append(Spacer(1, 4))
                    elements.append(Paragraph(
                        _escape_xml(profile.description), styles["BodyWrap"]
                    ))
                if profile.associated_campaigns:
                    elements.append(Paragraph(
                        f"<b>Campaigns:</b> {_escape_xml(', '.join(profile.associated_campaigns))}",
                        styles["ActorField"],
                    ))
                elements.append(Spacer(1, 8))
                elements.append(HRFlowable(
                    width="100%", thickness=0.5, color=colors.lightgrey,
                ))
                elements.append(Spacer(1, 8))

        # ── IOC Enrichment Results ──
        if enrichment_summary and hasattr(enrichment_summary, "results") and enrichment_summary.results:
            elements.append(PageBreak())
            elements.append(Paragraph("IOC Enrichment Results", styles["SectionHeading"]))

            enrich_data = [[
                Paragraph("IOC", styles["TableHeaderCell"]),
                Paragraph("Type", styles["TableHeaderCell"]),
                Paragraph("Risk Score", styles["TableHeaderCell"]),
                Paragraph("Risk Level", styles["TableHeaderCell"]),
                Paragraph("Malicious", styles["TableHeaderCell"]),
            ]]
            enrich_row_colors = []
            for r in enrichment_summary.results:
                enrich_data.append([
                    Paragraph(_escape_xml(r.ioc_value), styles["TableCellMono"]),
                    Paragraph(_escape_xml(r.ioc_type), styles["TableCell"]),
                    Paragraph(str(r.risk_score), styles["TableCell"]),
                    Paragraph(_escape_xml(r.risk_level), styles["TableCell"]),
                    Paragraph("Yes" if r.malicious else "No", styles["TableCell"]),
                ])
                if r.risk_score >= 60:
                    enrich_row_colors.append(colors.HexColor("#FFCCCC"))
                elif r.risk_score >= 40:
                    enrich_row_colors.append(colors.HexColor("#FFF3CC"))
                else:
                    enrich_row_colors.append(colors.HexColor("#CCFFCC"))

            enrich_table = Table(
                enrich_data,
                colWidths=[2.2 * inch, 0.7 * inch, 0.9 * inch, 0.9 * inch, 0.8 * inch],
            )
            enrich_style_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4472C4")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (2, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ]
            for i, bg in enumerate(enrich_row_colors, start=1):
                enrich_style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))
            enrich_table.setStyle(TableStyle(enrich_style_cmds))
            elements.append(enrich_table)

            high_risk = [r for r in enrichment_summary.results if r.risk_score >= 60]
            if high_risk:
                elements.append(Spacer(1, 12))
                elements.append(Paragraph("High-Risk IOC Details", styles["SubHeading"]))
                for r in high_risk:
                    elements.append(Paragraph(
                        f"<b>{_escape_xml(r.ioc_value)}</b> ({r.ioc_type}) — "
                        f"Risk Score: {r.risk_score}",
                        styles["BodyWrap"],
                    ))
                    for source_name, source_data in r.sources.items():
                        parts = [f"{k}: {v}" for k, v in source_data.items() if k != "risk_score"]
                        if parts:
                            elements.append(Paragraph(
                                f"<i>{_escape_xml(source_name)}:</i> {_escape_xml(', '.join(parts))}",
                                styles["IOCText"],
                            ))
                    elements.append(Spacer(1, 6))

        # ── MITRE ATT&CK Mappings ──
        if mitre_mappings:
            elements.append(PageBreak())
            elements.append(Paragraph(
                "MITRE ATT&CK Technique Mappings", styles["SectionHeading"]
            ))

            mitre_data = [[
                Paragraph("Tactic", styles["TableHeaderCell"]),
                Paragraph("Technique ID", styles["TableHeaderCell"]),
                Paragraph("Technique", styles["TableHeaderCell"]),
                Paragraph("Confidence", styles["TableHeaderCell"]),
            ]]
            for m in mitre_mappings:
                mitre_data.append([
                    Paragraph(_escape_xml(m.tactic), styles["TableCell"]),
                    Paragraph(_escape_xml(m.technique_id), styles["TableCell"]),
                    Paragraph(_escape_xml(m.technique), styles["TableCell"]),
                    Paragraph(_escape_xml(m.confidence), styles["TableCell"]),
                ])

            mitre_table = Table(
                mitre_data,
                colWidths=[1.6 * inch, 1.1 * inch, 2.5 * inch, 1.0 * inch],
            )
            mitre_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4472C4")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#F2F2F2"), colors.white]),
            ]))
            elements.append(mitre_table)

        # ── Consolidated IOC Summary ──
        all_ips, all_domains, all_md5s = set(), set(), set()
        all_sha256s, all_cves, all_emails = set(), set(), set()
        all_urls, all_malware = set(), set()
        for f in findings:
            all_ips.update(f.iocs.ipv4_addresses)
            all_domains.update(f.iocs.domains)
            all_md5s.update(f.iocs.md5_hashes)
            all_sha256s.update(f.iocs.sha256_hashes)
            all_cves.update(f.iocs.cve_ids)
            all_emails.update(f.iocs.emails)
            all_urls.update(f.iocs.urls)
            all_malware.update(f.iocs.malware_names)

        any_iocs = any([
            all_ips, all_domains, all_md5s, all_sha256s,
            all_cves, all_emails, all_urls, all_malware,
        ])
        if any_iocs:
            elements.append(PageBreak())
            elements.append(Paragraph(
                "Consolidated Indicators of Compromise", styles["SectionHeading"]
            ))
            total_ioc_count = (
                len(all_ips) + len(all_domains) + len(all_urls)
                + len(all_md5s) + len(all_sha256s) + len(all_cves)
                + len(all_emails) + len(all_malware)
            )
            elements.append(Paragraph(
                f"<i>Total unique indicators extracted: {total_ioc_count}</i>",
                styles["Timestamp"],
            ))
            elements.append(Spacer(1, 6))
            for label, items in [
                ("IPv4 Addresses", sorted(all_ips)),
                ("Domains", sorted(all_domains)),
                ("URLs", sorted(all_urls)),
                ("MD5 Hashes", sorted(all_md5s)),
                ("SHA-256 Hashes", sorted(all_sha256s)),
                ("CVE IDs", sorted(all_cves)),
                ("Emails", sorted(all_emails)),
                ("Malware Names", sorted(all_malware)),
            ]:
                if items:
                    cap = MAX_IOCS_PER_TYPE_CONSOLIDATED
                    count_note = ""
                    if len(items) > cap:
                        count_note = f" (showing {cap} of {len(items)})"
                    elements.append(Paragraph(
                        f"<b>{label}{count_note}</b>", styles["BodyWrap"]
                    ))
                    for item in items[:cap]:
                        elements.append(Paragraph(item, styles["IOCText"]))
                    elements.append(Spacer(1, 6))

        doc.build(elements)
        return str(filepath)
