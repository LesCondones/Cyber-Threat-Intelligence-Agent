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
    PageBreak, HRFlowable, XPreformatted, KeepTogether,
)

from agents.subagent import ResearchFinding
from agents.mitre_mapper import MITREMapping
from agents.source_classifier import classify_source


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

PRIORITY_COLORS = {
    "Critical": colors.HexColor("#FFC7C7"),
    "High": colors.HexColor("#FFE0B2"),
    "Medium": colors.HexColor("#FFF6B2"),
    "Low": colors.HexColor("#D9F2D9"),
}

THREAT_STATUS_COLORS = {
    "Active": "#CC0000",
    "Historical": "#666699",
    "Anticipated": "#0066CC",
    "Unknown": "#777777",
}

# Canonical Lockheed Martin Cyber Kill Chain phases
KILL_CHAIN_PHASES = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command and Control", "Actions on Objectives",
]


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
    styles.add(ParagraphStyle(
        name="TLDRBullet", parent=styles["BodyText"],
        fontSize=11, leading=15, spaceAfter=4,
        leftIndent=14, textColor=colors.HexColor("#1a1a2e"),
    ))
    styles.add(ParagraphStyle(
        name="CodeBlock", parent=styles["BodyText"],
        fontSize=8, leading=10, fontName="Courier",
        leftIndent=8, rightIndent=8, spaceAfter=6,
        backColor=colors.HexColor("#F4F4F4"),
        borderColor=colors.HexColor("#CCCCCC"),
        borderWidth=0.5, borderPadding=6,
    ))
    styles.add(ParagraphStyle(
        name="RecommendationAction", parent=styles["BodyText"],
        fontSize=10, leading=14, spaceAfter=2,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="RecommendationMeta", parent=styles["BodyText"],
        fontSize=9, leading=12, spaceAfter=4,
        textColor=colors.HexColor("#444444"),
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


def _build_kill_chain_diagram(kill_chain_phases) -> Image:
    """Render a horizontal Kill Chain flow showing which phases have evidence."""
    observed = {p.phase: p for p in kill_chain_phases}

    fig, ax = plt.subplots(figsize=(7, 1.8))
    n = len(KILL_CHAIN_PHASES)
    x_positions = list(range(n))

    for i, phase in enumerate(KILL_CHAIN_PHASES):
        has_evidence = phase in observed
        face_color = "#FF6B6B" if has_evidence else "#E0E0E0"
        edge_color = "#CC0000" if has_evidence else "#A0A0A0"

        ax.add_patch(plt.Rectangle(
            (i - 0.42, 0.3), 0.84, 0.6,
            facecolor=face_color, edgecolor=edge_color, linewidth=1.5,
        ))
        # Wrap long phase names
        label = phase.replace("Command and Control", "C2")
        ax.text(i, 0.6, label, ha="center", va="center",
                fontsize=8, fontweight="bold",
                color="white" if has_evidence else "#666666")

        # Arrow to next phase
        if i < n - 1:
            ax.annotate(
                "", xy=(i + 0.58, 0.6), xytext=(i + 0.42, 0.6),
                arrowprops=dict(
                    arrowstyle="->",
                    color="#999999",
                    lw=1.2,
                ),
            )

    ax.set_xlim(-0.6, n - 0.4)
    ax.set_ylim(0, 1.2)
    ax.set_aspect("auto")
    ax.axis("off")
    ax.set_title(
        "Cyber Kill Chain — Observed Phases",
        fontsize=11, fontweight="bold", pad=8,
    )
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return Image(buf, width=7 * inch, height=1.8 * inch)


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
        tldr_bullets: Optional[List[str]] = None,
        threat_status: Optional[str] = None,
        recommendations: Optional[list] = None,
        detection_logic: Optional[object] = None,
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

        # ── Title & Timeliness Header ──
        elements.append(Paragraph(title, styles["ReportTitle"]))

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = (threat_status or "Unknown").strip() or "Unknown"
        status_color = THREAT_STATUS_COLORS.get(status, "#777777")
        timeliness_line = (
            f"<b>Intelligence Collected:</b> {now_str} &nbsp;|&nbsp; "
            f"<b>Threat Status:</b> "
            f'<font color="{status_color}"><b>{_escape_xml(status)}</b></font>'
        )
        elements.append(Paragraph(timeliness_line, styles["Timestamp"]))
        elements.append(Spacer(1, 10))

        # ── TL;DR Card ──
        if tldr_bullets:
            tldr_inner = [
                Paragraph(
                    f'<b>TL;DR — Executive Read</b>',
                    ParagraphStyle(
                        name="TLDRTitle", parent=styles["BodyText"],
                        fontSize=12, leading=14, spaceAfter=6,
                        textColor=colors.white,
                    ),
                ),
            ]
            for bullet in tldr_bullets:
                tldr_inner.append(Paragraph(
                    f"&bull; {_escape_xml(bullet)}", styles["TLDRBullet"]
                ))
            tldr_table = Table(
                [[item] for item in tldr_inner],
                colWidths=[7.0 * inch],
            )
            tldr_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8F9FB")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#16213e")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ]))
            elements.append(tldr_table)
            elements.append(Spacer(1, 12))

        # ── Intelligence Assessment (if available) ──
        if framework_analysis and hasattr(framework_analysis, "assessment"):
            a = framework_analysis.assessment
            if a.overall_confidence != "Low" or a.key_judgments:
                elements.append(Paragraph("Intelligence Assessment", styles["SectionHeading"]))
                # Confidence / reliability / credibility on one line \u2014 three
                # separate paragraphs was needless vertical bloat.
                elements.append(Paragraph(
                    f"<b>Confidence:</b> {_escape_xml(a.overall_confidence)} "
                    f"&nbsp;|&nbsp; <b>Source Reliability:</b> {_escape_xml(a.source_reliability)} "
                    f"&nbsp;|&nbsp; <b>Info Credibility:</b> {_escape_xml(a.information_credibility)}",
                    styles["FrameworkField"],
                ))
                # Key judgments are only shown here when there is no TL;DR card;
                # otherwise the TL;DR already carries them in executive language.
                if a.key_judgments and not tldr_bullets:
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

        # ── Prioritized Recommendations ──
        if recommendations:
            elements.append(Paragraph(
                "Prioritized Recommendations", styles["SectionHeading"]
            ))
            elements.append(Paragraph(
                "<i>Each item is specific enough to assign as a ticket. "
                "Priority reflects active exploitation, scope, and ease of exploit.</i>",
                styles["BodyWrap"],
            ))
            elements.append(Spacer(1, 4))

            rec_data = [[
                Paragraph("Priority", styles["TableHeaderCell"]),
                Paragraph("Action", styles["TableHeaderCell"]),
                Paragraph("Owner", styles["TableHeaderCell"]),
                Paragraph("Rationale & References", styles["TableHeaderCell"]),
            ]]
            rec_row_colors = []
            for rec in recommendations:
                refs = ""
                if rec.references:
                    refs = (
                        f'<br/><font size="8" color="#666666">'
                        f'Refs: {_escape_xml(", ".join(rec.references[:6]))}'
                        f'</font>'
                    )
                rec_data.append([
                    Paragraph(rec.priority, styles["TableCellBold"]),
                    Paragraph(_escape_xml(rec.action), styles["TableCell"]),
                    Paragraph(_escape_xml(rec.target), styles["TableCell"]),
                    Paragraph(_escape_xml(rec.rationale) + refs, styles["TableCell"]),
                ])
                rec_row_colors.append(
                    PRIORITY_COLORS.get(rec.priority, colors.HexColor("#F2F2F2"))
                )

            rec_table = Table(
                rec_data,
                colWidths=[0.85 * inch, 2.3 * inch, 1.2 * inch, 2.65 * inch],
            )
            rec_style_cmds = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4472C4")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (0, 0), (0, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
            for i, bg in enumerate(rec_row_colors, start=1):
                rec_style_cmds.append(("BACKGROUND", (0, i), (0, i), bg))
            rec_table.setStyle(TableStyle(rec_style_cmds))
            elements.append(rec_table)
            elements.append(Spacer(1, 10))

        # ── Detection Logic ──
        if detection_logic and detection_logic.has_any():
            elements.append(PageBreak())
            elements.append(Paragraph("Detection Logic", styles["SectionHeading"]))
            elements.append(Paragraph(
                "<i>Deployable detection content grounded in the observed TTPs "
                "and IOCs. Review and tune before promoting to production.</i>",
                styles["BodyWrap"],
            ))
            elements.append(Spacer(1, 6))

            def _code_blocks(section_heading, items, getters):
                if not items:
                    return
                elements.append(Paragraph(
                    f"<b>{section_heading}</b>", styles["SubHeading"],
                ))
                for item in items:
                    title_field, desc_field, body_field = getters
                    title_val = getattr(item, title_field)
                    desc_val = getattr(item, desc_field)
                    body_val = getattr(item, body_field)
                    elements.append(KeepTogether([
                        Paragraph(
                            f"<b>{_escape_xml(title_val)}</b>",
                            styles["RecommendationAction"],
                        ),
                        Paragraph(
                            f"<i>{_escape_xml(desc_val)}</i>",
                            styles["RecommendationMeta"],
                        ),
                        XPreformatted(
                            _escape_xml(body_val.rstrip()),
                            styles["CodeBlock"],
                        ),
                        Spacer(1, 6),
                    ]))

            _code_blocks(
                "Sigma Rules", detection_logic.sigma_rules,
                ("title", "description", "yaml"),
            )
            _code_blocks(
                "YARA Rules", detection_logic.yara_rules,
                ("name", "description", "body"),
            )
            _code_blocks(
                "Splunk SPL Hunts", detection_logic.splunk_queries,
                ("title", "description", "query"),
            )
            _code_blocks(
                "Microsoft KQL Hunts", detection_logic.kql_queries,
                ("title", "description", "query"),
            )

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
                elements.append(_build_kill_chain_diagram(kc))
                elements.append(Spacer(1, 6))
                # One compact line per observed phase — the diagram already
                # conveys which phases have evidence, so drop the per-phase
                # sub-headings and fold evidence inline.
                for phase in kc:
                    line = f"<b>{_escape_xml(phase.phase)}:</b> {_escape_xml(phase.description)}"
                    if phase.evidence:
                        line += (
                            f" <font color='#666666'><i>(Evidence: "
                            f"{_escape_xml(phase.evidence)})</i></font>"
                        )
                    elements.append(Paragraph(line, styles["FrameworkField"]))

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
                    tag = classify_source(source.url)
                    tag_tag = (
                        f' <font size="8" color="#666666">'
                        f'[{_escape_xml(tag.category)}]</font>'
                    )
                    elements.append(Paragraph(
                        f'[{idx}] {safe_title}{tag_tag} — '
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
