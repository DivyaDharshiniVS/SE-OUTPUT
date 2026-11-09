"""
manual_generator.py - Automated Operational & User Manual PDF Engine
AI-Based Network Intrusion Detection System

Generates a publication-grade, professionally structured operational manual
documenting the complete architecture, machine learning pipeline, authentication,
traffic scanning, and software engineering tools.
"""

import io
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    HRFlowable
)
from reportlab.pdfgen import canvas

# ------------------------------------------------------------------------------
# TWO-PASS NUMBERED CANVAS FOR "PAGE X OF Y" PAGINATION
# ------------------------------------------------------------------------------

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and print total page count
    along with running header rules and confidentiality footers.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        page_w, page_h = letter

        # Running Top Header (pages 2 and onward)
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#102621"))
            self.drawString(54, page_h - 36, "AI-BASED NETWORK INTRUSION DETECTION SYSTEM (NIDS)")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748B"))
            self.drawRightString(page_w - 54, page_h - 36, "OPERATIONAL MANUAL & ARCHITECTURAL SPEC")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.6)
            self.line(54, page_h - 40, page_w - 54, page_h - 40)

        # Running Bottom Footer
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.6)
        self.line(54, 46, page_w - 54, 46)

        self.setFont("Helvetica", 8.5)
        self.setFillColor(colors.HexColor("#475569"))
        self.drawString(54, 32, "AI-BASED NETWORK INTRUSION DETECTION SYSTEM (NIDS)")
        footer_text = f"Page {self._pageNumber} of {page_count} | Confidential - Cyber Defense SOC"
        self.drawRightString(page_w - 54, 32, footer_text)

        self.restoreState()


# ------------------------------------------------------------------------------
# CORE PDF BUILDER FUNCTION
# ------------------------------------------------------------------------------

def generate_nids_user_manual_pdf() -> bytes:
    """
    Generates the complete publication-grade User Manual PDF for the NIDS platform.
    Returns the binary PDF content as bytes.
    """
    buffer = io.BytesIO()

    # 0.75 in margins = 54 pt
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Document Title Style (14 pt, Bold, Uppercase, Center, Forest Emerald)
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#102621"),
        spaceAfter=6
    )

    # Document Subtitle Style
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#92400E"),
        spaceAfter=12
    )

    # Section 1 Heading (Deep Navy / Slate Blue: #1E3A8A)
    heading_sec1 = ParagraphStyle(
        "HeadingSec1",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    # Section 2 Heading (Emerald Green: #0D5F46)
    heading_sec2 = ParagraphStyle(
        "HeadingSec2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#0D5F46"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    # Section 3 Heading (Burgundy / Crimson: #991B1B)
    heading_sec3 = ParagraphStyle(
        "HeadingSec3",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#991B1B"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    # Section 4 Heading (Dark Amber / Bronze: #92400E)
    heading_sec4 = ParagraphStyle(
        "HeadingSec4",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#92400E"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    # Body Text Style (12 pt, Justified, Strict Black #000000)
    body_style = ParagraphStyle(
        "BodyJustified",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        alignment=TA_JUSTIFY,
        textColor=colors.HexColor("#000000"),
        spaceAfter=8
    )

    # Technical Callout Text Style (12 pt, Justified, Strict Black #000000)
    callout_text_style = ParagraphStyle(
        "CalloutText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        alignment=TA_JUSTIFY,
        textColor=colors.HexColor("#000000")
    )

    # Code / ASCII Flow Style
    ascii_flow_style = ParagraphStyle(
        "AsciiFlow",
        parent=styles["Normal"],
        fontName="Courier-Bold",
        fontSize=9.5,
        leading=13,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0D5F46")
    )

    story = []

    # --------------------------------------------------------------------------
    # DOCUMENT HEADER
    # --------------------------------------------------------------------------
    story.append(Paragraph("AI-BASED NETWORK INTRUSION DETECTION SYSTEM: OPERATIONAL & USER MANUAL", title_style))
    story.append(Paragraph("Enterprise Platform Documentation &bull; Autonomous Cyber Defense SOC Runbook", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#E2B96F"), spaceBefore=2, spaceAfter=14))

    # --------------------------------------------------------------------------
    # SECTION 1: ARCHITECTURE & SYSTEM OVERVIEW (Deep Navy: #1E3A8A)
    # --------------------------------------------------------------------------
    story.append(Paragraph("1. System Overview & Core Architecture", heading_sec1))
    story.append(Paragraph(
        "The AI-Based Network Intrusion Detection System (NIDS) is a specialized cyber defense platform designed "
        "to ingest, analyze, and classify high-velocity network packet flow telemetry in real time. Built upon an "
        "ensemble Scikit-Learn Random Forest Classifier, the system achieves a benchmark detection accuracy of "
        "98.6% across diverse attack vectors. Telemetry attributes extracted from standard NetFlow and NSL-KDD formats "
        "include flow duration, protocol type, service identification, TCP flag profiles, source bytes, destination bytes, "
        "serror rate, same-service rate, and destination host service density. The ingestion pipeline extracts 24 one-hot "
        "encoded numerical dimensions, enabling robust separation between legitimate baseline traffic and anomalous intrusions.",
        body_style
    ))

    # Flowchart Callout Box
    flow_content = [
        [Paragraph("<strong>PIPELINE FLOW DIAGRAM:</strong>", ParagraphStyle("H", parent=ascii_flow_style, fontSize=9, textColor=colors.HexColor("#1E3A8A")))],
        [Paragraph("[Packet Ingestion] &rarr; [Feature Preprocessing] &rarr; [RandomForest Inference] &rarr; [Threat Classification] &rarr; [SOC Alert & Mitigation]", ascii_flow_style)]
    ]
    t_flow = Table(flow_content, colWidths=[doc.width])
    t_flow.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ('BOX', (0, 0), (-1, -1), 1.2, colors.HexColor("#1E3A8A")),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(t_flow)
    story.append(Spacer(1, 10))

    # Screenshot Placeholder 1
    sc1_content = [
        [Paragraph("<strong>[Figure 1: Network Traffic Scanner Interface & Defense Radar]</strong>", ParagraphStyle("FigTitle", parent=callout_text_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#1E3A8A")))],
        [Paragraph("<em>Screenshot Callout: Captures the primary dual-column scanning console illustrating real-time packet stream counters, active protocol distribution widgets, and anomalous flow detection cards.</em>", callout_text_style)]
    ]
    t_sc1 = Table(sc1_content, colWidths=[doc.width])
    t_sc1.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.HexColor("#E2E8F0")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t_sc1)
    story.append(Spacer(1, 10))

    # --------------------------------------------------------------------------
    # SECTION 2: AUTHENTICATION & SOC ACCESS (Emerald Green: #0D5F46)
    # --------------------------------------------------------------------------
    story.append(Paragraph("2. Analyst Authentication & Session Management", heading_sec2))
    story.append(Paragraph(
        "The platform enforces Role-Based Access Control (RBAC) powered by an embedded SQLite credential repository "
        "(nids_platform.db). Every operator password undergoes salted SHA-256 cryptographic hashing prior to storage. "
        "The system distinguishes between public observers and authenticated SOC personnel. While all users may inspect "
        "source code, model metrics, and traffic visualizations, administrative operations such as committing incident "
        "records into SQLite, purging audit logs, and updating external infrastructure links strictly require an authenticated "
        "session. Default credentials are pre-seeded upon initialization (Username: admin, Password: admin123, Role: SOC Admin).",
        body_style
    ))
    story.append(Paragraph(
        "Supported operational roles include SOC Analyst (daily telemetry triage and alert inspection), Security Admin "
        "(policy orchestration and system configuration), Incident Responder (containment and mitigation dispatch), and "
        "Lead Security Analyst (comprehensive audit governance). Analysts may authenticate or register via the Champagne "
        "Gold modal portal located in the top utility header.",
        body_style
    ))

    # --------------------------------------------------------------------------
    # SECTION 3: MODULE WALKTHROUGHS & SCANNERS (Burgundy: #991B1B)
    # --------------------------------------------------------------------------
    story.append(Paragraph("3. Dual-Column Scanner & The 3 Platform Modules", heading_sec3))
    story.append(Paragraph(
        "The primary analytical capabilities are organized across a unified dual-column dashboard and three focused modules. "
        "Module 1 (Network Traffic Analysis) ingests packet captures or the 1-click synthetic benchmark (120 NetFlow packets), "
        "validating column dimensions, checking null values, and plotting statistical distributions for TCP connection flags "
        "(SF, S0, REJ), service endpoints (HTTP, DNS, SSH, SMTP), and byte volumetric ratios.",
        body_style
    ))

    # Screenshot Placeholder 2
    sc2_content = [
        [Paragraph("<strong>[Figure 2: AI Model Evaluation & Feature Importance Analysis]</strong>", ParagraphStyle("FigTitle", parent=callout_text_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#991B1B")))],
        [Paragraph("<em>Screenshot Callout: Captures the interactive Scikit-Learn confusion matrix, classification metrics (Accuracy, Precision, Recall, F1), and Plotly bar charts ranking top features such as src_bytes and serror_rate.</em>", callout_text_style)]
    ]
    t_sc2 = Table(sc2_content, colWidths=[doc.width])
    t_sc2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#FDF2F2")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#FCA5A5")),
        ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.HexColor("#FEE2E2")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t_sc2)
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "Module 2 (AI-Based Intrusion Detection) executes the trained Random Forest classifier over the active stream, "
        "categorizing packets into Normal Traffic or distinct threat classes: Denial-of-Service (SYN Flood), Reconnaissance "
        "(PortScan), and Unauthorized Host Access. Dynamic confidence metrics and interactive Plotly confusion matrices "
        "provide mathematical verification without hard-coded estimates.",
        body_style
    ))
    story.append(Paragraph(
        "Module 3 (Security Dashboard, Alerts & Reports) aggregates high-severity alerts into an incident response console. "
        "For each detected threat, actionable containment directives and automated firewall drop rules (e.g., iptables -A "
        "INPUT -s [attacker_ip] -j DROP) are generated. Authenticated operators may commit scan batches into SQLite or export "
        "forensic audit reports as formatted CSV files.",
        body_style
    ))

    # Screenshot Placeholder 3
    sc3_content = [
        [Paragraph("<strong>[Figure 3: Security Incident Alert Feed & Actionable Mitigation Panel]</strong>", ParagraphStyle("FigTitle", parent=callout_text_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#991B1B")))],
        [Paragraph("<em>Screenshot Callout: Illustrates real-time alert triage cards with severity badges (Critical, High), source IP indicators, and machine-generated firewall isolation rules.</em>", callout_text_style)]
    ]
    t_sc3 = Table(sc3_content, colWidths=[doc.width])
    t_sc3.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#FDF2F2")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#FCA5A5")),
        ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.HexColor("#FEE2E2")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t_sc3)
    story.append(Spacer(1, 10))

    # --------------------------------------------------------------------------
    # SECTION 4: SE TOOLS & DEVOPS INTEGRATION (Dark Amber: #92400E)
    # --------------------------------------------------------------------------
    story.append(Paragraph("4. Software Engineering Tools & DevOps Pipeline", heading_sec4))
    story.append(Paragraph(
        "Demonstrating end-to-end alignment with modern software engineering practices, the application embeds eight "
        "integrated tools spanning the complete Software Development Life Cycle (SDLC): GitHub (branching model and staged "
        "monorepo), Vercel / Edge (serverless hosting descriptor), Jira (7 Epics, 14 User Stories, sprint velocity), Confluence "
        "(4 comprehensive engineering volumes), Figma (Executive Dark Emerald design tokens), Docker (hardened non-root "
        "multi-stage container), Kubernetes (Deployment, Service, HPA, ConfigMap manifests), and CI/CD (GitHub Actions automated "
        "verification pipeline).",
        body_style
    ))
    story.append(Paragraph(
        "Analysts can inspect architectural blueprints in Tab 3, synchronize cloud endpoints in Tab 4, or scan the high-resolution "
        "vector QR code in Tab 5 to launch the platform directly on mobile devices over the local network (bound to 0.0.0.0:8501). "
        "All configuration files (Dockerfile, deployment.yaml, ci.yml, vercel.json) are downloadable on demand.",
        body_style
    ))

    # Screenshot Placeholder 4
    sc4_content = [
        [Paragraph("<strong>[Figure 4: Software Engineering DevOps Pipeline & Kubernetes Manifests]</strong>", ParagraphStyle("FigTitle", parent=callout_text_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#92400E")))],
        [Paragraph("<em>Screenshot Callout: Highlights the production-grade Kubernetes manifest viewer, Docker container healthcheck metrics, and active GitHub Actions automated verification indicators.</em>", callout_text_style)]
    ]
    t_sc4 = Table(sc4_content, colWidths=[doc.width])
    t_sc4.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#FFFBEB")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#FCD34D")),
        ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.HexColor("#FEF3C7")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(t_sc4)

    # Build PDF with custom NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

if __name__ == "__main__":
    data = generate_nids_user_manual_pdf()
    with open("NIDS_User_Manual.pdf", "wb") as f:
        f.write(data)
    print(f"Generated NIDS_User_Manual.pdf successfully ({len(data)} bytes).")
