import io
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func
import models
from geoip import get_country_for_ip

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_pdf_report(db: Session) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a')
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569')
    )

    section_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#00f2fe'),
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#334155')
    )

    elements = []

    # 1. Header Banner
    elements.append(Paragraph("🛡️ CyberSentinel — Executive Threat Analysis Report", title_style))
    elements.append(Paragraph(f"Generated On: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Intrusion Detection & Traffic Forensics", subtitle_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#00f2fe'), spaceAfter=15))

    # 2. Key Metrics Summary Table
    total_packets = db.query(models.PacketLog).count()
    total_alerts = db.query(models.Alert).count()
    critical_alerts = db.query(models.Alert).filter(models.Alert.severity == "CRITICAL").count()
    high_alerts = db.query(models.Alert).filter(models.Alert.severity == "HIGH").count()
    medium_alerts = db.query(models.Alert).filter(models.Alert.severity == "MEDIUM").count()

    metrics_data = [
        [
            Paragraph("<b>Total Packets Analyzed</b>", body_style),
            Paragraph(f"<b>{total_packets:,}</b>", body_style),
            Paragraph("<b>Critical Threats Flagged</b>", body_style),
            Paragraph(f"<font color='#dc2626'><b>{critical_alerts}</b></font>", body_style)
        ],
        [
            Paragraph("<b>Total Incidents Logged</b>", body_style),
            Paragraph(f"<b>{total_alerts}</b>", body_style),
            Paragraph("<b>High / Warning Attacks</b>", body_style),
            Paragraph(f"<font color='#d97706'><b>{high_alerts}</b></font>", body_style)
        ]
    ]

    metrics_table = Table(metrics_data, colWidths=[140, 100, 140, 100])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(Paragraph("System Overview Metrics", section_style))
    elements.append(metrics_table)
    elements.append(Spacer(1, 15))

    # 3. Top Attacker IPs Table
    top_src_query = db.query(
        models.Alert.source_ip, 
        func.count(models.Alert.id).label("count")
    ).group_by(models.Alert.source_ip).order_by(func.count(models.Alert.id).desc()).limit(5).all()

    elements.append(Paragraph("Top Malicious Origin IPs (Attacker Summary)", section_style))

    top_ip_rows = [["Attacker Source IP", "Country Location", "Incidents Triggered", "Threat Rank"]]
    for idx, item in enumerate(top_src_query, 1):
        ip = item[0] or "Unknown"
        count = item[1]
        country = get_country_for_ip(ip)
        top_ip_rows.append([ip, country, str(count), f"#{idx}"])

    if len(top_ip_rows) == 1:
        top_ip_rows.append(["No active attack sources logged", "-", "0", "-"])

    ip_table = Table(top_ip_rows, colWidths=[130, 150, 120, 80])
    ip_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ffffff')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(ip_table)
    elements.append(Spacer(1, 15))

    # 4. Recent Security Alerts Incident Audit Log
    elements.append(Paragraph("Recent Critical Incident Log (Sample)", section_style))

    recent_alerts = db.query(models.Alert).order_by(models.Alert.id.desc()).limit(8).all()
    alert_rows = [["Rule Triggered", "Severity", "Attacker IP", "Victim IP", "Description"]]

    for a in recent_alerts:
        alert_rows.append([
            Paragraph(f"<b>{a.rule_name}</b>", body_style),
            Paragraph(f"<font color='{get_sev_color(a.severity)}'><b>{a.severity}</b></font>", body_style),
            Paragraph(a.source_ip or "Unknown", body_style),
            Paragraph(a.dest_ip or "Unknown", body_style),
            Paragraph(a.description[:50] + "..." if len(a.description) > 50 else a.description, body_style)
        ])

    if len(alert_rows) == 1:
        alert_rows.append(["No incidents recorded", "-", "-", "-", "-"])

    alert_table = Table(alert_rows, colWidths=[110, 60, 95, 95, 120])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(alert_table)
    elements.append(Spacer(1, 20))

    # 5. Report Signature & Confidentiality Notice
    footer_text = Paragraph(
        "<i>CONFIDENTIAL SECURITY REPORT — CyberSentinel Intrusion Detection System. Automated forensic compilation.</i>",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=7, textColor=colors.HexColor('#94a3b8'), alignment=1)
    )
    elements.append(footer_text)

    doc.build(elements)
    buffer.seek(0)
    return buffer

def get_sev_color(severity: str) -> str:
    if severity == "CRITICAL": return "#dc2626"
    if severity == "HIGH": return "#d97706"
    if severity == "MEDIUM": return "#2563eb"
    return "#16a34a"
