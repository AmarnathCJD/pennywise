"""
Enhanced Export Manager for PennyWise.
Generates professional security reports in multiple formats: PDF, HTML, JSON, XML.
"""

import json
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from io import BytesIO
import base64

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ExportManager:
    """
    Professional report exporter for vulnerability scan results.
    Supports PDF, HTML, JSON, and XML formats.
    """
    
    def __init__(self, scan_data: Dict[str, Any]):
        """
        Initialize the export manager.
        
        Args:
            scan_data: Dictionary containing scan results with structure:
                {
                    'target': str,
                    'timestamp': str,
                    'findings': List[Dict],
                    'summary': Dict,
                    'severity_breakdown': Dict
                }
        """
        self.data = scan_data
        self.timestamp = scan_data.get('timestamp', datetime.now().isoformat())
        self.target = scan_data.get('target', 'Unknown')
        self.findings = scan_data.get('findings', [])
        self.summary = scan_data.get('summary', {})
        self.severity_breakdown = scan_data.get('severity_breakdown', {})
    
    def export_json(self) -> str:
        """Export as JSON string."""
        report = {
            'report_metadata': {
                'title': f'PennyWise Security Scan Report',
                'generated_at': datetime.now().isoformat(),
                'target': self.target,
                'scanner_version': '2.0.0'
            },
            'scan_summary': {
                'target_url': self.target,
                'scan_timestamp': self.timestamp,
                'total_findings': len(self.findings),
                'pages_scanned': self.summary.get('pages_crawled', self.summary.get('pages_scanned', 0)),
                'requests_made': self.summary.get('requests_made', 0),
                'duration_seconds': self.summary.get('duration_seconds', 0),
                'severity_breakdown': self.severity_breakdown
            },
            'findings': self.findings,
            'risk_assessment': self._calculate_risk_level()
        }
        return json.dumps(report, indent=2, default=str)
    
    def export_xml(self) -> str:
        """Export as XML string."""
        root = ET.Element('SecurityScanReport')
        root.set('version', '2.0')
        root.set('generated', datetime.now().isoformat())
        
        # Metadata
        metadata = ET.SubElement(root, 'Metadata')
        ET.SubElement(metadata, 'Title').text = 'PennyWise Security Scan Report'
        ET.SubElement(metadata, 'Target').text = self.target
        ET.SubElement(metadata, 'ScanTimestamp').text = self.timestamp
        ET.SubElement(metadata, 'Scanner').text = 'PennyWise v2.0.0'
        
        # Summary
        summary = ET.SubElement(root, 'Summary')
        ET.SubElement(summary, 'TotalFindings').text = str(len(self.findings))
        ET.SubElement(summary, 'PagesScanned').text = str(self.summary.get('pages_crawled', self.summary.get('pages_scanned', 0)))
        ET.SubElement(summary, 'RequestsMade').text = str(self.summary.get('requests_made', 0))
        ET.SubElement(summary, 'Duration').text = str(self.summary.get('duration_seconds', 0))
        
        # Severity Breakdown
        severity = ET.SubElement(summary, 'SeverityBreakdown')
        for level, count in self.severity_breakdown.items():
            sev_elem = ET.SubElement(severity, 'Severity')
            sev_elem.set('level', level.upper())
            sev_elem.text = str(count)
        
        # Risk Assessment
        risk = ET.SubElement(root, 'RiskAssessment')
        risk_level = self._calculate_risk_level()
        ET.SubElement(risk, 'OverallRisk').text = risk_level['level']
        ET.SubElement(risk, 'Score').text = str(risk_level['score'])
        
        # Findings
        findings_elem = ET.SubElement(root, 'Findings')
        for idx, finding in enumerate(self.findings, 1):
            finding_elem = ET.SubElement(findings_elem, 'Finding')
            finding_elem.set('id', str(idx))
            
            ET.SubElement(finding_elem, 'Title').text = finding.get('title', 'Unknown')
            ET.SubElement(finding_elem, 'Severity').text = finding.get('severity', 'info').upper()
            ET.SubElement(finding_elem, 'AttackType').text = finding.get('attack_type', 'unknown').upper()
            ET.SubElement(finding_elem, 'URL').text = finding.get('url', '')
            
            if finding.get('parameter'):
                ET.SubElement(finding_elem, 'Parameter').text = finding.get('parameter')
            
            if finding.get('evidence'):
                ET.SubElement(finding_elem, 'Evidence').text = finding.get('evidence', '')[:500]
            
            if finding.get('payload'):
                ET.SubElement(finding_elem, 'Payload').text = finding.get('payload', '')[:500]
        
        # Pretty print XML
        xml_str = ET.tostring(root, encoding='unicode')
        dom = minidom.parseString(xml_str)
        return dom.toprettyxml(indent='  ')
    
    def export_html(self) -> str:
        """Export as professional HTML report."""
        risk_level = self._calculate_risk_level()
        risk_color = {
            'CRITICAL': '#ff3b5c',
            'HIGH': '#ff8c42',
            'MEDIUM': '#ffd93d',
            'LOW': '#6bcb77'
        }.get(risk_level['level'], '#4d96ff')
        
        # Group findings by attack type
        by_type = {}
        for f in self.findings:
            attack_type = f.get('attack_type', 'unknown')
            if attack_type not in by_type:
                by_type[attack_type] = []
            by_type[attack_type].append(f)
        
        findings_html = ''
        for attack_type, findings in by_type.items():
            findings_html += f'''
            <div class="attack-section">
                <h3 class="attack-type-title">
                    <i class="icon">🔍</i> {attack_type.upper()} 
                    <span class="badge">{len(findings)} findings</span>
                </h3>
            '''
            
            for idx, finding in enumerate(findings, 1):
                sev = finding.get('severity', 'info').lower()
                sev_colors = {
                    'critical': '#ff3b5c',
                    'high': '#ff8c42',
                    'medium': '#ffd93d',
                    'low': '#6bcb77',
                    'info': '#4d96ff'
                }
                
                findings_html += f'''
                <div class="finding-card severity-{sev}">
                    <div class="finding-header">
                        <span class="finding-number">#{idx}</span>
                        <h4 class="finding-title">{self._escape_html(finding.get('title', 'Unknown Vulnerability'))}</h4>
                        <span class="severity-badge" style="background: {sev_colors.get(sev, '#4d96ff')}">
                            {sev.upper()}
                        </span>
                    </div>
                    <div class="finding-details">
                        <div class="detail-row">
                            <span class="label">URL:</span>
                            <span class="value">{self._escape_html(finding.get('url', 'N/A'))}</span>
                        </div>
                '''
                
                if finding.get('parameter'):
                    findings_html += f'''
                        <div class="detail-row">
                            <span class="label">Parameter:</span>
                            <span class="value code">{self._escape_html(finding.get('parameter'))}</span>
                        </div>
                    '''
                
                if finding.get('payload'):
                    payload = finding.get('payload', '')[:200]
                    findings_html += f'''
                        <div class="detail-row">
                            <span class="label">Payload:</span>
                            <span class="value code">{self._escape_html(payload)}</span>
                        </div>
                    '''
                
                if finding.get('evidence'):
                    evidence = finding.get('evidence', '')[:300]
                    findings_html += f'''
                        <div class="detail-row">
                            <span class="label">Evidence:</span>
                            <pre class="evidence">{self._escape_html(evidence)}</pre>
                        </div>
                    '''
                
                findings_html += '</div></div>'
            
            findings_html += '</div>'
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PennyWise Security Scan Report - {self._escape_html(self.target)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 30px;
            border-bottom: 2px solid rgba(0, 212, 255, 0.3);
        }}
        
        .logo {{
            font-size: 48px;
            font-weight: 700;
            background: linear-gradient(135deg, #00d4ff, #7c3aed);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        
        .report-title {{
            font-size: 24px;
            color: #00d4ff;
            margin: 10px 0;
        }}
        
        .report-meta {{
            font-size: 14px;
            color: #888;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .summary-card {{
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .summary-card h3 {{
            font-size: 14px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}
        
        .summary-value {{
            font-size: 32px;
            font-weight: 700;
            color: #00d4ff;
            font-family: 'Courier New', monospace;
        }}
        
        .risk-banner {{
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.1), rgba(124, 58, 237, 0.1));
            border: 2px solid {risk_color};
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            margin: 30px 0;
        }}
        
        .risk-level {{
            font-size: 36px;
            font-weight: 700;
            color: {risk_color};
            margin-bottom: 10px;
        }}
        
        .risk-score {{
            font-size: 18px;
            color: #888;
        }}
        
        .severity-breakdown {{
            display: flex;
            justify-content: space-around;
            padding: 20px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            margin: 20px 0;
        }}
        
        .severity-item {{
            text-align: center;
        }}
        
        .severity-count {{
            font-size: 28px;
            font-weight: 700;
            font-family: 'Courier New', monospace;
        }}
        
        .severity-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 5px;
        }}
        
        .critical {{ color: #ff3b5c; }}
        .high {{ color: #ff8c42; }}
        .medium {{ color: #ffd93d; }}
        .low {{ color: #6bcb77; }}
        .info {{ color: #4d96ff; }}
        
        .findings-section {{
            margin-top: 40px;
        }}
        
        .section-title {{
            font-size: 24px;
            color: #00d4ff;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid rgba(0, 212, 255, 0.3);
        }}
        
        .attack-section {{
            margin-bottom: 40px;
        }}
        
        .attack-type-title {{
            font-size: 18px;
            color: #7c3aed;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .badge {{
            background: rgba(124, 58, 237, 0.2);
            color: #7c3aed;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}
        
        .finding-card {{
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #888;
        }}
        
        .finding-card.severity-critical {{ border-left-color: #ff3b5c; }}
        .finding-card.severity-high {{ border-left-color: #ff8c42; }}
        .finding-card.severity-medium {{ border-left-color: #ffd93d; }}
        .finding-card.severity-low {{ border-left-color: #6bcb77; }}
        
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
        }}
        
        .finding-number {{
            background: rgba(0, 212, 255, 0.2);
            color: #00d4ff;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            flex-shrink: 0;
        }}
        
        .finding-title {{
            flex: 1;
            font-size: 16px;
            color: #e0e0e0;
        }}
        
        .severity-badge {{
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            color: #000;
            letter-spacing: 1px;
        }}
        
        .finding-details {{
            padding-left: 55px;
        }}
        
        .detail-row {{
            margin-bottom: 10px;
        }}
        
        .label {{
            color: #888;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: inline-block;
            min-width: 100px;
        }}
        
        .value {{
            color: #e0e0e0;
            font-size: 14px;
        }}
        
        .code {{
            background: rgba(0, 0, 0, 0.5);
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #00d4ff;
        }}
        
        .evidence {{
            background: rgba(0, 0, 0, 0.5);
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #ffd93d;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            margin-top: 8px;
            border: 1px solid rgba(255, 217, 61, 0.2);
        }}
        
        .footer {{
            text-align: center;
            margin-top: 60px;
            padding-top: 30px;
            border-top: 2px solid rgba(0, 212, 255, 0.3);
            color: #666;
            font-size: 14px;
        }}
        
        @media print {{
            body {{ background: #fff; color: #000; }}
            .container {{ box-shadow: none; background: #fff; }}
            .finding-card {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ PennyWise</div>
            <h1 class="report-title">Security Scan Report</h1>
            <div class="report-meta">
                <div>Target: <strong>{self._escape_html(self.target)}</strong></div>
                <div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                <div>Scanner Version: 2.0.0</div>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="summary-value">{len(self.findings)}</div>
            </div>
            <div class="summary-card">
                <h3>Pages Scanned</h3>
                <div class="summary-value">{self.summary.get('pages_crawled', self.summary.get('pages_scanned', 0))}</div>
            </div>
            <div class="summary-card">
                <h3>Requests Made</h3>
                <div class="summary-value">{self.summary.get('requests_made', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <div class="summary-value">{self.summary.get('duration_seconds', 0):.1f}s</div>
            </div>
        </div>
        
        <div class="risk-banner">
            <div class="risk-level">{risk_level['level']} RISK</div>
            <div class="risk-score">Risk Score: {risk_level['score']}/100</div>
        </div>
        
        <div class="severity-breakdown">
            <div class="severity-item">
                <div class="severity-count critical">{self.severity_breakdown.get('critical', 0)}</div>
                <div class="severity-label critical">Critical</div>
            </div>
            <div class="severity-item">
                <div class="severity-count high">{self.severity_breakdown.get('high', 0)}</div>
                <div class="severity-label high">High</div>
            </div>
            <div class="severity-item">
                <div class="severity-count medium">{self.severity_breakdown.get('medium', 0)}</div>
                <div class="severity-label medium">Medium</div>
            </div>
            <div class="severity-item">
                <div class="severity-count low">{self.severity_breakdown.get('low', 0)}</div>
                <div class="severity-label low">Low</div>
            </div>
        </div>
        
        <div class="findings-section">
            <h2 class="section-title">Detailed Findings</h2>
            {findings_html}
        </div>
        
        <div class="footer">
            <p>Generated by PennyWise AI Security Scanner v2.0.0</p>
            <p>This report contains sensitive security information and should be handled confidentially.</p>
        </div>
    </div>
</body>
</html>'''
        
        return html
    
    def export_pdf(self) -> bytes:
        """
        Export as PDF report.
        Requires reportlab library.
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab library is required for PDF export. Install with: pip install reportlab")
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=letter, 
            topMargin=0.75*inch, 
            bottomMargin=0.75*inch,
            leftMargin=0.75*inch,
            rightMargin=0.75*inch
        )
        story = []
        styles = getSampleStyleSheet()
        
        # Professional color scheme
        PRIMARY_COLOR = colors.HexColor('#1a1a2e')
        ACCENT_COLOR = colors.HexColor('#2563eb')
        TEXT_COLOR = colors.HexColor('#1f2937')
        LIGHT_BG = colors.HexColor('#f9fafb')
        BORDER_COLOR = colors.HexColor('#e5e7eb')
        
        # Severity colors - professional palette
        SEV_COLORS = {
            'CRITICAL': colors.HexColor('#dc2626'),
            'HIGH': colors.HexColor('#ea580c'),
            'MEDIUM': colors.HexColor('#d97706'),
            'LOW': colors.HexColor('#65a30d'),
            'INFO': colors.HexColor('#2563eb')
        }
        
        # Custom styles - clean and professional
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=PRIMARY_COLOR,
            spaceAfter=8,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        subtitle_style = ParagraphStyle(
            'SubTitle',
            parent=styles['Normal'],
            fontSize=11,
            textColor=colors.HexColor('#6b7280'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=ACCENT_COLOR,
            spaceAfter=15,
            spaceBefore=25,
            fontName='Helvetica-Bold',
            borderWidth=0,
            borderColor=ACCENT_COLOR,
            borderPadding=0,
            leading=18
        )
        
        subheading_style = ParagraphStyle(
            'SubHeading',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=TEXT_COLOR,
            spaceAfter=10,
            spaceBefore=18,
            fontName='Helvetica-Bold',
            leading=16
        )
        
        # Title section
        story.append(Paragraph("Security Scan Report", title_style))
        story.append(Paragraph("PennyWise AI Vulnerability Scanner", subtitle_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Metadata table - clean design
        meta_data = [
            ['Target URL', self.target],
            ['Report Generated', datetime.now().strftime('%B %d, %Y at %H:%M:%S')],
            ['Scanner Version', 'PennyWise v2.0.0'],
            ['Total Vulnerabilities', str(len(self.findings))]
        ]
        
        meta_table = Table(meta_data, colWidths=[2.2*inch, 4.3*inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
            ('TEXTCOLOR', (0, 0), (0, -1), TEXT_COLOR),
            ('TEXTCOLOR', (1, 0), (1, -1), TEXT_COLOR),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR)
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.4*inch))
        
        # Risk Assessment - clean banner
        risk_level = self._calculate_risk_level()
        risk_color = SEV_COLORS.get(risk_level['level'], ACCENT_COLOR)
        
        risk_data = [[
            Paragraph(f"<b>RISK LEVEL:</b> {risk_level['level']}", ParagraphStyle(
                'RiskText',
                parent=styles['Normal'],
                fontSize=13,
                textColor=risk_color,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            )),
            Paragraph(f"<b>Score:</b> {risk_level['score']}/100", ParagraphStyle(
                'ScoreText',
                parent=styles['Normal'],
                fontSize=13,
                textColor=TEXT_COLOR,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ))
        ]]
        
        risk_table = Table(risk_data, colWidths=[3.25*inch, 3.25*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
            ('BOX', (0, 0), (-1, -1), 2, risk_color),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 0.35*inch))
        
        # Summary Statistics - professional table
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Spacer(1, 0.1*inch))
        
        summary_data = [
            ['Scan Metrics', 'Value', 'Findings by Severity', 'Count'],
            ['Pages Scanned', str(self.summary.get('pages_scanned', self.summary.get('pages_crawled', 0))), 
             'Critical', str(self.severity_breakdown.get('critical', 0))],
            ['Requests Made', str(self.summary.get('requests_made', 0)), 
             'High', str(self.severity_breakdown.get('high', 0))],
            ['Scan Duration', f"{self.summary.get('duration_seconds', 0):.2f}s", 
             'Medium', str(self.severity_breakdown.get('medium', 0))],
            ['', '', 'Low', str(self.severity_breakdown.get('low', 0))]
        ]
        
        summary_table = Table(summary_data, colWidths=[1.8*inch, 1.4*inch, 1.8*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            # Header row
            ('BACKGROUND', (0, 0), (1, 0), PRIMARY_COLOR),
            ('BACKGROUND', (2, 0), (3, 0), PRIMARY_COLOR),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, 0), 'LEFT'),
            
            # Data rows
            ('BACKGROUND', (0, 1), (1, -1), LIGHT_BG),
            ('BACKGROUND', (2, 1), (3, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), TEXT_COLOR),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 1), (1, -1), 'Helvetica'),
            ('FONTNAME', (2, 1), (2, -1), 'Helvetica-Bold'),
            ('FONTNAME', (3, 1), (3, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('ALIGN', (2, 0), (2, -1), 'LEFT'),
            ('ALIGN', (3, 0), (3, -1), 'RIGHT'),
            
            # Padding
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            
            # Borders
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('LINEBELOW', (0, 0), (-1, 0), 2, PRIMARY_COLOR)
        ]))
        story.append(summary_table)
        
        # Detailed Findings Section
        if self.findings:
            story.append(PageBreak())
            story.append(Paragraph("Detailed Vulnerability Findings", heading_style))
            story.append(Spacer(1, 0.15*inch))
            
            # Group by attack type
            by_type = {}
            for f in self.findings:
                attack_type = f.get('attack_type', 'unknown')
                if attack_type not in by_type:
                    by_type[attack_type] = []
                by_type[attack_type].append(f)
            
            finding_counter = 1
            for attack_type, findings in by_type.items():
                # Attack type header
                story.append(Spacer(1, 0.15*inch))
                story.append(Paragraph(
                    f"{attack_type.upper().replace('_', ' ')} Vulnerabilities ({len(findings)})", 
                    subheading_style
                ))
                story.append(Spacer(1, 0.12*inch))
                
                for finding in findings:
                    sev = finding.get('severity', 'info').upper()
                    sev_color = SEV_COLORS.get(sev, SEV_COLORS['INFO'])
                    
                    # Finding header with severity badge
                    finding_header = [[
                        Paragraph(f"<b>#{finding_counter}</b>", ParagraphStyle(
                            'FindingNum',
                            parent=styles['Normal'],
                            fontSize=10,
                            textColor=TEXT_COLOR,
                            fontName='Helvetica-Bold'
                        )),
                        Paragraph(finding.get('title', 'Unknown Vulnerability'), ParagraphStyle(
                            'FindingTitle',
                            parent=styles['Normal'],
                            fontSize=10,
                            textColor=TEXT_COLOR,
                            fontName='Helvetica-Bold'
                        )),
                        Paragraph(f"<b>{sev}</b>", ParagraphStyle(
                            'SevBadge',
                            parent=styles['Normal'],
                            fontSize=9,
                            textColor=colors.white,
                            alignment=TA_CENTER,
                            fontName='Helvetica-Bold'
                        ))
                    ]]
                    
                    header_table = Table(finding_header, colWidths=[0.5*inch, 4.8*inch, 1.2*inch])
                    header_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (1, 0), LIGHT_BG),
                        ('BACKGROUND', (2, 0), (2, 0), sev_color),
                        ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                        ('ALIGN', (1, 0), (1, 0), 'LEFT'),
                        ('ALIGN', (2, 0), (2, 0), 'CENTER'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('TOPPADDING', (0, 0), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                        ('LEFTPADDING', (0, 0), (-1, -1), 10),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR)
                    ]))
                    story.append(header_table)
                    
                    # Finding details
                    details_data = []
                    
                    url_text = finding.get('url', 'N/A')
                    if len(url_text) > 70:
                        url_text = url_text[:67] + '...'
                    details_data.append(['URL', url_text])
                    
                    if finding.get('parameter'):
                        details_data.append(['Parameter', finding.get('parameter')])
                    
                    if finding.get('payload'):
                        payload = finding.get('payload', '')
                        if len(payload) > 80:
                            payload = payload[:77] + '...'
                        details_data.append(['Payload', payload])
                    
                    if finding.get('confidence'):
                        details_data.append(['Confidence', f"{finding.get('confidence')}%"])
                    
                    if details_data:
                        details_table = Table(details_data, colWidths=[1.2*inch, 5.3*inch])
                        details_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
                            ('TEXTCOLOR', (1, 0), (1, -1), TEXT_COLOR),
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('FONTNAME', (1, 0), (1, -1), 'Courier'),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                            ('TOPPADDING', (0, 0), (-1, -1), 6),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                            ('LEFTPADDING', (0, 0), (-1, -1), 10),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                            ('GRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR)
                        ]))
                        story.append(details_table)
                    
                    story.append(Spacer(1, 0.25*inch))
                    finding_counter += 1
        else:
            # No findings message
            story.append(Spacer(1, 0.2*inch))
            no_findings_para = Paragraph(
                "No vulnerabilities were detected during this scan. The target appears to be secure against the tested attack vectors.",
                ParagraphStyle(
                    'NoFindings',
                    parent=styles['Normal'],
                    fontSize=11,
                    textColor=colors.HexColor('#059669'),
                    alignment=TA_CENTER,
                    spaceAfter=20,
                    spaceBefore=20
                )
            )
            story.append(no_findings_para)
        
        # Footer
        story.append(Spacer(1, 0.5*inch))
        footer_text = Paragraph(
            "<b>PennyWise AI Security Scanner v2.0.0</b><br/>"
            "This report contains sensitive security information and should be handled confidentially.<br/>"
            f"<i>Generated on {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</i>",
            ParagraphStyle(
                'Footer',
                parent=styles['Normal'],
                fontSize=8,
                textColor=colors.HexColor('#9ca3af'),
                alignment=TA_CENTER,
                leading=12
            )
        )
        story.append(footer_text)
        
        # Build PDF
        doc.build(story)
        pdf_data = buffer.getvalue()
        buffer.close()
        
        return pdf_data
    
    def _calculate_risk_level(self) -> Dict[str, Any]:
        """Calculate overall risk level and score."""
        critical = self.severity_breakdown.get('critical', 0)
        high = self.severity_breakdown.get('high', 0)
        medium = self.severity_breakdown.get('medium', 0)
        low = self.severity_breakdown.get('low', 0)
        
        # Calculate risk score (0-100)
        score = min(100, (critical * 40) + (high * 20) + (medium * 10) + (low * 5))
        
        # Determine risk level
        if critical > 0 or score >= 80:
            level = 'CRITICAL'
        elif high > 0 or score >= 50:
            level = 'HIGH'
        elif medium > 0 or score >= 20:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        return {
            'level': level,
            'score': score,
            'critical_count': critical,
            'high_count': high,
            'medium_count': medium,
            'low_count': low
        }
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ''
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))
