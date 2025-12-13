"""
PDF Report Generator for PennyWise Vulnerability Scanner.
Generates professional PDF reports with screenshots and prevention suggestions.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, ListFlowable, ListItem
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.colors import HexColor
import base64
from io import BytesIO
import requests
from PIL import Image as PILImage
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
import time

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityReport:
    """Complete vulnerability report data."""
    scan_summary: Dict[str, Any]
    findings: List[Dict[str, Any]]
    ai_logs: List[Dict[str, Any]] = field(default_factory=list)
    screenshots: Dict[str, bytes] = field(default_factory=dict)
    prevention_suggestions: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)


class PDFReportGenerator:
    """
    Generates professional PDF vulnerability reports with screenshots and AI analysis.
    """

    def __init__(self):
        """Initialize the PDF report generator."""
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        logger.info("PDF Report Generator initialized")

    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report."""
        # Professional color scheme
        self.colors = {
            'primary': HexColor('#1e3a8a'),      # Deep blue
            'secondary': HexColor('#7c3aed'),    # Purple
            'accent': HexColor('#dc2626'),       # Red
            'success': HexColor('#059669'),      # Green
            'warning': HexColor('#d97706'),      # Orange
            'info': HexColor('#0891b2'),         # Cyan
            'light_bg': HexColor('#f8fafc'),     # Light gray background
            'dark_text': HexColor('#1e293b'),    # Dark slate
            'medium_text': HexColor('#475569'),  # Medium slate
            'light_text': HexColor('#64748b'),   # Light slate
        }

        # Title styles
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            fontName='Helvetica-Bold',
            spaceAfter=20,
            alignment=TA_CENTER,
            textColor=self.colors['primary'],
            leading=32
        ))

        self.styles.add(ParagraphStyle(
            name='ReportSubtitle',
            parent=self.styles['Heading2'],
            fontSize=18,
            fontName='Helvetica',
            spaceAfter=40,
            alignment=TA_CENTER,
            textColor=self.colors['secondary'],
            leading=22
        ))

        # Section headers with professional styling
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            fontName='Helvetica-Bold',
            spaceAfter=15,
            spaceBefore=20,
            textColor=self.colors['primary'],
            borderWidth=0,
            borderColor=self.colors['primary'],
            borderPadding=8,
            backColor=self.colors['light_bg'],
            leading=20
        ))

        # Vulnerability title with severity colors
        self.styles.add(ParagraphStyle(
            name='VulnTitle',
            parent=self.styles['Heading3'],
            fontSize=14,
            fontName='Helvetica-Bold',
            spaceAfter=12,
            textColor=self.colors['dark_text'],
            leading=18
        ))

        # Professional body text - modify existing Normal style
        self.styles['Normal'].fontSize = 11
        self.styles['Normal'].fontName = 'Helvetica'
        self.styles['Normal'].textColor = self.colors['dark_text']
        self.styles['Normal'].leading = 14
        self.styles['Normal'].spaceAfter = 8

        self.styles.add(ParagraphStyle(
            name='NormalIndented',
            parent=self.styles['Normal'],
            leftIndent=25,
            spaceAfter=6,
            fontSize=10,
            textColor=self.colors['medium_text']
        ))

        # Professional code blocks
        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Normal'],
            fontName='Courier',
            fontSize=9,
            textColor=self.colors['dark_text'],
            backgroundColor=HexColor('#f1f5f9'),
            borderWidth=1,
            borderColor=HexColor('#e2e8f0'),
            borderPadding=8,
            leftIndent=25,
            spaceAfter=10,
            leading=12
        ))

        # Metadata styles
        self.styles.add(ParagraphStyle(
            name='MetadataLabel',
            parent=self.styles['Normal'],
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=self.colors['medium_text'],
            spaceAfter=4
        ))

        self.styles.add(ParagraphStyle(
            name='MetadataValue',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.colors['dark_text'],
            spaceAfter=6
        ))

        # Risk level styles
        self.styles.add(ParagraphStyle(
            name='RiskCritical',
            parent=self.styles['Normal'],
            fontSize=12,
            fontName='Helvetica-Bold',
            textColor=self.colors['accent'],
            spaceAfter=8
        ))

        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            fontSize=12,
            fontName='Helvetica-Bold',
            textColor=HexColor('#dc2626'),
            spaceAfter=8
        ))

        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            fontSize=12,
            fontName='Helvetica-Bold',
            textColor=self.colors['warning'],
            spaceAfter=8
        ))

        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            fontSize=12,
            fontName='Helvetica-Bold',
            textColor=self.colors['success'],
            spaceAfter=8
        ))

    def generate_report(self, report_data: VulnerabilityReport, output_path: str) -> bool:
        """
        Generate a comprehensive PDF vulnerability report.

        Args:
            report_data: Complete vulnerability report data
            output_path: Path to save the PDF report

        Returns:
            True if report generated successfully, False otherwise
        """
        try:
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )

            # Build the report content
            story = []

            # Title page
            logger.info("Creating title page...")
            story.extend(self._create_title_page(report_data))

            # Executive summary
            logger.info("Creating executive summary...")
            story.extend(self._create_executive_summary(report_data))

            # Table of contents
            logger.info("Creating table of contents...")
            story.extend(self._create_table_of_contents(report_data))

            # Detailed findings
            logger.info("Creating detailed findings...")
            story.extend(self._create_detailed_findings(report_data))

            # AI Analysis section
            logger.info("Creating AI analysis section...")
            story.extend(self._create_ai_analysis_section(report_data))

            # Prevention and remediation
            logger.info("Creating prevention section...")
            story.extend(self._create_prevention_section(report_data))

            # Technical details
            logger.info("Creating technical details...")
            story.extend(self._create_technical_details(report_data))

            # Generate PDF
            logger.info("Building PDF document...")
            doc.build(story, onFirstPage=self._add_page_header_footer,
                     onLaterPages=self._add_page_header_footer)

            logger.info(f"PDF report generated successfully: {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

    def _create_title_page(self, report_data: VulnerabilityReport) -> List[Any]:
        """Create a professional title page."""
        story = []

        # Add some top spacing
        story.append(Spacer(1, 100))

        # Main title with professional styling
        story.append(Paragraph("PENNYWISE", self.styles['ReportTitle']))
        story.append(Paragraph("SECURITY ASSESSMENT REPORT", self.styles['ReportSubtitle']))

        story.append(Spacer(1, 60))

        # Professional header box with metadata
        metadata = report_data.scan_metadata
        target_url = metadata.get('target_url', 'N/A')
        scan_date = metadata.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        scanner_version = metadata.get('user_agent', 'PennyWise v2.0')

        # Create a professional metadata table
        metadata_data = [
            ['Assessment Date:', scan_date],
            ['Target System:', target_url],
            ['Scanner Version:', scanner_version],
            ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
        ]

        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.colors['light_bg']),
            ('TEXTCOLOR', (0, 0), (0, -1), self.colors['medium_text']),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (0, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, self.colors['light_text']),
        ]))

        story.append(metadata_table)

        story.append(Spacer(1, 40))

        # Risk summary with professional styling
        summary = report_data.scan_summary
        overall_risk = summary.get('overall_risk', 'Unknown')
        total_findings = summary.get('total_findings', 0)

        # Risk level indicator
        risk_style_map = {
            'Critical': 'RiskCritical',
            'High': 'RiskHigh',
            'Medium': 'RiskMedium',
            'Low': 'RiskLow',
            'Info': 'RiskLow'
        }

        risk_style = risk_style_map.get(overall_risk, 'RiskLow')

        story.append(Paragraph("EXECUTIVE RISK SUMMARY", self.styles['SectionHeader']))

        # Risk assessment table
        risk_data = [
            ['Overall Risk Level:', Paragraph(f"<b>{overall_risk.upper()}</b>", self.styles[risk_style])],
            ['Total Vulnerabilities:', f"{total_findings} findings detected"],
            ['Assessment Scope:', 'Full security scan with AI analysis'],
            ['Confidentiality:', 'This report contains sensitive security information']
        ]

        risk_table = Table(risk_data, colWidths=[2.5*inch, 3.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.colors['light_bg']),
            ('TEXTCOLOR', (0, 0), (0, -1), self.colors['medium_text']),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, self.colors['light_text']),
        ]))

        story.append(risk_table)

        story.append(Spacer(1, 30))

        # Professional footer
        story.append(Paragraph(
            "This report was generated by PennyWise AI-Powered Vulnerability Scanner",
            self.styles['Normal']
        ))
        story.append(Paragraph(
            "For questions or support, contact your security team",
            self.styles['Normal']
        ))

        story.append(PageBreak())
        return story

    def _create_executive_summary(self, report_data: VulnerabilityReport) -> List[Any]:
        """Create a professional executive summary section."""
        story = []

        story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader']))

        summary = report_data.scan_summary

        # Summary text in a professional box
        summary_text = summary.get('summary', 'Security assessment completed with comprehensive analysis.')
        summary_box = Table([[Paragraph(summary_text, self.styles['Normal'])]],
                          colWidths=[6.5*inch])
        summary_box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.colors['light_bg']),
            ('BOX', (0, 0), (-1, -1), 1, self.colors['primary']),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('RIGHTPADDING', (0, 0), (-1, -1), 15),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ]))
        story.append(summary_box)

        story.append(Spacer(1, 20))

        # Severity breakdown with professional table
        severity_data = summary.get('severity_breakdown', {})
        if severity_data:
            story.append(Paragraph("VULNERABILITY SEVERITY BREAKDOWN", self.styles['VulnTitle']))

            # Create severity table data
            severity_table_data = [['Severity Level', 'Count', 'Risk Assessment']]
            severity_colors = {
                'Critical': ('Critical', self.colors['accent']),
                'High': ('High', HexColor('#dc2626')),
                'Medium': ('Medium', self.colors['warning']),
                'Low': ('Low', self.colors['success']),
                'Info': ('Info', self.colors['info'])
            }

            for severity, count in severity_data.items():
                if severity in severity_colors:
                    color_name, color = severity_colors[severity]
                    severity_table_data.append([
                        Paragraph(f"<font color='{color}'>{severity}</font>", self.styles['Normal']),
                        Paragraph(f"<b>{count}</b>", self.styles['Normal']),
                        Paragraph(f"● {color_name} Risk Level", self.styles['Normal'])
                    ])

            severity_table = Table(severity_table_data, colWidths=[2*inch, 1*inch, 2.5*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('TOPPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, self.colors['light_text']),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))

            story.append(severity_table)

        story.append(Spacer(1, 15))

        # Attack type distribution
        vuln_types = summary.get('vulnerability_types', [])
        if vuln_types:
            story.append(Paragraph("ATTACK VECTOR ANALYSIS", self.styles['VulnTitle']))

            attack_types_text = f"Detected attack vectors: {', '.join([t.upper() for t in vuln_types])}"
            attack_box = Table([[Paragraph(attack_types_text, self.styles['Normal'])]],
                             colWidths=[6.5*inch])
            attack_box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), HexColor('#fef3c7')),
                ('BOX', (0, 0), (-1, -1), 1, self.colors['warning']),
                ('LEFTPADDING', (0, 0), (-1, -1), 15),
                ('RIGHTPADDING', (0, 0), (-1, -1), 15),
                ('TOPPADDING', (0, 0), (-1, -1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(attack_box)

        story.append(Spacer(1, 15))

        # Recommendations preview
        recommendations = summary.get('recommendations', [])
        if recommendations:
            story.append(Paragraph("PRIORITY RECOMMENDATIONS", self.styles['VulnTitle']))

            # Show top 3 recommendations
            for i, rec in enumerate(recommendations[:3], 1):
                rec_box = Table([[Paragraph(f"{i}. {rec}", self.styles['Normal'])]],
                               colWidths=[6.5*inch])
                rec_box.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), HexColor('#ecfdf5')),
                    ('BOX', (0, 0), (-1, -1), 1, self.colors['success']),
                    ('LEFTPADDING', (0, 0), (-1, -1), 15),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 15),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ]))
                story.append(rec_box)
                story.append(Spacer(1, 3))

        story.append(PageBreak())
        return story

    def _create_table_of_contents(self, report_data: VulnerabilityReport) -> List[Any]:
        """Create table of contents."""
        story = []

        story.append(Paragraph("TABLE OF CONTENTS", self.styles['SectionHeader']))

        toc_items = [
            "1. Executive Summary",
            "2. Detailed Findings",
            "3. AI Analysis & Activity Logs",
            "4. Prevention & Remediation",
            "5. Technical Details",
            "6. Screenshots & Evidence"
        ]

        for item in toc_items:
            story.append(Paragraph(item, self.styles['Normal']))

        story.append(PageBreak())
        return story

    def _create_detailed_findings(self, report_data: VulnerabilityReport) -> List[Any]:
        """Create professional detailed findings section."""
        story = []

        story.append(Paragraph("DETAILED VULNERABILITY FINDINGS", self.styles['SectionHeader']))

        findings = report_data.findings
        if not findings:
            no_findings_box = Table([[Paragraph("✅ No vulnerabilities were detected during this comprehensive security scan.", self.styles['Normal'])]],
                                  colWidths=[6.5*inch])
            no_findings_box.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), HexColor('#ecfdf5')),
                ('BOX', (0, 0), (-1, -1), 2, self.colors['success']),
                ('LEFTPADDING', (0, 0), (-1, -1), 20),
                ('RIGHTPADDING', (0, 0), (-1, -1), 20),
                ('TOPPADDING', (0, 0), (-1, -1), 15),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
            ]))
            story.append(no_findings_box)
            return story

        for i, finding in enumerate(findings, 1):
            # Vulnerability header with severity badge
            vuln_type = finding.get('attack_type', 'Unknown').upper()
            title = finding.get('title', f'{vuln_type} Vulnerability')
            severity = finding.get('severity', 'Medium')

            severity_colors = {
                'Critical': ('Critical', self.colors['accent'], '🔴'),
                'High': ('High', HexColor('#dc2626'), '🟠'),
                'Medium': ('Medium', self.colors['warning'], '🟡'),
                'Low': ('Low', self.colors['success'], '🟢'),
                'Info': ('Info', self.colors['info'], '🔵')
            }

            severity_emoji, severity_color, severity_badge = severity_colors.get(severity, ('Unknown', self.colors['medium_text'], '⚪'))

            # Professional vulnerability header
            vuln_header = Table([[
                Paragraph(f"{i}. {title}", self.styles['VulnTitle']),
                Paragraph(f"{severity_badge} {severity_emoji}", self.styles['Normal'])
            ]], colWidths=[5*inch, 1.5*inch])

            vuln_header.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), self.colors['light_bg']),
                ('BOX', (0, 0), (-1, -1), 1, severity_color),
                ('LEFTPADDING', (0, 0), (-1, -1), 15),
                ('RIGHTPADDING', (0, 0), (-1, -1), 15),
                ('TOPPADDING', (0, 0), (-1, -1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(vuln_header)

            story.append(Spacer(1, 10))

            # Vulnerability details in a structured table
            details_data = []

            # URL
            url = finding.get('url', 'N/A')
            details_data.append(['Target URL:', Paragraph(url, self.styles['Normal'])])

            # Parameter
            parameter = finding.get('parameter', 'N/A')
            if parameter and parameter != 'N/A':
                details_data.append(['Affected Parameter:', Paragraph(f"<code>{parameter}</code>", self.styles['Normal'])])

            # Payload
            payload = finding.get('payload', 'N/A')
            if payload and payload != 'N/A':
                details_data.append(['Attack Payload:', Paragraph(payload, self.styles['CodeBlock'])])

            # Description
            description = finding.get('description', '')
            if description:
                details_data.append(['Description:', Paragraph(description, self.styles['Normal'])])

            # Evidence
            evidence = finding.get('evidence', '')
            if evidence:
                # Clean HTML content more thoroughly for PDF
                import re
                import html

                # Remove HTML tags completely for cleaner display
                clean_evidence = re.sub(r'<[^>]+>', '', evidence)
                # Remove extra whitespace and newlines
                clean_evidence = re.sub(r'\s+', ' ', clean_evidence).strip()
                # Escape any remaining special characters
                clean_evidence = html.escape(clean_evidence)
                # Remove common HTML entities that might remain
                clean_evidence = clean_evidence.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
                # Truncate if too long
                if len(clean_evidence) > 300:
                    clean_evidence = clean_evidence[:300] + "..."
                details_data.append(['Technical Evidence:', Paragraph(clean_evidence, self.styles['CodeBlock'])])

            # Create details table
            if details_data:
                details_table = Table(details_data, colWidths=[1.8*inch, 4.7*inch])
                details_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.colors['light_text']),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(details_table)

            story.append(Spacer(1, 15))

            # Screenshot if available
            vuln_id = finding.get('id', f'vuln_{i}')
            if vuln_id in report_data.screenshots:
                try:
                    story.append(Paragraph("VISUAL EVIDENCE", self.styles['VulnTitle']))
                    screenshot_data = report_data.screenshots[vuln_id]
                    img = Image(BytesIO(screenshot_data))
                    img.drawHeight = 3*inch
                    img.drawWidth = 4*inch
                    img.hAlign = 'CENTER'
                    story.append(img)
                    story.append(Paragraph("Screenshot captured at time of detection", self.styles['Normal']))
                except Exception as e:
                    logger.warning(f"Failed to add screenshot for vulnerability {vuln_id}: {e}")

            story.append(Spacer(1, 25))

        story.append(PageBreak())
        return story

    def _create_ai_analysis_section(self, report_data: VulnerabilityReport) -> List[Any]:
        """Create AI analysis section with activity logs."""
        story = []

        story.append(Paragraph("AI ANALYSIS & ACTIVITY LOGS", self.styles['SectionHeader']))

        ai_logs = report_data.ai_logs
        if not ai_logs:
            story.append(Paragraph("No AI activity logs available.", self.styles['Normal']))
            return story

        # AI Summary
        total_ops = len(ai_logs)
        successful_ops = sum(1 for log in ai_logs if log.get('success', False))
        avg_time = sum(log.get('processing_time', 0) for log in ai_logs) / max(total_ops, 1)

        story.append(Paragraph("AI Activity Summary:", self.styles['Normal']))
        story.append(Paragraph(f"• Total AI Operations: {total_ops}", self.styles['NormalIndented']))
        story.append(Paragraph(f"• Success Rate: {successful_ops/max(total_ops, 1)*100:.1f}%", self.styles['NormalIndented']))
        story.append(Paragraph(f"• Average Processing Time: {avg_time:.3f}s", self.styles['NormalIndented']))

        story.append(Spacer(1, 15))

        # Operations by type
        operations_by_type = {}
        for log in ai_logs:
            op_type = log.get('operation', 'unknown')
            operations_by_type[op_type] = operations_by_type.get(op_type, 0) + 1

        if operations_by_type:
            story.append(Paragraph("Operations by Type:", self.styles['Normal']))
            for op_type, count in operations_by_type.items():
                story.append(Paragraph(f"• {op_type.replace('_', ' ').title()}: {count}", self.styles['NormalIndented']))

        story.append(Spacer(1, 20))

        # Detailed logs
        story.append(Paragraph("Detailed AI Activity Logs:", self.styles['Normal']))

        for log in ai_logs[-20:]:  # Show last 20 logs
            timestamp = log.get('timestamp', 'N/A')
            operation = log.get('operation', 'unknown').replace('_', ' ').title()
            success = "✓" if log.get('success', False) else "✗"
            processing_time = log.get('processing_time', 0)

            story.append(Paragraph(
                f"{timestamp} | {operation} | {success} | {processing_time:.3f}s",
                self.styles['CodeBlock']
            ))

        story.append(PageBreak())
        return story

    def _create_prevention_section(self, report_data: VulnerabilityReport) -> List[Any]:
        """Create prevention and remediation section."""
        story = []

        story.append(Paragraph("PREVENTION & REMEDIATION", self.styles['SectionHeader']))

        prevention_data = report_data.prevention_suggestions
        if not prevention_data:
            story.append(Paragraph("No specific prevention suggestions available.", self.styles['Normal']))
            return story

        for vuln_type, suggestions in prevention_data.items():
            story.append(Paragraph(f"{vuln_type.upper()} Prevention", self.styles['VulnTitle']))

            for suggestion in suggestions:
                title = suggestion.get('title', 'Prevention Measure')
                story.append(Paragraph(f"<b>{title}</b>", self.styles['Normal']))

                description = suggestion.get('description', '')
                if description:
                    story.append(Paragraph(description, self.styles['NormalIndented']))

                code_example = suggestion.get('code_example', '')
                if code_example:
                    story.append(Paragraph("<i>Code Example:</i>", self.styles['Normal']))
                    story.append(Paragraph(code_example, self.styles['CodeBlock']))

                references = suggestion.get('references', [])
                if references:
                    story.append(Paragraph("<i>References:</i>", self.styles['Normal']))
                    for ref in references:
                        story.append(Paragraph(f"• {ref}", self.styles['NormalIndented']))

                effort = suggestion.get('effort', 'Medium')
                story.append(Paragraph(f"<i>Implementation Effort: {effort}</i>", self.styles['NormalIndented']))

                story.append(Spacer(1, 10))

        story.append(PageBreak())
        return story

    def _create_technical_details(self, report_data: VulnerabilityReport) -> List[Any]:
        """Create technical details section."""
        story = []

        story.append(Paragraph("TECHNICAL DETAILS", self.styles['SectionHeader']))

        metadata = report_data.scan_metadata

        # Scan configuration
        story.append(Paragraph("Scan Configuration:", self.styles['Normal']))
        story.append(Paragraph(f"• Target URL: {metadata.get('target_url', 'N/A')}", self.styles['NormalIndented']))
        story.append(Paragraph(f"• Scan Mode: {metadata.get('scan_mode', 'Full')}", self.styles['NormalIndented']))
        story.append(Paragraph(f"• User Agent: {metadata.get('user_agent', 'PennyWise Scanner')}", self.styles['NormalIndented']))
        story.append(Paragraph(f"• Timeout: {metadata.get('timeout', 30)}s", self.styles['NormalIndented']))

        # Scan statistics
        summary = report_data.scan_summary
        story.append(Paragraph("Scan Statistics:", self.styles['Normal']))
        story.append(Paragraph(f"• Pages Crawled: {summary.get('pages_crawled', 0)}", self.styles['NormalIndented']))
        story.append(Paragraph(f"• Requests Made: {summary.get('requests_made', 0)}", self.styles['NormalIndented']))
        story.append(Paragraph(f"• Scan Duration: {summary.get('duration', 0):.2f}s", self.styles['NormalIndented']))

        story.append(PageBreak())
        return story

    def _add_page_header_footer(self, canvas, doc):
        """Add professional header and footer to each page."""
        canvas.saveState()

        # Professional header with logo-like styling
        canvas.setFillColor(self.colors['primary'])
        canvas.setFont('Helvetica-Bold', 12)
        canvas.drawString(72, 810, "PENNYWISE")
        canvas.setFont('Helvetica', 10)
        canvas.setFillColor(self.colors['secondary'])
        canvas.drawString(72, 795, "AI-Powered Security Assessment")

        # Subtle border line
        canvas.setStrokeColor(self.colors['light_text'])
        canvas.setLineWidth(0.5)
        canvas.line(72, 785, 520, 785)

        # Professional footer
        canvas.setFillColor(self.colors['medium_text'])
        canvas.setFont('Helvetica', 8)

        # Left side - generation info
        footer_left = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        canvas.drawString(72, 40, footer_left)

        # Center - confidentiality notice
        canvas.setFont('Helvetica-Oblique', 7)
        footer_center = "CONFIDENTIAL - For authorized security personnel only"
        canvas.drawCentredString(297, 40, footer_center)  # A4 width is ~595 points, center is ~297

        # Right side - page number
        canvas.setFont('Helvetica', 8)
        footer_right = f"Page {doc.page}"
        canvas.drawRightString(520, 40, footer_right)

        # Subtle top border for footer
        canvas.setStrokeColor(self.colors['light_text'])
        canvas.setLineWidth(0.3)
        canvas.line(72, 55, 520, 55)

        canvas.restoreState()

    def capture_screenshot(self, url: str) -> Optional[bytes]:
        """
        Capture a screenshot of a URL using Selenium.

        Args:
            url: URL to capture

        Returns:
            Screenshot data as bytes, or None if failed
        """
        driver = None
        try:
            logger.info(f"Capturing screenshot for: {url}")

            # Setup Chrome options for headless browsing
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1280,1024")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-plugins")
            chrome_options.add_argument("--disable-images")  # Speed up loading
            chrome_options.add_argument("--disable-javascript")  # For security, but may break some sites
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

            # Initialize WebDriver
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)

            # Set timeouts
            driver.set_page_load_timeout(30)
            driver.set_script_timeout(10)

            # Navigate to URL
            driver.get(url)

            # Wait for page to load (basic wait)
            time.sleep(2)

            # Try to wait for body element
            try:
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except Exception:
                logger.warning(f"Timeout waiting for page load: {url}")

            # Take screenshot
            screenshot = driver.get_screenshot_as_png()
            logger.info(f"Screenshot captured successfully for: {url} ({len(screenshot)} bytes)")

            return screenshot

        except Exception as e:
            logger.error(f"Failed to capture screenshot for {url}: {e}")
            # Return a placeholder image with error message
            try:
                img = PILImage.new('RGB', (800, 600), color=(255, 200, 200))
                from PIL import ImageDraw, ImageFont
                draw = ImageDraw.Draw(img)
                # Use default font
                draw.text((10, 10), f"Screenshot failed for:\n{url}\nError: {str(e)[:100]}",
                         fill=(0, 0, 0))
                buffer = BytesIO()
                img.save(buffer, format='PNG')
                return buffer.getvalue()
            except Exception as img_error:
                logger.error(f"Failed to create error placeholder image: {img_error}")
                return None

        finally:
            if driver:
                try:
                    driver.quit()
                except Exception as e:
                    logger.warning(f"Error closing WebDriver: {e}")


# Global instance
_pdf_generator: Optional[PDFReportGenerator] = None


def get_pdf_generator() -> PDFReportGenerator:
    """Get the global PDF generator instance."""
    global _pdf_generator
    if _pdf_generator is None:
        _pdf_generator = PDFReportGenerator()
    return _pdf_generator