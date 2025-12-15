"""
Report Generator for PennyWise.
Generates professional security reports in multiple formats.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from ..core.scanner import ScanResult, Finding
from ..config import SeverityLevel
from ..ai.remedy_analyzer import AIRemedyAnalyzer
from ..ai.classifier import AIVulnerabilityClassifier


@dataclass
class ReportMetadata:
    """Metadata for a security report."""
    title: str
    generated_at: datetime
    target_url: str
    scan_duration: float
    scanner_version: str = "2.0.0"
    analyst: str = "PennyWise AI Scanner"


class ReportGenerator:
    """
    Generates professional security reports from scan results.
    
    Supports:
    - JSON export
    - HTML report
    - Markdown report
    - Summary text
    """
    
    def __init__(self, scan_result: ScanResult, include_ai_insights: bool = True):
        """
        Initialize the report generator.
        
        Args:
            scan_result: Completed scan result to report on
            include_ai_insights: Whether to include AI classification and remediation
        """
        self.result = scan_result
        self.metadata = ReportMetadata(
            title=f"Security Scan Report - {scan_result.target_url}",
            generated_at=datetime.now(),
            target_url=scan_result.target_url,
            scan_duration=scan_result.duration_seconds
        )
        self.include_ai_insights = include_ai_insights
        
        # Initialize AI analyzers if needed
        if self.include_ai_insights:
            try:
                self.remedy_analyzer = AIRemedyAnalyzer()
                self.classifier = AIVulnerabilityClassifier()
            except Exception as e:
                print(f"Warning: Could not initialize AI analyzers: {e}")
                self.include_ai_insights = False
    
    def generate_json(self, output_path: Optional[str] = None) -> str:
        """Generate JSON report."""
        report = {
            'metadata': {
                'title': self.metadata.title,
                'generated_at': self.metadata.generated_at.isoformat(),
                'target_url': self.metadata.target_url,
                'scan_duration_seconds': self.metadata.scan_duration,
                'scanner_version': self.metadata.scanner_version
            },
            'summary': {
                'total_findings': len(self.result.findings),
                'by_severity': self._count_by_severity(),
                'pages_scanned': self.result.pages_scanned,
                'requests_made': self.result.requests_made,
                'status': self.result.status
            },
            'findings': [f.to_dict() for f in self.result.findings],
            'errors': self.result.errors
        }
        
        json_str = json.dumps(report, indent=2, default=str)
        
        if output_path:
            Path(output_path).write_text(json_str)
        
        return json_str
    
    def generate_html(self, output_path: Optional[str] = None) -> str:
        """Generate HTML report."""
        severity_counts = self._count_by_severity()
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.metadata.title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #0a0a0a; 
            color: #00ff00; 
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ 
            text-align: center; 
            padding: 40px 20px; 
            border-bottom: 2px solid #00ff00;
            margin-bottom: 30px;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .meta {{ color: #00aa00; font-size: 0.9em; }}
        
        .summary {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 40px;
        }}
        .summary-card {{ 
            background: #111; 
            border: 1px solid #003300; 
            padding: 20px; 
            text-align: center;
        }}
        .summary-card .number {{ font-size: 2.5em; font-weight: bold; }}
        .summary-card .label {{ color: #00aa00; text-transform: uppercase; font-size: 0.8em; }}
        
        .severity-critical {{ color: #ff0000; border-color: #ff0000; }}
        .severity-high {{ color: #ff6600; border-color: #ff6600; }}
        .severity-medium {{ color: #ffff00; border-color: #ffff00; }}
        .severity-low {{ color: #00ffff; border-color: #00ffff; }}
        .severity-info {{ color: #0088ff; border-color: #0088ff; }}
        
        .findings {{ margin-top: 40px; }}
        .finding {{ 
            background: #111; 
            border-left: 4px solid #00ff00; 
            padding: 20px; 
            margin-bottom: 20px;
        }}
        .finding.severity-critical {{ border-left-color: #ff0000; }}
        .finding.severity-high {{ border-left-color: #ff6600; }}
        .finding.severity-medium {{ border-left-color: #ffff00; }}
        .finding.severity-low {{ border-left-color: #00ffff; }}
        
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .finding-title {{ font-size: 1.2em; font-weight: bold; }}
        .finding-badge {{ 
            padding: 5px 15px; 
            font-size: 0.8em; 
            text-transform: uppercase; 
            font-weight: bold;
        }}
        
        .finding-details {{ color: #00aa00; }}
        .finding-details dt {{ font-weight: bold; margin-top: 10px; }}
        .finding-details dd {{ margin-left: 20px; }}
        
        .recommendations {{ margin-top: 15px; padding: 15px; background: #001100; }}
        .recommendations h4 {{ margin-bottom: 10px; }}
        .recommendations ul {{ margin-left: 20px; }}
        
        code {{ 
            background: #001100; 
            padding: 2px 8px; 
            font-family: 'Courier New', monospace;
            word-break: break-all;
        }}
        
        .footer {{ 
            text-align: center; 
            padding: 40px 20px; 
            border-top: 1px solid #003300; 
            margin-top: 40px;
            color: #006600;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 PennyWise Security Report</h1>
            <div class="meta">
                <p>Target: <strong>{self.metadata.target_url}</strong></p>
                <p>Generated: {self.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Scan Duration: {self.metadata.scan_duration:.1f} seconds</p>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="number">{len(self.result.findings)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card severity-critical">
                <div class="number">{severity_counts.get('critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card severity-high">
                <div class="number">{severity_counts.get('high', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card severity-medium">
                <div class="number">{severity_counts.get('medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card severity-low">
                <div class="number">{severity_counts.get('low', 0)}</div>
                <div class="label">Low</div>
            </div>
        </div>
        
        <div class="findings">
            <h2>📋 Detailed Findings</h2>
            {self._generate_findings_html()}
        </div>
        
        <div class="footer">
            <p>Report generated by PennyWise AI Security Scanner v{self.metadata.scanner_version}</p>
            <p>© {datetime.now().year} PennyWise Project</p>
        </div>
    </div>
</body>
</html>"""
        
        if output_path:
            Path(output_path).write_text(html)
        
        return html
    
    def generate_markdown(self, output_path: Optional[str] = None) -> str:
        """Generate Markdown report."""
        severity_counts = self._count_by_severity()
        
        md = f"""# PennyWise Security Report

**Target:** {self.metadata.target_url}  
**Generated:** {self.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S')}  
**Duration:** {self.metadata.scan_duration:.1f} seconds  
**Scanner:** PennyWise v{self.metadata.scanner_version}

---

## Summary

| Metric | Value |
|--------|-------|
| Total Findings | {len(self.result.findings)} |
| Critical | {severity_counts.get('critical', 0)} |
| High | {severity_counts.get('high', 0)} |
| Medium | {severity_counts.get('medium', 0)} |
| Low | {severity_counts.get('low', 0)} |
| Info | {severity_counts.get('info', 0)} |
| Pages Scanned | {self.result.pages_scanned} |
| Requests Made | {self.result.requests_made} |

---

## Findings

"""
        
        for finding in sorted(self.result.findings, 
                             key=lambda f: self._severity_order(f.severity)):
            md += f"""### [{finding.severity.value.upper()}] {finding.title}

**ID:** {finding.id}  
**Type:** {finding.attack_type.value.upper()}  
**URL:** `{finding.url}`  
**Confidence:** {finding.confidence:.0%}

{finding.description}

"""
            if finding.parameter:
                md += f"**Parameter:** `{finding.parameter}`\n\n"
            
            if finding.payload:
                md += f"**Payload:**\n```\n{finding.payload}\n```\n\n"
            
            if finding.recommendations:
                md += "**Recommendations:**\n"
                for rec in finding.recommendations:
                    md += f"- {rec}\n"
                md += "\n"
            
            md += "---\n\n"
        
        if output_path:
            Path(output_path).write_text(md)
        
        return md
    
    def generate_summary(self) -> str:
        """Generate a short text summary."""
        severity_counts = self._count_by_severity()
        
        lines = [
            "=" * 60,
            "PENNYWISE SECURITY SCAN SUMMARY",
            "=" * 60,
            f"Target: {self.metadata.target_url}",
            f"Scanned: {self.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Duration: {self.metadata.scan_duration:.1f} seconds",
            "",
            "FINDINGS:",
            f"  Critical: {severity_counts.get('critical', 0)}",
            f"  High:     {severity_counts.get('high', 0)}",
            f"  Medium:   {severity_counts.get('medium', 0)}",
            f"  Low:      {severity_counts.get('low', 0)}",
            f"  Info:     {severity_counts.get('info', 0)}",
            f"  TOTAL:    {len(self.result.findings)}",
            "",
            "STATISTICS:",
            f"  Pages Scanned: {self.result.pages_scanned}",
            f"  Requests Made: {self.result.requests_made}",
            f"  Status: {self.result.status.upper()}",
            "=" * 60
        ]
        
        return "\n".join(lines)
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {}
        for finding in self.result.findings:
            sev = finding.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _severity_order(self, severity: SeverityLevel) -> int:
        """Get sort order for severity (lower = more severe)."""
        order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        return order.get(severity, 5)
    
    def _get_ai_insights(self, finding: Finding) -> Dict[str, Any]:
        """Get AI classification and remediation for a finding."""
        insights = {'classification': None, 'remediation': None}
        
        if not self.include_ai_insights:
            return insights
        
        try:
            # Get classification
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            classification_result = loop.run_until_complete(
                self.classifier.classify_vulnerability(
                    vuln_type=finding.attack_type.value,
                    endpoint=finding.url,
                    parameter=finding.parameter or '',
                    payload=finding.payload or '',
                    impact=finding.description
                )
            )
            
            if classification_result and classification_result.get('success'):
                insights['classification'] = classification_result.get('classification')
            
            # Get remediation
            remediation_result = self.remedy_analyzer.generate_remediation_report(
                vuln_type=finding.attack_type.value,
                endpoint=finding.url,
                parameter=finding.parameter or '',
                payload=finding.payload or '',
                impact=finding.description
            )
            
            if remediation_result and remediation_result.get('success'):
                insights['remediation'] = remediation_result.get('remediation')
            
            loop.close()
            
        except Exception as e:
            print(f"Warning: Could not get AI insights: {e}")
        
        return insights
    
    def _generate_findings_html(self) -> str:
        """Generate HTML for all findings."""
        if not self.result.findings:
            return "<p>No vulnerabilities found.</p>"
        
        html_parts = []
        
        for finding in sorted(self.result.findings,
                             key=lambda f: self._severity_order(f.severity)):
            sev_class = f"severity-{finding.severity.value}"
            
            # Get AI insights
            ai_insights = self._get_ai_insights(finding)
            classification = ai_insights.get('classification')
            remediation = ai_insights.get('remediation')
            
            # Classification section
            classification_html = ""
            if classification:
                classification_html = f"""
                <div class="ai-classification" style="margin-top: 15px; padding: 15px; background: rgba(0, 212, 255, 0.05); border-left: 3px solid #00d4ff;">
                    <h4 style="margin-bottom: 10px; color: #00d4ff;">🤖 AI Classification Analysis</h4>
                    <dl style="display: grid; grid-template-columns: 150px 1fr; gap: 8px; font-size: 0.9em;">
                        <dt>CVSS Score:</dt><dd><strong>{classification.get('cvss_score', 'N/A')}</strong> ({classification.get('risk_level', 'N/A')})</dd>
                        <dt>Exploitability:</dt><dd>{classification.get('exploitability', 'N/A')}</dd>
                        <dt>Business Impact:</dt><dd>{classification.get('business_impact', 'N/A')}</dd>
                        <dt>Remediation Effort:</dt><dd>{classification.get('remediation_effort', 'N/A')}</dd>
                    </dl>
                </div>
                """
            
            # Remediation section
            remediation_html = ""
            if remediation and remediation.get('steps'):
                steps_items = "".join(f"<li>{step}</li>" for step in remediation['steps'])
                code_example = ""
                if remediation.get('code_example'):
                    code_example = f"""<div style="margin-top: 10px;">
                        <strong>Code Example:</strong>
                        <pre style="background: #001100; padding: 10px; margin-top: 5px; overflow-x: auto;">{remediation['code_example']}</pre>
                    </div>"""
                
                remediation_html = f"""
                <div class="ai-remediation" style="margin-top: 15px; padding: 15px; background: rgba(124, 58, 237, 0.05); border-left: 3px solid #7c3aed;">
                    <h4 style="margin-bottom: 10px; color: #7c3aed;">🛡️ AI Remediation Guide</h4>
                    <div style="display: inline-block; padding: 4px 12px; background: rgba(255, 140, 66, 0.2); color: #ff8c42; border-radius: 4px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; margin-bottom: 10px;">Priority: {remediation.get('priority', 'Medium')}</div>
                    <ol style="margin-left: 20px; line-height: 1.8;">{steps_items}</ol>
                    {code_example}
                </div>
                """
            
            # Original recommendations
            recs_html = ""
            if finding.recommendations:
                recs_items = "".join(f"<li>{r}</li>" for r in finding.recommendations)
                recs_html = f"""
                <div class="recommendations">
                    <h4>Recommendations</h4>
                    <ul>{recs_items}</ul>
                </div>
                """
            
            finding_html = f"""
            <div class="finding {sev_class}">
                <div class="finding-header">
                    <span class="finding-title">{finding.title}</span>
                    <span class="finding-badge {sev_class}">{finding.severity.value.upper()}</span>
                </div>
                <dl class="finding-details">
                    <dt>ID</dt><dd>{finding.id}</dd>
                    <dt>Type</dt><dd>{finding.attack_type.value.upper()}</dd>
                    <dt>URL</dt><dd><code>{finding.url}</code></dd>
                    <dt>Description</dt><dd>{finding.description}</dd>
                    {"<dt>Parameter</dt><dd><code>" + finding.parameter + "</code></dd>" if finding.parameter else ""}
                    {"<dt>Payload</dt><dd><code>" + finding.payload + "</code></dd>" if finding.payload else ""}
                    <dt>Confidence</dt><dd>{finding.confidence:.0%}</dd>
                </dl>
                {classification_html}
                {remediation_html}
                {recs_html}
            </div>
            """
            html_parts.append(finding_html)
        
        return "\n".join(html_parts)
