"""
Report Generator for PennyWise.
Generates various output formats from scan results.
"""

import json
from datetime import datetime
from typing import Dict, Any, List
from ..core.results import ScanResult, VulnerabilityFinding


class ReportGenerator:
    """Generates reports in various formats from scan results."""

    def __init__(self, scan_result: ScanResult):
        self.scan_result = scan_result

    def generate_json(self) -> str:
        """Generate JSON report."""
        return json.dumps(self._to_dict(), indent=2, default=str)

    def generate_html(self) -> str:
        """Generate HTML report."""
        data = self._to_dict()

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>PennyWise Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .findings {{ margin: 20px 0; }}
        .finding {{ border: 1px solid #ccc; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .critical {{ border-color: #ff0000; background: #ffeaea; }}
        .high {{ border-color: #ff6600; background: #fff2ea; }}
        .medium {{ border-color: #ffcc00; background: #fffdea; }}
        .low {{ border-color: #009900; background: #eaffea; }}
        .info {{ border-color: #666666; background: #f0f0f0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>PennyWise Security Scan Report</h1>
        <p><strong>Target:</strong> {data['target']}</p>
        <p><strong>Scanned:</strong> {data['timestamp']}</p>
        <p><strong>Duration:</strong> {data['duration']:.2f} seconds</p>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Status:</strong> {data['status']}</p>
        <p><strong>Pages Scanned:</strong> {data['pages_scanned']}</p>
        <p><strong>Requests Made:</strong> {data['requests_made']}</p>
        <p><strong>Findings:</strong> {data['total_findings']}</p>
        <ul>
            <li>Critical: {data['findings_by_severity']['critical']}</li>
            <li>High: {data['findings_by_severity']['high']}</li>
            <li>Medium: {data['findings_by_severity']['medium']}</li>
            <li>Low: {data['findings_by_severity']['low']}</li>
            <li>Info: {data['findings_by_severity']['info']}</li>
        </ul>
    </div>

    <div class="findings">
        <h2>Findings</h2>
"""

        for finding in data['findings']:
            severity_class = finding['severity'].lower()
            html += f"""
        <div class="finding {severity_class}">
            <h3>{finding['title']}</h3>
            <p><strong>Severity:</strong> {finding['severity']}</p>
            <p><strong>URL:</strong> {finding['url']}</p>
            <p><strong>Parameter:</strong> {finding.get('parameter', 'N/A')}</p>
            <p><strong>Description:</strong> {finding['description']}</p>
            <p><strong>Payload:</strong> {finding.get('payload', 'N/A')}</p>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""
        return html

    def generate_markdown(self) -> str:
        """Generate Markdown report."""
        data = self._to_dict()

        md = f"""# PennyWise Security Scan Report

## Summary
- **Target:** {data['target']}
- **Scanned:** {data['timestamp']}
- **Duration:** {data['duration']:.2f} seconds
- **Status:** {data['status']}
- **Pages Scanned:** {data['pages_scanned']}
- **Requests Made:** {data['requests_made']}
- **Total Findings:** {data['total_findings']}

### Findings by Severity
- Critical: {data['findings_by_severity']['critical']}
- High: {data['findings_by_severity']['high']}
- Medium: {data['findings_by_severity']['medium']}
- Low: {data['findings_by_severity']['low']}
- Info: {data['findings_by_severity']['info']}

## Findings

"""

        for finding in data['findings']:
            md += f"""### {finding['title']}
- **Severity:** {finding['severity']}
- **URL:** {finding['url']}
- **Parameter:** {finding.get('parameter', 'N/A')}
- **Description:** {finding['description']}
- **Payload:** {finding.get('payload', 'N/A')}

"""

        return md

    def generate_summary(self) -> str:
        """Generate text summary."""
        data = self._to_dict()

        summary = f"""
============================================================
PENNYWISE SECURITY SCAN SUMMARY
============================================================
Target: {data['target']}
Scanned: {data['timestamp']}
Duration: {data['duration']:.2f} seconds

FINDINGS:
  Critical: {data['findings_by_severity']['critical']}
  High:     {data['findings_by_severity']['high']}
  Medium:   {data['findings_by_severity']['medium']}
  Low:      {data['findings_by_severity']['low']}
  Info:     {data['findings_by_severity']['info']}
  TOTAL:    {data['total_findings']}

STATISTICS:
  Pages Scanned: {data['pages_scanned']}
  Requests Made: {data['requests_made']}
  Status: {data['status']}
============================================================
"""
        return summary

    def _to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        findings_by_severity = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        findings_list = []
        for finding in self.scan_result.findings:
            findings_by_severity[finding.severity.value.lower()] += 1
            findings_list.append({
                'title': finding.title,
                'severity': finding.severity.value,
                'url': finding.url,
                'parameter': getattr(finding, 'parameter', None),
                'description': finding.description,
                'payload': getattr(finding, 'payload', None)
            })

        return {
            'target': self.scan_result.target_url,
            'timestamp': self.scan_result.start_time.isoformat() if self.scan_result.start_time else datetime.now().isoformat(),
            'duration': self.scan_result.duration_seconds,
            'status': self.scan_result.status,
            'pages_scanned': self.scan_result.pages_scanned,
            'requests_made': self.scan_result.requests_made,
            'total_findings': len(self.scan_result.findings),
            'findings_by_severity': findings_by_severity,
            'findings': findings_list
        }