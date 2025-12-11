"""
PennyWise Main Application.
Ties together all components for a complete vulnerability scanning experience.
"""

import asyncio
import argparse
import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, List
import logging

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from pennywise.core.enhanced_scanner import EnhancedScanner, VulnerabilityFinding, ScanProgress
from pennywise.sandbox.vulnerable_server import run_sandbox_server, create_sandbox_app
from pennywise.ai.analyzer import get_ai_analyzer
from pennywise.config import PennywiseConfig, AttackType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)


BANNER = """
    ╔═╗╔═╗╔╗╔╔╗╔╦ ╦╦ ╦╦╔═╗╔═╗
    ╠═╝║╣ ║║║║║║╚╦╝║║║║╚═╗║╣ 
    ╩  ╚═╝╝╚╝╝╚╝ ╩ ╚╩╝╩╚═╝╚═╝
    AI-Powered Vulnerability Scanner v2.1
"""


def print_banner():
    """Print the PennyWise banner."""
    print("\033[96m" + BANNER + "\033[0m")


def print_finding(finding: VulnerabilityFinding):
    """Print a finding in real-time."""
    severity_colors = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[33m',    # Orange
        'low': '\033[94m',       # Blue
        'info': '\033[90m',      # Gray
    }
    color = severity_colors.get(finding.severity.value, '\033[0m')
    reset = '\033[0m'
    
    print(f"\n{color}🔴 [{finding.severity.value.upper()}] {finding.title}{reset}")
    print(f"   URL: {finding.url}")
    if finding.parameter:
        print(f"   Parameter: {finding.parameter}")
    if finding.payload:
        print(f"   Payload: {finding.payload[:50]}...")


def print_progress(progress: ScanProgress):
    """Print progress update."""
    bar_length = 30
    filled = int(bar_length * progress.percentage / 100)
    bar = '█' * filled + '░' * (bar_length - filled)
    
    print(f"\r\033[K[{bar}] {progress.percentage}% - {progress.current_phase}", end='', flush=True)


def print_summary(result: dict):
    """Print a formatted summary of scan results."""
    print("\n" + "="*70)
    print("\033[96m PENNYWISE SECURITY SCAN REPORT \033[0m".center(70))
    print("="*70)
    
    print(f"\n\033[1mTarget:\033[0m {result['target_url']}")
    print(f"\033[1mDuration:\033[0m {result['duration_seconds']:.1f} seconds")
    print(f"\033[1mPages Scanned:\033[0m {result['pages_scanned']}")
    print(f"\033[1mRequests Made:\033[0m {result['requests_made']}")
    
    # Summary section
    summary = result.get('summary', {})
    overall_risk = summary.get('overall_risk', 'Unknown')
    
    risk_colors = {
        'Critical': '\033[91m',
        'High': '\033[93m', 
        'Medium': '\033[33m',
        'Low': '\033[94m',
        'Unknown': '\033[90m'
    }
    risk_color = risk_colors.get(overall_risk, '\033[0m')
    
    print(f"\n\033[1mOverall Risk:\033[0m {risk_color}{overall_risk}\033[0m")
    
    # Findings breakdown
    findings = result.get('findings', [])
    severity_counts = summary.get('severity_breakdown', {})
    
    print(f"\n\033[1mFindings Summary:\033[0m")
    print(f"  \033[91m● Critical:\033[0m {severity_counts.get('Critical', 0)}")
    print(f"  \033[93m● High:\033[0m     {severity_counts.get('High', 0)}")
    print(f"  \033[33m● Medium:\033[0m   {severity_counts.get('Medium', 0)}")
    print(f"  \033[94m● Low:\033[0m      {severity_counts.get('Low', 0)}")
    print(f"  \033[90m● Info:\033[0m     {severity_counts.get('Info', 0)}")
    print(f"  \033[1m  TOTAL:\033[0m    {len(findings)}")
    
    # Detailed findings
    if findings:
        print(f"\n\033[1mDetailed Findings:\033[0m")
        print("-"*70)
        
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'medium')
            color = risk_colors.get(severity.capitalize(), '\033[0m')
            
            print(f"\n{color}[{i}] {finding['title']}\033[0m")
            print(f"    Severity: {severity.upper()} | CVSS: {finding.get('cvss_score', 'N/A')}")
            print(f"    URL: {finding['url']}")
            if finding.get('parameter'):
                print(f"    Parameter: {finding['parameter']}")
            if finding.get('description'):
                desc = finding['description'][:100] + '...' if len(finding['description']) > 100 else finding['description']
                print(f"    Description: {desc}")
            
            if finding.get('recommendations'):
                print(f"    Recommendations:")
                for rec in finding['recommendations'][:2]:
                    print(f"      • {rec}")
    
    # Recommendations
    recommendations = summary.get('recommendations', [])
    if recommendations:
        print(f"\n\033[1mKey Recommendations:\033[0m")
        for rec in recommendations[:5]:
            print(f"  → {rec}")
    
    print("\n" + "="*70)


def save_report(result: dict, output_path: str, format: str = 'json'):
    """Save the report to a file."""
    path = Path(output_path)
    
    if format == 'json':
        path.write_text(json.dumps(result, indent=2, default=str))
    elif format == 'html':
        html = generate_html_report(result)
        path.write_text(html)
    
    print(f"\n📄 Report saved to: {path.absolute()}")


def generate_html_report(result: dict) -> str:
    """Generate an HTML report."""
    findings = result.get('findings', [])
    summary = result.get('summary', {})
    
    findings_html = ""
    for finding in findings:
        severity = finding.get('severity', 'medium')
        severity_class = f"severity-{severity.lower()}"
        
        findings_html += f"""
        <div class="finding {severity_class}">
            <h3>{finding['title']}</h3>
            <p class="severity">{severity.upper()} | CVSS: {finding.get('cvss_score', 'N/A')}</p>
            <p><strong>URL:</strong> {finding['url']}</p>
            {'<p><strong>Parameter:</strong> ' + finding['parameter'] + '</p>' if finding.get('parameter') else ''}
            <p>{finding.get('description', '')}</p>
            {'<p><strong>Evidence:</strong> <code>' + (finding.get('evidence', '')[:200]) + '</code></p>' if finding.get('evidence') else ''}
        </div>
        """
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PennyWise Security Report - {result['target_url']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            line-height: 1.6;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; padding: 40px 20px; }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding: 30px;
            background: rgba(0, 212, 255, 0.1);
            border-radius: 12px;
            border: 1px solid rgba(0, 212, 255, 0.2);
        }}
        .header h1 {{
            color: #00d4ff;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .target {{
            color: #888;
            font-size: 1.1em;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .stat-card .number {{
            font-size: 2em;
            font-weight: bold;
            color: #00d4ff;
        }}
        .stat-card .label {{
            color: #888;
            font-size: 0.9em;
        }}
        .risk-critical {{ background: rgba(255, 0, 0, 0.1); border-color: #ff4444; }}
        .risk-critical .number {{ color: #ff4444; }}
        .risk-high {{ background: rgba(255, 165, 0, 0.1); border-color: #ffa500; }}
        .risk-high .number {{ color: #ffa500; }}
        .risk-medium {{ background: rgba(255, 255, 0, 0.1); border-color: #ffff00; }}
        .risk-medium .number {{ color: #ffcc00; }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #00d4ff;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid rgba(0, 212, 255, 0.3);
        }}
        .finding {{
            background: rgba(255, 255, 255, 0.05);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #888;
        }}
        .finding h3 {{
            margin-bottom: 10px;
        }}
        .finding .severity {{
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .finding code {{
            background: rgba(0, 0, 0, 0.3);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9em;
            word-break: break-all;
        }}
        .severity-critical {{ border-color: #ff4444; }}
        .severity-critical .severity {{ color: #ff4444; }}
        .severity-high {{ border-color: #ffa500; }}
        .severity-high .severity {{ color: #ffa500; }}
        .severity-medium {{ border-color: #ffcc00; }}
        .severity-medium .severity {{ color: #ffcc00; }}
        .severity-low {{ border-color: #00aaff; }}
        .severity-low .severity {{ color: #00aaff; }}
        .recommendations {{
            background: rgba(0, 212, 255, 0.1);
            padding: 20px;
            border-radius: 10px;
        }}
        .recommendations li {{
            margin-bottom: 10px;
            padding-left: 10px;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 PennyWise Security Report</h1>
            <p class="target">{result['target_url']}</p>
            <p style="color: #666; margin-top: 10px;">
                Scanned: {result.get('scan_completed', 'N/A')} | 
                Duration: {result.get('duration_seconds', 0):.1f}s
            </p>
        </div>
        
        <div class="stats">
            <div class="stat-card risk-{summary.get('overall_risk', 'low').lower()}">
                <div class="number">{summary.get('overall_risk', 'N/A')}</div>
                <div class="label">Overall Risk</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(findings)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="number">{result.get('pages_scanned', 0)}</div>
                <div class="label">Pages Scanned</div>
            </div>
            <div class="stat-card">
                <div class="number">{result.get('requests_made', 0)}</div>
                <div class="label">Requests Made</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔍 Findings</h2>
            {findings_html if findings_html else '<p style="color: #888;">No vulnerabilities detected.</p>'}
        </div>
        
        <div class="section">
            <h2>📋 Recommendations</h2>
            <div class="recommendations">
                <ul>
                    {''.join(f'<li>{rec}</li>' for rec in summary.get('recommendations', ['No recommendations.']))}
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by PennyWise AI-Powered Vulnerability Scanner</p>
        </div>
    </div>
</body>
</html>"""


async def run_scan(target: str, 
                   attacks: Optional[List[str]] = None,
                   output: Optional[str] = None,
                   no_crawl: bool = False,
                   max_pages: int = 50,
                   threads: int = 10):
    """Run a vulnerability scan."""
    print_banner()
    
    # Parse attack types
    attack_types = None
    if attacks:
        attack_map = {
            'xss': AttackType.XSS,
            'sqli': AttackType.SQLI,
            'csrf': AttackType.CSRF,
            'auth': AttackType.AUTH,
            'all': None
        }
        
        if 'all' not in attacks:
            attack_types = []
            for a in attacks:
                if a.lower() in attack_map:
                    attack_types.append(attack_map[a.lower()])
    
    print(f"\n🎯 Target: {target}")
    print(f"📡 Attack Types: {', '.join(a.value for a in attack_types) if attack_types else 'All'}")
    print(f"🔄 Max Concurrent Requests: {threads}")
    print(f"📄 Max Pages: {max_pages}")
    print()
    
    # Create scanner
    scanner = EnhancedScanner(
        max_concurrent_requests=threads,
        on_finding=print_finding,
        on_progress=print_progress
    )
    
    # Run scan
    result = await scanner.scan(
        url=target,
        attack_types=attack_types,
        crawl=not no_crawl,
        max_pages=max_pages
    )
    
    print("\n")  # Clear progress line
    
    # Print summary
    print_summary(result)
    
    # Save report if output specified
    if output:
        format_type = 'html' if output.endswith('.html') else 'json'
        save_report(result, output, format_type)
    else:
        # Auto-save to default location
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        json_path = reports_dir / f"scan_{timestamp}.json"
        html_path = reports_dir / f"scan_{timestamp}.html"
        
        save_report(result, str(json_path), 'json')
        save_report(result, str(html_path), 'html')
    
    return result


async def run_sandbox(port: int = 8888):
    """Run the vulnerable sandbox server."""
    print_banner()
    print("\n🎪 Starting Vulnerable Sandbox Server...")
    print("⚠️  WARNING: This server contains intentional vulnerabilities!")
    print("    Never expose to the internet!")
    print()
    
    await run_sandbox_server(host='127.0.0.1', port=port)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog='pennywise',
        description='PennyWise - AI-Powered Vulnerability Scanner'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a target for vulnerabilities')
    scan_parser.add_argument('target', help='Target URL to scan')
    scan_parser.add_argument('-a', '--attacks', nargs='+', 
                            choices=['xss', 'sqli', 'csrf', 'auth', 'all'],
                            default=['all'],
                            help='Attack types to test')
    scan_parser.add_argument('-o', '--output', help='Output file path')
    scan_parser.add_argument('--no-crawl', action='store_true', help='Disable crawling')
    scan_parser.add_argument('-p', '--pages', type=int, default=50, help='Max pages to crawl')
    scan_parser.add_argument('-t', '--threads', type=int, default=10, help='Concurrent requests')
    
    # Sandbox command
    sandbox_parser = subparsers.add_parser('sandbox', help='Run vulnerable test server')
    sandbox_parser.add_argument('-p', '--port', type=int, default=8888, help='Port number')
    
    # Web UI command
    webui_parser = subparsers.add_parser('webui', help='Run the web interface')
    webui_parser.add_argument('-p', '--port', type=int, default=8080, help='Port number')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        asyncio.run(run_scan(
            target=args.target,
            attacks=args.attacks,
            output=args.output,
            no_crawl=args.no_crawl,
            max_pages=args.pages,
            threads=args.threads
        ))
    
    elif args.command == 'sandbox':
        asyncio.run(run_sandbox(port=args.port))
    
    elif args.command == 'webui':
        print_banner()
        print(f"\n🌐 Starting Web UI on http://localhost:{args.port}")
        # Import and run web UI
        from pennywise.webui.app import run_webui
        asyncio.run(run_webui(port=args.port))
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
