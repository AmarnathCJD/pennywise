#!/usr/bin/env python3
"""
Comprehensive test scanner for PennyWise against local vulnerable server.

This script:
1. Starts the vulnerable sandbox server (if not running)
2. Runs the scanner with all attack types enabled
3. Displays detailed findings with colored output
4. Validates expected vulnerabilities are detected
"""
import asyncio
import sys
import time
import subprocess
import socket
from typing import List, Dict, Any

# Add parent to path
sys.path.insert(0, '.')

from pennywise.core.enhanced_scanner import EnhancedScanner
from pennywise.config import AttackType, SeverityLevel

# ANSI colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def c(text: str, color: str) -> str:
    """Colorize text for terminal."""
    return f"{color}{text}{Colors.RESET}"


# Expected vulnerabilities in the sandbox server
EXPECTED_VULNERABILITIES = {
    'sqli': [
        '/sandbox/sqli',           # Product lookup SQLi
        '/sandbox/sqli/search',    # Search SQLi
        '/sandbox/sqli/login',     # Login SQLi
    ],
    'xss': [
        '/sandbox/xss/reflected',  # Reflected XSS
        '/sandbox/xss/stored',     # Stored XSS
        '/sandbox/xss/dom',        # DOM XSS
    ],
    'csrf': [
        '/sandbox/csrf/transfer',  # CSRF in transfer form
        '/sandbox/sqli/login',     # CSRF in login form
        '/sandbox/auth/login',     # CSRF in auth login
    ],
}


def is_server_running(host: str = '127.0.0.1', port: int = 8888) -> bool:
    """Check if the vulnerable server is running."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            return result == 0
    except:
        return False


def start_server():
    """Start the vulnerable sandbox server."""
    print(c("[*] Starting vulnerable sandbox server...", Colors.CYAN))
    
    # Start server in background
    process = subprocess.Popen(
        [sys.executable, '-m', 'pennywise.sandbox.vulnerable_server'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0
    )
    
    # Wait for server to start
    for _ in range(10):
        if is_server_running():
            print(c("[+] Server started successfully!", Colors.GREEN))
            return True
        time.sleep(0.5)
    
    print(c("[!] Failed to start server", Colors.RED))
    return False


class TestResults:
    """Track test results."""
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.expected_found = {'sqli': [], 'xss': [], 'csrf': []}
        self.expected_missed = {'sqli': [], 'xss': [], 'csrf': []}
    
    def add_finding(self, finding):
        self.findings.append(finding)
        attack_type = finding.attack_type.value if hasattr(finding.attack_type, 'value') else finding.attack_type
        url = finding.url if hasattr(finding, 'url') else finding.get('url', '')
        
        # Check if this matches expected vulnerabilities
        for expected_url in EXPECTED_VULNERABILITIES.get(attack_type, []):
            if expected_url in url:
                if expected_url not in self.expected_found.get(attack_type, []):
                    self.expected_found[attack_type].append(expected_url)
    
    def calculate_coverage(self):
        """Calculate detection coverage."""
        for attack_type, expected in EXPECTED_VULNERABILITIES.items():
            for url in expected:
                if url not in self.expected_found.get(attack_type, []):
                    self.expected_missed[attack_type].append(url)


results = TestResults()


def on_finding(finding):
    """Callback when a vulnerability is found."""
    results.add_finding(finding)
    
    # Get severity color
    severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
    severity_colors = {
        'critical': Colors.RED,
        'high': Colors.RED,
        'medium': Colors.YELLOW,
        'low': Colors.CYAN,
    }
    sev_color = severity_colors.get(severity.lower(), Colors.WHITE)
    
    print(f"\n{c('='*70, Colors.GREEN)}")
    print(c("[!] VULNERABILITY DETECTED!", Colors.GREEN + Colors.BOLD))
    print(c('='*70, Colors.GREEN))
    
    attack_type = finding.attack_type.value if hasattr(finding.attack_type, 'value') else str(finding.attack_type)
    print(f"  {c('Type:', Colors.CYAN)}       {c(attack_type.upper(), Colors.MAGENTA)}")
    print(f"  {c('Severity:', Colors.CYAN)}   {c(severity.upper(), sev_color)}")
    print(f"  {c('Title:', Colors.CYAN)}      {finding.title}")
    print(f"  {c('URL:', Colors.CYAN)}        {finding.url}")
    
    if finding.parameter:
        print(f"  {c('Parameter:', Colors.CYAN)}  {finding.parameter}")
    
    if finding.payload:
        payload_display = finding.payload[:80] + ('...' if len(finding.payload) > 80 else '')
        print(f"  {c('Payload:', Colors.CYAN)}    {c(payload_display, Colors.YELLOW)}")
    
    if finding.evidence:
        evidence_display = finding.evidence[:100] + ('...' if len(finding.evidence) > 100 else '')
        print(f"  {c('Evidence:', Colors.CYAN)}   {evidence_display}")
    
    if hasattr(finding, 'db_structure') and finding.db_structure:
        print(f"  {c('Database:', Colors.CYAN)}   {finding.db_structure[:100]}")
    
    print(c('='*70, Colors.GREEN) + "\n")


def on_log(message: str, level: str):
    """Callback for log messages."""
    level_colors = {
        'info': Colors.CYAN,
        'success': Colors.GREEN,
        'warning': Colors.YELLOW,
        'error': Colors.RED,
    }
    color = level_colors.get(level, Colors.WHITE)
    
    # Only show important messages
    if level in ['success', 'warning', 'error'] or 'FOUND' in message or 'VULN' in message.upper():
        print(f"{c(f'[{level.upper()}]', color)} {message}")


async def run_scan(target: str = 'http://127.0.0.1:8888/sandbox'):
    """Run the vulnerability scan."""
    print(f"\n{c('='*70, Colors.BLUE)}")
    print(c("  PENNYWISE VULNERABILITY SCANNER - TEST SUITE", Colors.BLUE + Colors.BOLD))
    print(c('='*70, Colors.BLUE))
    print(f"  {c('Target:', Colors.CYAN)} {target}")
    print(f"  {c('Tests:', Colors.CYAN)}  XSS, SQLi, CSRF")
    print(f"  {c('Mode:', Colors.CYAN)}   Full scan with crawling")
    print(c('='*70, Colors.BLUE) + "\n")
    
    scanner = EnhancedScanner(
        max_concurrent_requests=30,
        on_log=on_log,
        on_finding=on_finding
    )
    
    start_time = time.time()
    
    # Run the scan
    scan_results = await scanner.scan(
        target,
        attack_types=[AttackType.XSS, AttackType.SQLI, AttackType.CSRF],
        crawl=True,
        max_pages=30
    )
    
    duration = time.time() - start_time
    
    # Calculate coverage
    results.calculate_coverage()
    
    # Print summary
    print(f"\n{c('='*70, Colors.MAGENTA)}")
    print(c("  SCAN RESULTS SUMMARY", Colors.MAGENTA + Colors.BOLD))
    print(c('='*70, Colors.MAGENTA))
    
    print(f"\n  {c('Scan Statistics:', Colors.CYAN + Colors.BOLD)}")
    print(f"    - Pages crawled:  {scan_results.get('pages_scanned', 0)}")
    print(f"    - Requests made:  {scan_results.get('requests_made', 0)}")
    print(f"    - Duration:       {duration:.2f}s")
    
    findings = scan_results.get('findings', [])
    print(f"\n  {c('Findings:', Colors.CYAN + Colors.BOLD)}")
    print(f"    - Total:    {c(str(len(findings)), Colors.GREEN if findings else Colors.YELLOW)}")
    
    # Count by type
    by_type = {}
    for f in findings:
        atype = f.get('attack_type', 'unknown')
        by_type[atype] = by_type.get(atype, 0) + 1
    
    for atype, count in by_type.items():
        print(f"    - {atype.upper()}: {count}")
    
    # Expected vs Found analysis
    print(f"\n  {c('Detection Coverage:', Colors.CYAN + Colors.BOLD)}")
    total_expected = sum(len(v) for v in EXPECTED_VULNERABILITIES.values())
    total_found = sum(len(v) for v in results.expected_found.values())
    
    for attack_type in ['sqli', 'xss', 'csrf']:
        expected = len(EXPECTED_VULNERABILITIES.get(attack_type, []))
        found = len(results.expected_found.get(attack_type, []))
        missed = results.expected_missed.get(attack_type, [])
        
        status = c('OK', Colors.GREEN) if found == expected else c(f'PARTIAL ({found}/{expected})', Colors.YELLOW)
        print(f"    - {attack_type.upper()}: {status}")
        
        if missed:
            for m in missed:
                print(f"      {c('MISSED:', Colors.RED)} {m}")
    
    coverage = (total_found / total_expected * 100) if total_expected > 0 else 0
    print(f"\n    {c('Overall Coverage:', Colors.BOLD)} {coverage:.1f}%")
    
    # Final verdict
    print(f"\n{c('='*70, Colors.MAGENTA)}")
    if len(findings) > 0:
        print(c(f"  [+] SCAN COMPLETE: {len(findings)} VULNERABILITIES DETECTED!", Colors.GREEN + Colors.BOLD))
    else:
        print(c("  [!] SCAN COMPLETE: NO VULNERABILITIES DETECTED", Colors.YELLOW + Colors.BOLD))
        print(c("      This may indicate detection issues.", Colors.YELLOW))
    print(c('='*70, Colors.MAGENTA) + "\n")
    
    return scan_results


async def main():
    """Main entry point."""
    target = 'http://127.0.0.1:8888/sandbox'
    
    # Check if server is running
    if not is_server_running():
        print(c("[!] Vulnerable server not running!", Colors.YELLOW))
        print(c("[*] Please start it with:", Colors.CYAN))
        print(c("    python -m pennywise.sandbox.vulnerable_server", Colors.WHITE))
        print()
        
        # Try to start it
        response = input("Start server automatically? (y/n): ").strip().lower()
        if response == 'y':
            if not start_server():
                print(c("[!] Could not start server. Please start manually.", Colors.RED))
                return
        else:
            return
    
    print(c("[+] Server is running!", Colors.GREEN))
    
    # Run the scan
    await run_scan(target)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(c("\n[*] Scan interrupted by user", Colors.YELLOW))
    except Exception as e:
        print(c(f"\n[!] Error: {e}", Colors.RED))
        import traceback
        traceback.print_exc()
