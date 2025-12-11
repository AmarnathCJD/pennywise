#!/usr/bin/env python3
"""Test scanner against local vulnerable server."""
import asyncio
from pennywise.core.enhanced_scanner import EnhancedScanner
from pennywise.config import AttackType

def on_log(message, level):
    print(f'[{level}] {message}')

def on_finding(finding):
    print(f'\n*** FOUND: {finding.title} ***')
    print(f'    Severity: {finding.severity.value}')
    print(f'    Parameter: {finding.parameter}')
    print(f'    Payload: {finding.payload[:100]}...')
    print()

async def main():
    scanner = EnhancedScanner(
        max_concurrent_requests=10,
        on_log=on_log,
        on_finding=on_finding
    )
    
    results = await scanner.scan(
        'http://127.0.0.1:5000',
        attack_types=[AttackType.XSS, AttackType.SQLI, AttackType.CSRF],
        crawl=True,
        max_pages=10
    )
    
    print(f"\n\n{'='*60}")
    print(f"SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Pages scanned: {results.get('pages_scanned', 0)}")
    print(f"Requests made: {results.get('requests_made', 0)}")
    print(f"Findings: {len(results.get('findings', []))}")
    print(f"{'='*60}\n")
    
    for idx, finding in enumerate(results.get('findings', []), 1):
        print(f"{idx}. {finding['title']} - {finding['severity']} - {finding['url']}")

if __name__ == '__main__':
    asyncio.run(main())
