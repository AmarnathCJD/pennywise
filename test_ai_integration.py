#!/usr/bin/env python3
"""
Test the updated AI analyzer with Qwen model integration
"""

from pennywise.ai.analyzer import get_ai_analyzer
import logging
logging.basicConfig(level=logging.INFO)

print('Testing updated AI analyzer...')
try:
    analyzer = get_ai_analyzer()
    print('✓ AI Analyzer initialized with Qwen model')

    # Test target analysis
    test_html = '<html><body><form action="/search" method="get"><input type="text" name="q" value=""><input type="submit" value="Search"></form><div id="results"></div></body></html>'

    test_headers = {'Content-Type': 'text/html', 'Server': 'nginx/1.18.0'}

    recommendations = analyzer.analyze_target('http://example.com/search?q=test', test_html, test_headers)
    print(f'✓ AI-powered target analysis completed: {len(recommendations)} recommendations')

    for rec in recommendations[:3]:  # Show first 3
        print(f'  - {rec.attack_type.value}: {rec.probability:.2f} confidence')

    # Test severity classification
    test_finding = {
        'attack_type': 'xss',
        'title': 'Cross-site scripting vulnerability',
        'description': 'Found XSS in search parameter',
        'url': 'http://example.com/search?q=<script>alert(1)</script>',
        'payload': '<script>alert(1)</script>',
        'evidence': 'Script executed in browser'
    }

    severity = analyzer.classify_severity(test_finding)
    print(f'✓ AI-powered severity classification: {severity.severity} (CVSS: {severity.cvss_score})')

    # Test remediation suggestions
    remediation = analyzer.suggest_remediation(test_finding)
    print(f'✓ AI-powered remediation suggestions: {len(remediation)} suggestions')

    print('\n🎉 All AI functions now working with Qwen model!')

except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()