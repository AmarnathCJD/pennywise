#!/usr/bin/env python3
"""
Simple test to debug the XSS crawler behavior
"""

import sys
import logging
from modules.xss.sub.xss_selenium import crawl_and_scan

# Enable verbose logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    # Test with localhost first
    test_urls = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://juice-shop.herokuapp.com",
    ]
    
    print("=" * 60)
    print("XSS CRAWLER TEST")
    print("=" * 60)
    
    for test_url in test_urls:
        print(f"\n\nTesting: {test_url}")
        print("-" * 60)
        try:
            findings = crawl_and_scan(test_url)
            print(f"\nFindings: {len(findings)} vulnerabilities found")
            for f in findings[:5]:  # Show first 5
                print(f"  - {f.get('type')}: {f.get('url', 'N/A')[:50]}...")
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
        
        break  # Only test first URL for now
