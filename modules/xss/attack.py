#!/usr/bin/env python3
"""
Main module for attack testing. Menu-driven interface for different attack types.
Currently supports XSS testing. Other attacks can be added later.
"""
import sys
from .sub import xss_selenium as xss

PENNY = r"""
    ╔═╗╔═╗╔╗╔╔╗╔╦ ╦╦ ╦╦╔═╗╔═╗
    ╠═╝║╣ ║║║║║║╚╦╝║║║║╚═╗║╣ 
    ╩  ╚═╝╝╚╝╝╚╝ ╩ ╚╩╝╩╚═╝╚═╝
"""

def run_xss_scan(url):
    if not xss.is_allowed_target(url):
        return []
    findings = xss.crawl_and_scan(url)
    return findings or []

def menu():
    print(PENNY)
    print("Welcome to PennyWise Attack Testing Framework!")
    print("Select an attack type:")
    print("1. XSS Scanner (local)")
    print("2. [Reserved for future attacks]")
    print("0. Exit")

def run_xss():
    url = input("Enter target URL (localhost/127.0.0.1 only): ").strip()
    if not xss.is_allowed_target(url):
        print("ERROR: start URL must be localhost or 127.0.0.1")
        return
    print("Scanning for XSS vulnerabilities...")
    findings = xss.crawl_and_scan(url)
    categorized = xss.categorize_findings(findings or [])
    print("\n=== Scan Summary ===")
    any_findings = any(len(v) for v in categorized.values())
    if any_findings:
        print("Summary (PennyWise findings grouped by category):\n")
        for cat, items in categorized.items():
            print(f"--- {cat} ({len(items)}) ---")
            if not items:
                print("  (none)")
            else:
                for i, item in enumerate(items, 1):
                    print(f"  {i}. {item}")
            print()
    else:
        print("No obvious issues found by this scanner.")
    print("Scan complete.")
    # Generate PDF report
    xss.generate_pdf_report(categorized)

def main():
    while True:
        menu()
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            run_xss()
        elif choice == "0":
            print("Exiting PennyWise. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

