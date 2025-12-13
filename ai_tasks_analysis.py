#!/usr/bin/env python3
"""
AI Tasks Analysis - What the AI Currently Does in PennyWise
Shows current AI responsibilities and payload selection mechanism
"""

import sys
import json
from datetime import datetime

# Add parent to path
sys.path.insert(0, '.')

from pennywise.ai.model_interface import AIModelInterface
from pennywise.core.payloads import PayloadLibrary, AttackType

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"

def print_header(title: str):
    print(colorize(f"\n{'='*70}", Colors.BLUE))
    print(colorize(f" {title}", Colors.BOLD + Colors.BLUE))
    print(colorize(f"{'='*70}", Colors.BLUE))

def print_section(title: str):
    print(colorize(f"\n{title}", Colors.BOLD + Colors.GREEN))
    print(colorize(f"{'-'*len(title)}", Colors.GREEN))

def analyze_ai_current_tasks():
    """Analyze what the AI currently does."""
    print_header("🤖 CURRENT AI TASKS IN PENNYWISE")

    print_section("AI Model Interface (Qwen3-0.6B) - Current Functions")

    ai_tasks = {
        "🎯 Target Analysis & Attack Recommendation": {
            "function": "analyze_target()",
            "description": "Analyzes target HTML/headers to recommend attack types",
            "input": "URL, HTML content, response headers",
            "output": "List of AttackRecommendation with probabilities",
            "used_in": "Scanner initialization for attack strategy"
        },
        "🔍 Vulnerability Analysis": {
            "function": "analyze_vulnerability()",
            "description": "Deep analysis of individual security findings",
            "input": "Vulnerability details (type, title, description, URL, payload)",
            "output": "Risk assessment, impact analysis, remediation steps",
            "used_in": "Post-detection analysis of findings"
        },
        "📊 Severity Classification": {
            "function": "classify_severity()",
            "description": "Classifies vulnerability severity with CVSS scoring",
            "input": "Vulnerability data dictionary",
            "output": "Severity level (Critical/High/Medium/Low) + CVSS score",
            "used_in": "Finding classification after detection"
        },
        "🛠️ Remediation Suggestions": {
            "function": "suggest_remediation()",
            "description": "Provides step-by-step fix recommendations",
            "input": "Vulnerability details",
            "output": "Structured remediation suggestions with code examples",
            "used_in": "Report generation and AI analysis"
        },
        "🌐 Site Auditing": {
            "function": "audit_site()",
            "description": "Comprehensive site security assessment",
            "input": "Site structure, technologies, configurations",
            "output": "Overall security posture analysis",
            "used_in": "Advanced scanning modes"
        }
    }

    for task_name, details in ai_tasks.items():
        print(f"\n{task_name}")
        print(f"   Function: {colorize(details['function'], Colors.CYAN)}")
        print(f"   Description: {details['description']}")
        print(f"   Input: {details['input']}")
        print(f"   Output: {details['output']}")
        print(f"   Used In: {details['used_in']}")

def analyze_payload_selection():
    """Analyze how payloads are currently selected."""
    print_header("🎯 PAYLOAD SELECTION MECHANISM")

    print_section("Current Payload Selection: RULE-BASED (Not AI-Driven)")

    payload_selection = {
        "Selection Method": "RULE-BASED ALGORITHM",
        "AI Involvement": "❌ NONE - Payloads selected by hardcoded logic",
        "Current Logic": [
            "Context-aware selection (API vs web forms)",
            "Attack type categorization",
            "Effectiveness scoring",
            "Category filtering (api_json, basic, etc.)"
        ],
        "Payload Library": "Dynamic library with 54+ payloads",
        "Selection Factors": [
            "Injection point type (query param, form input, API endpoint)",
            "Attack type (XSS, SQLi, CSRF)",
            "Context (API vs regular web app)",
            "Success rate tracking"
        ]
    }

    for key, value in payload_selection.items():
        print(f"• {key}: {colorize(str(value), Colors.CYAN)}")

    print_section("How Payloads Are Currently Selected")

    selection_process = [
        "1. Scanner identifies injection points (forms, params, APIs)",
        "2. For each attack type, payload library is queried",
        "3. Selection based on: attack_type + context (API/form) + limit",
        "4. Example: XSS on API → get_payloads(AttackType.XSS, limit=15, category='api_json')",
        "5. Fallback to basic payloads if library unavailable",
        "6. Payloads tested in parallel batches (10 at a time)"
    ]

    for step in selection_process:
        print(f"   {step}")

    print_section("Payload Categories Available")

    try:
        payload_lib = PayloadLibrary()
        categories = {}

        # Check what categories exist
        for attack_type in [AttackType.XSS, AttackType.SQLI, AttackType.CSRF]:
            payloads = payload_lib.get_payloads(attack_type, limit=50)
            if payloads:
                for payload in payloads[:5]:  # Sample first 5
                    cat = payload.category
                    if cat not in categories:
                        categories[cat] = []
                    if len(categories[cat]) < 3:  # Show up to 3 examples per category
                        categories[cat].append(payload.vector[:50] + "..." if len(payload.vector) > 50 else payload.vector)

        for category, examples in categories.items():
            print(f"• {category.upper()}:")
            for example in examples:
                print(f"   - {colorize(example, Colors.YELLOW)}")

    except Exception as e:
        print(f"Could not load payload library: {e}")

def show_ai_vs_rule_based_comparison():
    """Compare AI tasks vs rule-based payload selection."""
    print_header("🤖 AI vs RULE-BASED: CURRENT ARCHITECTURE")

    print_section("AI-Handled Tasks (Intelligent Analysis)")

    ai_tasks = [
        "✅ Target reconnaissance and attack type recommendation",
        "✅ Vulnerability severity classification with CVSS scoring",
        "✅ Impact assessment and risk evaluation",
        "✅ Remediation planning with step-by-step fixes",
        "✅ Natural language analysis of findings",
        "✅ Context-aware security assessment"
    ]

    for task in ai_tasks:
        print(f"   {task}")

    print_section("Rule-Based Tasks (Algorithmic Selection)")

    rule_tasks = [
        "❌ Payload selection and customization",
        "❌ Attack execution logic and flow",
        "❌ Injection point discovery",
        "❌ Response analysis and pattern matching",
        "❌ Crawling and site mapping",
        "❌ Concurrency and performance optimization"
    ]

    for task in rule_tasks:
        print(f"   {task}")

    print_section("Why Payload Selection is Rule-Based")

    reasons = [
        "Performance: AI model calls are expensive/slow for payload testing",
        "Precision: Rule-based ensures comprehensive coverage of edge cases",
        "Speed: Thousands of payloads can be tested quickly with rules",
        "Reliability: Deterministic selection vs potential AI hallucinations",
        "Context: Complex injection contexts require algorithmic precision"
    ]

    for reason in reasons:
        print(f"• {reason}")

def show_potential_ai_payload_selection():
    """Show what AI-driven payload selection could look like."""
    print_header("🚀 FUTURE: AI-DRIVEN PAYLOAD SELECTION")

    print_section("Potential AI Payload Selection Capabilities")

    future_ai_payloads = {
        "Context-Aware Selection": "AI analyzes injection context to choose optimal payloads",
        "Adaptive Payload Generation": "AI creates custom payloads based on target patterns",
        "Success Prediction": "AI predicts which payloads are most likely to succeed",
        "Evasion Techniques": "AI selects payloads that bypass specific WAFs/filters",
        "Multi-Stage Attacks": "AI orchestrates complex multi-payload attack chains",
        "Learning from Failures": "AI adapts payload selection based on previous failures"
    }

    for capability, description in future_ai_payloads.items():
        print(f"• {capability}: {description}")

    print_section("Current Limitations of Rule-Based Selection")

    limitations = [
        "No adaptation to target-specific defenses",
        "Cannot generate novel payloads for new vulnerabilities",
        "Limited understanding of complex contexts",
        "No learning from previous scan failures",
        "Cannot predict payload effectiveness"
    ]

    for limitation in limitations:
        print(f"• {limitation}")

def main():
    """Main analysis function."""
    analyze_ai_current_tasks()
    analyze_payload_selection()
    show_ai_vs_rule_based_comparison()
    show_potential_ai_payload_selection()

    print_header("📊 SUMMARY: AI TASKS IN PENNYWISE")
    print(colorize("\n🤖 AI CURRENTLY HANDLES:", Colors.BOLD + Colors.GREEN))
    print("• Target analysis and attack type recommendations")
    print("• Vulnerability severity classification")
    print("• Impact assessment and risk evaluation")
    print("• Remediation planning and fix suggestions")
    print("• Natural language processing of security findings")

    print(colorize("\n🎯 PAYLOAD SELECTION IS:", Colors.BOLD + Colors.YELLOW))
    print("• RULE-BASED algorithmic selection (not AI-driven)")
    print("• Context-aware but deterministic")
    print("• Fast and comprehensive coverage")
    print("• No AI involvement in payload choice")

    print(colorize("\n🔮 FUTURE POTENTIAL:", Colors.BOLD + Colors.CYAN))
    print("• AI-driven payload selection and generation")
    print("• Adaptive payload customization")
    print("• Success prediction and evasion techniques")
    print("• Learning from attack patterns")

    print(colorize("\n✅ CURRENT SYSTEM: AI + Rules = Optimal Performance", Colors.BOLD + Colors.MAGENTA))

if __name__ == "__main__":
    main()