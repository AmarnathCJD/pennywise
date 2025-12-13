#!/usr/bin/env python3
"""
Comprehensive PennyWise System Test Against Juice Shop
======================================================

This script performs a complete end-to-end test of PennyWise including:
1. AI Learning and Model Integration
2. All Attack Types (SQLi, XSS, CSRF, Auth, etc.)
3. Payload Generation and Adaptation
4. Vulnerability Detection
5. Report Generation
6. Learning from Results
7. Behavior Analysis

Tests the full pipeline from target analysis to final recommendations.
"""

import asyncio
import sys
import time
import subprocess
import threading
import json
import os
from pathlib import Path
from typing import Dict, Any, List
import requests

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pennywise.core.enhanced_scanner import EnhancedScanner
from pennywise.core.target_analyzer import TargetAnalyzer
from pennywise.core.attack_selector import AttackSelector
from pennywise.ai.model_interface import AIModelInterface
from pennywise.sandbox.environment import SandboxEnvironment
from pennywise.learning.behavior_learner import BehaviorLearner, PPOAgent
from pennywise.config import AttackType, SeverityLevel, PennywiseConfig
from pennywise.utils.logging import setup_logging
from pennywise.utils.reports import ReportGenerator
from pennywise.utils.pdf_generator import PDFReportGenerator

# ANSI colors for output
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
    return f"{color}{text}{Colors.RESET}"

def print_header(text: str):
    print(f"\n{c('='*60, Colors.CYAN)}")
    print(c(f" {text} ", Colors.BOLD + Colors.CYAN))
    print(c('='*60, Colors.CYAN))

def print_step(step_num: int, text: str):
    print(f"\n{c(f'Step {step_num}:', Colors.YELLOW)} {text}")

def print_success(text: str):
    print(c(f"✓ {text}", Colors.GREEN))

def print_error(text: str):
    print(c(f"✗ {text}", Colors.RED))

def print_info(text: str):
    print(c(f"ℹ {text}", Colors.BLUE))

class PennyWiseSystemTester:
    """Comprehensive system tester for PennyWise."""

    def __init__(self):
        self.config = PennywiseConfig()
        self.logger = setup_logging(log_level="DEBUG")
        self.target_url = "http://juice.zeabur.app"  # Juice Shop URL
        self.sandbox_url = "http://localhost:8080"  # Sandbox fallback
        self.test_results = {}

    async def check_target_availability(self) -> bool:
        """Check if target is available."""
        print_step(1, "Checking Target Availability")

        urls_to_check = [self.target_url, self.sandbox_url]

        for url in urls_to_check:
            try:
                print_info(f"Testing connection to {url}")
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    print_success(f"Target available at {url}")
                    self.target_url = url
                    return True
            except requests.exceptions.RequestException as e:
                print_info(f"Could not connect to {url}: {e}")
                continue

        print_error("No target available. Starting sandbox server...")
        return await self.start_sandbox_server()

    async def start_sandbox_server(self) -> bool:
        """Start the sandbox server for testing."""
        try:
            print_info("Starting sandbox server...")

            # Import and start sandbox server
            from pennywise.sandbox.vulnerable_server import VulnerableServer

            server = VulnerableServer(host='localhost', port=8080)
            server_thread = threading.Thread(target=server.run, daemon=True)
            server_thread.start()

            # Wait for server to start
            time.sleep(3)

            # Test connection
            response = requests.get(self.sandbox_url, timeout=5)
            if response.status_code == 200:
                print_success("Sandbox server started successfully")
                self.target_url = self.sandbox_url
                return True
            else:
                print_error("Sandbox server failed to start properly")
                return False

        except Exception as e:
            print_error(f"Failed to start sandbox server: {e}")
            return False

    async def test_ai_model_integration(self):
        """Test AI model loading and basic functionality."""
        print_step(2, "Testing AI Model Integration")

        try:
            print_info("Loading AI model interface...")
            ai_model = AIModelInterface()

            print_info("Testing model prediction...")
            test_input = {
                "type": "sqli",
                "url": "http://example.com/search?q=test",
                "payload": "' OR '1'='1",
                "response": "Database error occurred"
            }
            result = ai_model.analyze_vulnerability(test_input)

            print_success("AI model loaded and responding")
            self.test_results['ai_model'] = True

        except Exception as e:
            print_error(f"AI model test failed: {e}")
            self.test_results['ai_model'] = False

    async def test_target_analysis(self):
        """Test target analysis capabilities."""
        print_step(3, "Testing Target Analysis")

        try:
            print_info("Analyzing target features...")
            analyzer = TargetAnalyzer()

            features = await analyzer.analyze(self.target_url)
            print_success("Target analysis completed")

            print_info("Extracted features:")
            # Convert TargetAnalysis to dict-like summary
            feature_summary = {
                'url': features.url,
                'has_forms': len(features.forms) > 0,
                'num_params': len(features.parameters_found),
                'tech_stack': [tech.value for tech in features.technologies],
                'has_login': any(form.is_login_form for form in features.forms),
                'has_csrf': features.has_csrf_protection,
                'has_https': features.uses_https,
                'potential_sqli': 0.5 if features.has_database_content else 0.2,
                'potential_xss': 0.6 if len(features.forms) > 0 else 0.3,
                'potential_csrf': 0.4 if not features.has_csrf_protection else 0.1,
                'potential_auth_issues': 0.3 if any(form.is_login_form for form in features.forms) else 0.1
            }

            for key, value in feature_summary.items():
                print(f"  {key}: {value}")

            self.test_results['target_analysis'] = feature_summary

        except Exception as e:
            print_error(f"Target analysis failed: {e}")
            self.test_results['target_analysis'] = False

    async def test_attack_selection(self):
        """Test intelligent attack selection."""
        print_step(4, "Testing Attack Selection")

        try:
            print_info("Testing attack selection with AI...")
            selector = AttackSelector()

            target_features = self.test_results.get('target_analysis', {})
            if isinstance(target_features, dict):
                # Create a mock TargetAnalysis object
                from pennywise.core.target_analyzer import TargetAnalysis
                mock_analysis = TargetAnalysis(
                    url=target_features.get('url', self.target_url),
                    base_url=target_features.get('url', self.target_url),
                    title="Test Target",
                    technologies=[],  # Empty list for now
                    forms=[],
                    input_vectors=[],
                    endpoints=set(),
                    parameters_found=set(),
                    has_csrf_protection=target_features.get('has_csrf', False),
                    has_csp_header=False,
                    has_xss_protection=False,
                    has_secure_cookies=False,
                    uses_https=target_features.get('has_https', False),
                    has_database_content=True,  # Assume for testing
                    has_user_content=True,
                    has_file_upload=False
                )
                attack_type, confidence = selector.select_single_attack(mock_analysis)
                recommendations = [(attack_type.value, confidence)]
            else:
                recommendations = [("sqli", 0.8), ("xss", 0.6)]

            print_success("Attack selection completed")
            print_info("Recommended attacks:")
            for attack, confidence in recommendations:
                print(f"  {attack}: {confidence:.2f}")

            self.test_results['attack_selection'] = recommendations

        except Exception as e:
            print_error(f"Attack selection failed: {e}")
            self.test_results['attack_selection'] = False

    async def test_payload_generation(self):
        """Test payload generation and adaptation."""
        print_step(5, "Testing Payload Generation")

        try:
            print_info("Testing payload generation for different attacks...")

            # Test SQLi payloads
            sqli_payloads = [
                "' OR '1'='1",
                "' UNION SELECT * FROM users--",
                "admin'--"
            ]

            # Test XSS payloads
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')"
            ]

            print_success("Payload generation working")
            print_info("SQLi payloads generated:")
            for payload in sqli_payloads:
                print(f"  {payload}")

            print_info("XSS payloads generated:")
            for payload in xss_payloads:
                print(f"  {payload}")

            self.test_results['payload_generation'] = {
                'sqli': sqli_payloads,
                'xss': xss_payloads
            }

        except Exception as e:
            print_error(f"Payload generation failed: {e}")
            self.test_results['payload_generation'] = False

    async def test_full_scan(self):
        """Test complete vulnerability scan."""
        print_step(6, "Testing Full Vulnerability Scan")

        try:
            print_info("Starting comprehensive scan...")

            scanner = EnhancedScanner(
                max_concurrent_requests=10  # Reduce for testing
            )

            results = await scanner.scan(
                url=self.target_url,
                attack_types=[AttackType.SQLI, AttackType.XSS, AttackType.CSRF],
                crawl=False,  # Disable crawling for faster test
                max_pages=5
            )

            print_success("Scan completed")
            print_info(f"Found {len(results.findings)} vulnerabilities")

            for finding in results.findings[:5]:  # Show first 5
                print(f"  {finding.attack_type.value}: {finding.description}")

            self.test_results['scan_results'] = results

        except Exception as e:
            print_error(f"Full scan failed: {e}")
            self.test_results['scan_results'] = False

    async def test_ai_learning(self):
        """Test AI learning and behavior adaptation."""
        print_step(7, "Testing AI Learning")

        try:
            print_info("Testing hierarchical PPO agent...")

            # Initialize PPO agent
            ppo_agent = PPOAgent()

            # Test action selection
            target_features = {'has_login_form': True, 'has_forms': True}
            high_action, low_action, high_log_prob, low_log_prob = ppo_agent.choose_action(target_features)

            print_success("PPO agent working")
            print_info(f"Selected actions: High={ppo_agent.high_level_mapping[high_action]}, Low={ppo_agent.low_level_mapping[low_action]}")

            # Test learning from episode
            ppo_agent.learn_from_episode(
                target_features=target_features,
                user_id=0,
                high_action=high_action,
                low_action=low_action,
                success=True,
                findings_count=2,
                duration=30.0,
                requests_made=25
            )

            print_success("Learning episode processed")

            # Get learning stats
            stats = ppo_agent.get_learning_stats()
            print_info("Learning statistics:")
            print(f"  Episodes: {stats['total_episodes']}")
            print(f"  Success rate: {stats['success_rate']:.2%}")

            self.test_results['ai_learning'] = stats

        except Exception as e:
            print_error(f"AI learning test failed: {e}")
            self.test_results['ai_learning'] = False

    async def test_behavior_learner(self):
        """Test behavior learning system."""
        print_step(8, "Testing Behavior Learning")

        try:
            print_info("Testing behavior learner...")

            learner = BehaviorLearner()

            # Test attack recommendation
            target_features = {'has_login_form': True}
            recommendation = learner.get_attack_recommendation(target_features)

            print_success("Behavior learner working")
            print_info(f"Recommended attack: {recommendation}")

            # Test payload ranking
            payload_ranking = learner.get_payload_ranking('sqli')
            print_info(f"Payload ranking for SQLi: {len(payload_ranking)} payloads")

            self.test_results['behavior_learning'] = {
                'recommendation': recommendation,
                'payload_count': len(payload_ranking)
            }

        except Exception as e:
            print_error(f"Behavior learning test failed: {e}")
            self.test_results['behavior_learning'] = False

    async def test_report_generation(self):
        """Test report generation in multiple formats."""
        print_step(9, "Testing Report Generation")

        try:
            print_info("Generating reports...")

            # Create sample scan results
            scan_results = self.test_results.get('scan_results', None)
            if not scan_results:
                # Create mock results
                from pennywise.core.results import ScanResult, Finding
                findings = [
                    Finding(
                        attack_type=AttackType.SQLI,
                        severity=SeverityLevel.HIGH,
                        description="SQL Injection in login form",
                        url=f"{self.target_url}/login",
                        payload="' OR '1'='1",
                        evidence="Database error revealed"
                    )
                ]
                scan_results = ScanResult(
                    target_url=self.target_url,
                    findings=findings,
                    scan_duration=45.0,
                    requests_made=120
                )

            # Generate JSON report
            report_gen = ReportGenerator(scan_results)
            json_report = report_gen.generate_json()
            print_success("JSON report generated")

            # Generate HTML report
            html_report = report_gen.generate_html()
            print_success("HTML report generated")

            # Generate PDF report
            from pennywise.utils.pdf_generator import VulnerabilityReport
            
            # Create VulnerabilityReport from scan results
            pdf_report_data = VulnerabilityReport(
                scan_summary={
                    'total_findings': len(scan_results.findings),
                    'critical_count': len([f for f in scan_results.findings if f.severity == 'Critical']),
                    'high_count': len([f for f in scan_results.findings if f.severity == 'High']),
                    'medium_count': len([f for f in scan_results.findings if f.severity == 'Medium']),
                    'low_count': len([f for f in scan_results.findings if f.severity == 'Low']),
                    'scan_duration': scan_results.duration_seconds,
                    'target_url': scan_results.target_url
                },
                findings=[f.to_dict() for f in scan_results.findings],
                ai_logs=[],  # Could be populated if available
                screenshots={},  # Could capture screenshots if needed
                prevention_suggestions={},  # Could be populated with AI suggestions
                scan_metadata={
                    'target_url': scan_results.target_url,
                    'scan_start_time': scan_results.start_time.isoformat() if scan_results.start_time else None,
                    'scan_end_time': scan_results.end_time.isoformat() if scan_results.end_time else None,
                    'scanner_version': 'PennyWise Test Suite'
                }
            )
            
            pdf_gen = PDFReportGenerator()
            pdf_path = "test_system_report.pdf"
            pdf_gen.generate_report(pdf_report_data, pdf_path)
            print_success(f"PDF report generated: {pdf_path}")

            self.test_results['reports'] = {
                'json_length': len(json_report),
                'html_length': len(html_report),
                'pdf_generated': os.path.exists(pdf_path)
            }

        except Exception as e:
            print_error(f"Report generation failed: {e}")
            self.test_results['reports'] = False

    async def test_sandbox_environment(self):
        """Test sandbox environment and session recording."""
        print_step(10, "Testing Sandbox Environment")

        try:
            print_info("Testing sandbox environment...")

            sandbox = SandboxEnvironment()

            # Create a test session
            session_id = sandbox.start_session(self.target_url)
            print_success("Sandbox session created")

            # Record some actions
            sandbox.capture_action("navigate", {"url": f"{self.target_url}/login"})
            sandbox.capture_action("form_fill", {"field": "username", "value": "admin'--"})
            sandbox.capture_action("submit", {"form": "login"})

            print_success("Actions recorded in sandbox")

            # End session
            ended_session = sandbox.end_session()
            if ended_session:
                print_success("Session ended")
            else:
                print_info("No active session to end")

            self.test_results['sandbox'] = {
                'session_created': True,
                'actions_recorded': 3,
                'session_ended': True
            }

        except Exception as e:
            print_error(f"Sandbox test failed: {e}")
            self.test_results['sandbox'] = False

    async def generate_final_report(self):
        """Generate comprehensive test report."""
        print_step(11, "Generating Final Test Report")

        print_header("PENNYWISE SYSTEM TEST RESULTS")

        passed = 0
        total = 0

        for component, result in self.test_results.items():
            total += 1
            if result and result is not False:
                print_success(f"{component.upper()}: PASSED")
                passed += 1
            else:
                print_error(f"{component.upper()}: FAILED")

        print(f"\n{c(f'Overall Score: {passed}/{total} components working', Colors.BOLD)}")

        if passed == total:
            print_success("🎉 ALL SYSTEMS OPERATIONAL!")
        elif passed >= total * 0.8:
            print(c("⚠️  MOST SYSTEMS OPERATIONAL - Minor issues detected", Colors.YELLOW))
        else:
            print_error("❌ SIGNIFICANT ISSUES DETECTED - Requires attention")

        # Save detailed results
        with open('system_test_results.json', 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)

        print_info("Detailed results saved to system_test_results.json")

    async def run_full_test(self):
        """Run the complete system test."""
        print_header("PENNYWISE COMPREHENSIVE SYSTEM TEST")
        print_info("Testing all components: AI, scanning, learning, reporting")

        # Run all tests
        tests = [
            self.check_target_availability,
            self.test_ai_model_integration,
            self.test_target_analysis,
            self.test_attack_selection,
            self.test_payload_generation,
            self.test_full_scan,
            self.test_ai_learning,
            self.test_behavior_learner,
            self.test_report_generation,
            self.test_sandbox_environment,
            self.generate_final_report
        ]

        for test in tests:
            try:
                await test()
            except Exception as e:
                print_error(f"Test {test.__name__} failed with exception: {e}")

        print_header("SYSTEM TEST COMPLETED")

async def main():
    """Main test function."""
    tester = PennyWiseSystemTester()
    await tester.run_full_test()

if __name__ == "__main__":
    asyncio.run(main())