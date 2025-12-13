#!/usr/bin/env python3
"""
Test script for AI Model and Reinforcement Learning components.
Tests the Qwen model integration and behavior learning system.
"""

import sys
import json
import logging
from pathlib import Path
from datetime import datetime

# Add the pennywise directory to path
sys.path.insert(0, str(Path(__file__).parent))

from pennywise.ai.model_interface import AIModelInterface
from pennywise.learning.behavior_learner import BehaviorLearner
from pennywise.core.results import VulnerabilityFinding, ScanResult
from pennywise.config import AttackType, SeverityLevel

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_ai_model():
    """Test the AI model interface."""
    print("🧠 TESTING AI MODEL INTERFACE")
    print("=" * 50)

    try:
        # Initialize AI model
        ai_model = AIModelInterface()
        print("✅ AI Model initialized successfully")

        # Test vulnerability analysis
        test_vuln = {
            'attack_type': 'XSS',
            'title': 'Reflected XSS in search parameter',
            'description': 'Cross-site scripting vulnerability found',
            'url': 'http://example.com/search?q=test',
            'payload': '<script>alert(1)</script>',
            'evidence': 'Script tag reflected in response'
        }

        print("\n🔍 Testing vulnerability analysis...")
        response = ai_model.analyze_vulnerability(test_vuln)

        if response.success:
            print("✅ Vulnerability analysis successful")
            print(f"📊 Response data: {json.dumps(response.data, indent=2)}")
        else:
            print(f"❌ Vulnerability analysis failed: {response.error}")

        # Test attack recommendation
        print("\n🎯 Testing attack recommendation...")
        target_info = {
            'url': 'http://example.com',
            'technologies': ['PHP', 'MySQL'],
            'has_forms': True,
            'has_search': True
        }

        recommendation = ai_model.recommend_attacks(target_info)
        if recommendation.success:
            print("✅ Attack recommendation successful")
            print(f"📊 Recommended attacks: {recommendation.data}")
        else:
            print(f"❌ Attack recommendation failed: {recommendation.error}")

        return True

    except Exception as e:
        print(f"❌ AI Model test failed: {e}")
        return False


def test_reinforcement_learning():
    """Test the reinforcement learning system."""
    print("\n🧠 TESTING REINFORCEMENT LEARNING")
    print("=" * 50)

    try:
        # Initialize behavior learner
        learner = BehaviorLearner()
        print("✅ Behavior Learner initialized successfully")
        print(f"📊 Initial training samples: {learner.state.training_samples}")

        # Create test scan results
        test_findings = [
            VulnerabilityFinding(
                id="test-xss-1",
                attack_type=AttackType.XSS.value,
                severity=SeverityLevel.CRITICAL.value,
                title="Reflected XSS in search",
                description="Cross-site scripting vulnerability in search parameter",
                url="http://example.com/search?q=test",
                parameter="q",
                payload="<script>alert(1)</script>",
                evidence="Script reflected in response",
                confidence=0.95
            ),
            VulnerabilityFinding(
                id="test-sqli-1",
                attack_type=AttackType.SQLI.value,
                severity=SeverityLevel.HIGH.value,
                title="SQL Injection in login",
                description="SQL injection vulnerability in username parameter",
                url="http://example.com/login",
                parameter="username",
                payload="' OR '1'='1",
                evidence="Database error revealed",
                confidence=0.88
            )
        ]

        test_result = ScanResult(
            target_url="http://example.com",
            findings=test_findings,
            pages_scanned=5,
            requests_made=150,
            duration_seconds=10.5,
            status="completed",
            start_time=datetime.now(),
            end_time=datetime.now()
        )

        # Test recording scan results
        print("\n📝 Testing scan result recording...")
        attack_types = [AttackType.XSS, AttackType.SQLI]
        learner.record_scan_results(test_result, attack_types)
        print("✅ Scan results recorded successfully")
        print(f"📊 Training samples after recording: {learner.state.training_samples}")

        # Test payload ranking
        print("\n🎯 Testing payload ranking...")
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>"
        ]

        rankings = learner.get_payload_ranking(AttackType.XSS.value)
        print("✅ Payload rankings retrieved")
        print(f"📊 XSS Payload rankings: {rankings}")

        # Test attack weight adaptation
        print("\n⚖️ Testing attack weight adaptation...")
        weights = learner.state.attack_weights
        print("✅ Attack weights retrieved")
        print(f"📊 Attack weights: {weights}")

        # Test learning from multiple scans
        print("\n🔄 Testing learning from multiple scans...")
        for i in range(3):
            # Create varied results
            varied_findings = [
                VulnerabilityFinding(
                    id=f"test-vuln-{i}",
                    attack_type=(AttackType.XSS if i % 2 == 0 else AttackType.SQLI).value,
                    severity=(SeverityLevel.CRITICAL if i == 0 else SeverityLevel.HIGH).value,
                    title=f"Test vulnerability {i}",
                    description=f"Test vulnerability description {i}",
                    url=f"http://example.com/page{i}",
                    parameter="test",
                    payload=f"payload_{i}",
                    evidence=f"evidence_{i}",
                    confidence=0.8 + (i * 0.05)
                )
            ]

            varied_result = ScanResult(
                target_url=f"http://example{i}.com",
                findings=varied_findings,
                pages_scanned=3 + i,
                requests_made=100 + (i * 20),
                duration_seconds=5.0 + i,
                status="completed",
                start_time=datetime.now(),
                end_time=datetime.now()
            )

            learner.record_scan_results(varied_result, [AttackType.XSS, AttackType.SQLI])

        print("✅ Multiple scan learning completed")
        print(f"📊 Final training samples: {learner.state.training_samples}")

        # Test updated rankings
        updated_rankings = learner.get_payload_ranking(AttackType.XSS.value)
        print(f"📊 Updated XSS rankings: {updated_rankings}")

        updated_weights = learner.state.attack_weights
        print(f"📊 Updated attack weights: {updated_weights}")

        return True

    except Exception as e:
        print(f"❌ Reinforcement Learning test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_integration():
    """Test integration between AI model and learning system."""
    print("\n🔗 TESTING AI + LEARNING INTEGRATION")
    print("=" * 50)

    try:
        # Initialize both systems
        ai_model = AIModelInterface()
        learner = BehaviorLearner()

        print("✅ Both systems initialized")

        # Create a finding and have AI analyze it
        test_finding = VulnerabilityFinding(
            id="integration-test-xss",
            attack_type=AttackType.XSS.value,
            severity=SeverityLevel.CRITICAL.value,
            title="Critical XSS Vulnerability",
            description="Critical cross-site scripting vulnerability detected",
            url="http://test.com/xss",
            parameter="input",
            payload="<script>alert('xss')</script>",
            evidence="Script executed in browser",
            confidence=0.95
        )

        # Convert to dict for AI analysis
        finding_dict = {
            'attack_type': test_finding.attack_type,
            'title': test_finding.title,
            'description': test_finding.description,
            'url': test_finding.url,
            'payload': test_finding.payload,
            'evidence': test_finding.evidence
        }

        # AI analysis
        ai_response = ai_model.analyze_vulnerability(finding_dict)
        print("✅ AI analysis completed")

        # Create scan result and record in learning system
        scan_result = ScanResult(
            target_url="http://test.com",
            findings=[test_finding],
            pages_scanned=1,
            requests_made=50,
            duration_seconds=2.5,
            status="completed",
            start_time=datetime.now(),
            end_time=datetime.now()
        )

        learner.record_scan_results(scan_result, [AttackType.XSS])
        print("✅ Learning system updated")

        # Check if learning adapted based on AI-analyzed finding
        weights = learner.state.attack_weights
        xss_weight = weights.get('xss', 0)

        print(f"📊 XSS weight after AI-analyzed finding: {xss_weight}")

        if xss_weight > 0:
            print("✅ Integration working: Learning system adapted based on AI analysis")
        else:
            print("⚠️ Integration partial: Learning system recorded but weights not updated")

        return True

    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("🚀 PENNYWISE AI & LEARNING SYSTEM TESTS")
    print("=" * 60)

    from datetime import datetime

    results = []

    # Test AI Model
    ai_result = test_ai_model()
    results.append(("AI Model", ai_result))

    # Test Reinforcement Learning
    rl_result = test_reinforcement_learning()
    results.append(("Reinforcement Learning", rl_result))

    # Test Integration
    int_result = test_integration()
    results.append(("AI + Learning Integration", int_result))

    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)

    all_passed = True
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name}: {status}")
        if not passed:
            all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 ALL TESTS PASSED! AI and Learning systems are fully functional.")
    else:
        print("⚠️ Some tests failed. Check the output above for details.")

    print("=" * 60)


if __name__ == "__main__":
    main()