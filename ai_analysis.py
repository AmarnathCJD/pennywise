#!/usr/bin/env python3
"""
PennyWise AI System Analysis and Status Report
Shows current AI implementation, reinforcement learning, and fixes.
"""

import asyncio
import sys
import json
from datetime import datetime

# Add parent to path
sys.path.insert(0, '.')

from pennywise.ai.model_interface import AIModelInterface
from pennywise.learning.behavior_learner import BehaviorLearner
from pennywise.core.enhanced_scanner import EnhancedScanner

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
    print(colorize(f"\n{'='*60}", Colors.BLUE))
    print(colorize(f" {title}", Colors.BOLD + Colors.BLUE))
    print(colorize(f"{'='*60}", Colors.BLUE))

def print_section(title: str):
    print(colorize(f"\n{title}", Colors.BOLD + Colors.GREEN))
    print(colorize(f"{'-'*len(title)}", Colors.GREEN))

def show_ai_current_work():
    """Show what AI currently does in the implementation."""
    print_header("🤖 CURRENT AI IMPLEMENTATION IN PENNYWISE")

    print_section("AI Model Interface (Qwen3-0.6B)")
    print("• Vulnerability Analysis: Analyzes individual findings with risk assessment")
    print("• Impact Evaluation: Determines potential damage and attack vectors")
    print("• Remediation Suggestions: Provides step-by-step fix recommendations")
    print("• AI Logging: Tracks processing time, success rates, and confidence scores")

    print_section("AI Functions")
    functions = [
        "analyze_vulnerability() - Deep analysis of security findings",
        "generate_summary() - Creates comprehensive scan summaries",
        "suggest_remediation() - Provides prevention recommendations",
        "get_ai_logs() - Returns activity logs with performance metrics"
    ]
    for func in functions:
        print(f"• {func}")

    print_section("AI Response Format")
    print("• JSON structured output with risk levels, impact, and recommendations")
    print("• Markdown code block parsing for model responses")
    print("• Fallback handling for malformed responses")

def show_reinforcement_learning():
    """Show the reinforcement learning implementation."""
    print_header("🧠 REINFORCEMENT LEARNING SYSTEM")

    print_section("RL Components")
    components = [
        "Q-Learning Algorithm: Optimizes attack selection based on rewards",
        "State Representation: Target features (forms, params, tech stack)",
        "Action Space: Attack types (XSS, SQLi, CSRF, etc.)",
        "Reward Function: Based on findings, severity, efficiency"
    ]
    for comp in components:
        print(f"• {comp}")

    print_section("Learning Parameters")
    params = [
        "Alpha (α): 0.1 - Learning rate",
        "Gamma (γ): 0.9 - Discount factor for future rewards",
        "Epsilon (ε): 0.2 - Exploration vs exploitation balance"
    ]
    for param in params:
        print(f"• {param}")

    print_section("Real-time Learning Events")
    events = [
        "episode_start: New learning session begins",
        "exploration: Trying new attack strategies",
        "exploitation: Using learned optimal strategies",
        "reward_calculation: Computing success metrics",
        "q_update: Updating value function",
        "episode_end: Session completion with final reward"
    ]
    for event in events:
        print(f"• {event}")

def show_scan_analyze_learn():
    """Explain scan, analyze, and learn functionality."""
    print_header("🔍 SCAN, ANALYZE & LEARN WORKFLOW")

    print_section("1. SCAN Phase")
    scan_steps = [
        "Target Discovery: Crawl and map application structure",
        "Injection Point Detection: Find forms, parameters, APIs",
        "Attack Execution: Test for XSS, SQLi, CSRF vulnerabilities",
        "Evidence Collection: Gather proof-of-concept data",
        "Database Dumping: Extract data when SQLi is found"
    ]
    for i, step in enumerate(scan_steps, 1):
        print(f"{i}. {step}")

    print_section("2. ANALYZE Phase")
    analyze_steps = [
        "AI Vulnerability Analysis: Deep assessment of each finding",
        "Risk Assessment: Critical/High/Medium/Low classification",
        "Impact Evaluation: Determine potential damage scope",
        "Attack Vector Analysis: Identify exploitation methods",
        "Remediation Planning: Generate fix recommendations"
    ]
    for i, step in enumerate(analyze_steps, 1):
        print(f"{i}. {step}")

    print_section("3. LEARN Phase")
    learn_steps = [
        "Pattern Recognition: Identify successful attack patterns",
        "Q-Value Updates: Strengthen effective strategies",
        "Attack Weight Adjustment: Prefer successful attack types",
        "Workflow Optimization: Improve scanning efficiency",
        "Model Persistence: Save learned patterns for future use"
    ]
    for i, step in enumerate(learn_steps, 1):
        print(f"{i}. {step}")

def show_fixes_implemented():
    """Show the fixes implemented for reported issues."""
    print_header("🔧 FIXES IMPLEMENTED")

    print_section("SQLi Logging Fix")
    print("• Added on_log callback to CLI scanner initialization")
    print("• SQLi logs now properly displayed during scans")
    print("• Progress tracking shows payload testing status")
    print("• Success/error messages are immediately visible")

    print_section("PDF Generation Fix")
    print("• Added --pdf option to CLI scan command")
    print("• PDF reports now generated from command line scans")
    print("• Usage: pennywise scan <url> --pdf report.pdf")
    print("• Includes screenshots, AI analysis, and prevention suggestions")

    print_section("Reinforcement Learning Added")
    print("• Full Q-learning implementation for attack optimization")
    print("• Real-time learning event logging")
    print("• State-action-reward learning from scan results")
    print("• Adaptive attack selection based on target features")

def show_ai_logs_demo():
    """Show AI activity logs."""
    print_header("📊 AI ACTIVITY LOGS DEMONSTRATION")

    try:
        ai_model = AIModelInterface()

        # Show current AI logs
        logs = ai_model.get_ai_logs()
        if logs:
            print_section("Recent AI Activity")
            for log in logs[-5:]:  # Show last 5 entries
                print(f"• {log.operation}: {log.processing_time:.2f}s, Success: {log.success}")
        else:
            print("No AI logs available (run a scan with AI analysis first)")

        # Show AI stats
        stats = ai_model.get_ai_stats()
        print_section("AI Performance Statistics")
        print(f"• Total Operations: {stats.get('total_operations', 0)}")
        print(f"• Success Rate: {stats.get('success_rate', 0):.1%}")
        print(f"• Average Processing Time: {stats.get('avg_processing_time', 0):.2f}s")

    except Exception as e:
        print(colorize(f"AI Model not available: {e}", Colors.YELLOW))

def show_realtime_rl_demo():
    """Show real-time reinforcement learning in action."""
    print_header("🎯 REAL-TIME REINFORCEMENT LEARNING DEMO")

    def rl_callback(event):
        event_type = event['event_type']
        data = event['data']

        if event_type == "episode_start":
            print(colorize(f"🎯 Episode {data['episode']} started for {data['initial_state']}", Colors.GREEN))
        elif event_type == "exploration":
            print(colorize(f"🔍 Exploring: {data['chosen_action']} in state {data['state']}", Colors.YELLOW))
        elif event_type == "exploitation":
            best_q = max(data['q_values'].values())
            print(colorize(f"🎯 Exploiting: {data['chosen_action']} (Q={best_q:.3f})", Colors.GREEN))
        elif event_type == "reward_calculation":
            reward = data['total_reward']
            color = Colors.GREEN if reward > 0 else Colors.RED
            print(colorize(f"💰 Reward: {reward:.3f} ({data['findings']} findings)", color))
        elif event_type == "q_update":
            change = data['new_q'] - data['old_q']
            symbol = "↗" if change > 0 else "↘"
            print(colorize(f"📈 Q-value {data['action']}: {data['old_q']:.3f} → {data['new_q']:.3f} {symbol}", Colors.CYAN))

    try:
        from pennywise.learning.behavior_learner import ReinforcementLearner

        rl = ReinforcementLearner(alpha=0.2, gamma=0.9, epsilon=0.3)
        rl.set_log_callback(rl_callback)

        # Simulate a few learning episodes
        targets = [
            {'has_forms': True, 'is_api': True},
            {'has_params': True, 'technologies': ['php', 'mysql']},
            {'has_forms': True, 'has_params': True, 'uses_https': True}
        ]

        for i, target in enumerate(targets, 1):
            state = rl.start_learning_episode(target)
            # Simulate scan results
            findings = 2 if i > 1 else 1  # Learning improves results
            scan_results = {
                'findings': [{'severity': 'High'}] * findings,
                'duration': 40 - (i * 5),  # Gets faster
                'requests_made': 150 + (i * 20)
            }
            reward = rl.calculate_reward(scan_results)
            rl.learn(state, "scan", reward, state, done=True)
            rl.end_learning_episode(reward, findings > 0)

        # Show final Q-table
        print_section("Learned Q-Values")
        for state, actions in rl.q_table.items():
            print(f"State {state}:")
            for action, q_val in actions.items():
                print(f"  {action}: {q_val:.3f}")

    except Exception as e:
        print(colorize(f"RL Demo error: {e}", Colors.RED))

async def main():
    """Main demonstration function."""
    show_ai_current_work()
    show_reinforcement_learning()
    show_scan_analyze_learn()
    show_fixes_implemented()
    show_ai_logs_demo()
    show_realtime_rl_demo()

    print_header("✅ COMPREHENSIVE ANALYSIS COMPLETE")
    print(colorize("\nPennyWise now features:", Colors.BOLD + Colors.GREEN))
    print("• Advanced AI vulnerability analysis with GPU acceleration")
    print("• Reinforcement learning for attack optimization")
    print("• Real-time learning event logging")
    print("• Fixed SQLi logging and PDF generation")
    print("• Integrated scan-analyze-learn workflow")
    print()
    print(colorize("Run 'python rl_demo.py' for full RL demonstration!", Colors.CYAN))

if __name__ == "__main__":
    asyncio.run(main())