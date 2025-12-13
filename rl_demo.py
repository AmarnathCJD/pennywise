#!/usr/bin/env python3
"""
Reinforcement Learning Demonstration for PennyWise.
Shows real-time RL learning with attack optimization.
"""

import asyncio
import sys
import json
import time
from datetime import datetime
from typing import Dict, Any, List

# Add parent to path
sys.path.insert(0, '.')

from pennywise.learning.behavior_learner import BehaviorLearner, ReinforcementLearner
from pennywise.core.enhanced_scanner import EnhancedScanner
from pennywise.config import AttackType

# ANSI colors for output
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

def rl_log_callback(event: Dict[str, Any]):
    """Real-time reinforcement learning event logger."""
    event_type = event['event_type']
    timestamp = event['timestamp'].split('T')[1][:8]  # HH:MM:SS
    data = event['data']

    if event_type == "initialized":
        print(colorize(f"🧠 [{timestamp}] RL System Initialized", Colors.BLUE))
        print(colorize(f"   ├── Learning Rate: {data['alpha']}", Colors.CYAN))
        print(colorize(f"   ├── Discount Factor: {data['gamma']}", Colors.CYAN))
        print(colorize(f"   └── Exploration Rate: {data['epsilon']}", Colors.CYAN))

    elif event_type == "episode_start":
        print(colorize(f"🎯 [{timestamp}] Episode {data['episode']} Started", Colors.GREEN))
        print(colorize(f"   ├── State: {data['initial_state']}", Colors.CYAN))
        features = data['target_features']
        print(colorize(f"   └── Target: {features.get('url', 'unknown')}", Colors.CYAN))

    elif event_type == "exploration":
        print(colorize(f"🔍 [{timestamp}] Exploration Phase", Colors.YELLOW))
        print(colorize(f"   ├── State: {data['state']}", Colors.CYAN))
        print(colorize(f"   ├── Action: {data['chosen_action']}", Colors.GREEN))
        print(colorize(f"   └── Available: {', '.join(data['available_actions'])}", Colors.CYAN))

    elif event_type == "exploitation":
        print(colorize(f"🎯 [{timestamp}] Exploitation Phase", Colors.GREEN))
        print(colorize(f"   ├── State: {data['state']}", Colors.CYAN))
        print(colorize(f"   ├── Action: {data['chosen_action']}", Colors.GREEN))
        q_vals = data['q_values']
        best_q = max(q_vals.values())
        print(colorize(f"   └── Best Q-Value: {best_q:.3f}", Colors.MAGENTA))

    elif event_type == "reward_calculation":
        reward = data['total_reward']
        color = Colors.GREEN if reward > 0 else Colors.RED
        print(colorize(f"💰 [{timestamp}] Reward Calculated: {reward:.3f}", color))
        print(colorize(f"   ├── Findings: {data['findings']}", Colors.CYAN))
        print(colorize(f"   ├── Severity Bonus: +{data['severity_bonus']}", Colors.GREEN))
        print(colorize(f"   ├── Duration Penalty: -{data['duration_penalty']}", Colors.RED))
        print(colorize(f"   └── Request Penalty: -{data['request_penalty']}", Colors.RED))

    elif event_type == "q_update":
        old_q = data['old_q']
        new_q = data['new_q']
        change = new_q - old_q
        color = Colors.GREEN if change > 0 else Colors.RED
        symbol = "↗" if change > 0 else "↘"
        print(colorize(f"📈 [{timestamp}] Q-Value Updated {symbol} {change:+.3f}", color))
        print(colorize(f"   ├── State: {data['state']}, Action: {data['action']}", Colors.CYAN))
        print(colorize(f"   ├── Old Q: {old_q:.3f} → New Q: {new_q:.3f}", Colors.CYAN))
        print(colorize(f"   └── Reward: {data['reward']}", Colors.MAGENTA))

    elif event_type == "episode_end":
        success = data['success']
        reward = data['final_reward']
        color = Colors.GREEN if success else Colors.YELLOW
        status = "SUCCESS" if success else "COMPLETED"
        print(colorize(f"🏁 [{timestamp}] Episode {data['episode']} {status}", color))
        print(colorize(f"   ├── Final Reward: {reward:.3f}", Colors.MAGENTA))
        print(colorize(f"   ├── Success Rate: {data['success_rate']:.1%}", Colors.CYAN))
        print(colorize(f"   └── Avg Reward (last 10): {data['avg_reward']:.3f}", Colors.CYAN))

def simulate_scan_results(target_type: str, episode: int) -> Dict[str, Any]:
    """Simulate scan results for different target types."""
    base_findings = {
        'forms_api': [
            {'attack_type': 'xss', 'severity': 'High'},
            {'attack_type': 'csrf', 'severity': 'Medium'},
        ],
        'params_mysql': [
            {'attack_type': 'sqli', 'severity': 'Critical'},
            {'attack_type': 'xss', 'severity': 'Medium'},
        ],
        'unknown': [
            {'attack_type': 'xss', 'severity': 'Low'},
        ]
    }

    findings = base_findings.get(target_type, base_findings['unknown'])

    # Add some randomness
    if episode > 3:  # Learning improves over time
        findings.append({'attack_type': 'sqli', 'severity': 'High'})

    return {
        'findings': findings,
        'duration': 45 + (episode * 2),  # Scans get faster with learning
        'requests_made': 200 + (episode * 10),
        'pages_scanned': 5 + episode
    }

async def demonstrate_reinforcement_learning():
    """Demonstrate reinforcement learning in action."""
    print(colorize("🤖 PennyWise Reinforcement Learning Demonstration", Colors.BOLD + Colors.BLUE))
    print(colorize("=" * 60, Colors.BLUE))
    print()

    # Initialize RL system
    rl_learner = ReinforcementLearner(alpha=0.2, gamma=0.9, epsilon=0.3)
    rl_learner.set_log_callback(rl_log_callback)

    # Different target types to learn from
    target_scenarios = [
        {'url': 'http://forms-app.com', 'has_forms': True, 'is_api': True, 'technologies': ['node']},
        {'url': 'http://mysql-site.com', 'has_params': True, 'technologies': ['php', 'mysql']},
        {'url': 'http://unknown-target.com', 'has_forms': False, 'has_params': False},
        {'url': 'http://complex-app.com', 'has_forms': True, 'has_params': True, 'uses_https': True},
    ]

    print(colorize("🎯 Starting Learning Episodes...", Colors.GREEN))
    print()

    # Run learning episodes
    for episode in range(1, 8):
        # Select target scenario
        scenario_idx = (episode - 1) % len(target_scenarios)
        target_features = target_scenarios[scenario_idx]

        # Start learning episode
        state = rl_learner.start_learning_episode(target_features)

        # Simulate scan (in real scenario, this would be actual scanning)
        print(colorize(f"🔎 Simulating scan of {target_features['url']}...", Colors.CYAN))
        time.sleep(0.5)  # Brief pause for demonstration

        # Get scan results
        state_key = rl_learner.get_state_key(target_features)
        scan_results = simulate_scan_results(state_key, episode)

        # Learn from results
        next_state = state  # For simplicity, same state
        rl_learner.learn(state, "scan", rl_learner.calculate_reward(scan_results), next_state, done=True)
        rl_learner.end_learning_episode(rl_learner.calculate_reward(scan_results), len(scan_results['findings']) > 0)

        print()

    # Show final learning results
    print(colorize("📊 Final Learning Results", Colors.BOLD + Colors.MAGENTA))
    print(colorize("=" * 40, Colors.MAGENTA))

    stats = rl_learner.get_learning_stats()
    print(colorize(f"Total Episodes: {stats['total_episodes']}", Colors.CYAN))
    print(colorize(f"Success Rate: {stats['success_rate']:.1%}", Colors.GREEN))
    print(colorize(f"Average Reward: {stats['avg_reward']:.3f}", Colors.MAGENTA))
    print(colorize(f"States Learned: {stats['total_states']}", Colors.CYAN))
    print()

    # Show Q-table for key states
    print(colorize("🧠 Learned Q-Values (Top States)", Colors.BOLD + Colors.BLUE))
    print(colorize("-" * 40, Colors.BLUE))

    for state in list(rl_learner.q_table.keys())[:3]:
        print(colorize(f"State: {state}", Colors.CYAN))
        q_values = rl_learner.q_table[state]
        for action, q_val in sorted(q_values.items(), key=lambda x: x[1], reverse=True):
            print(colorize(f"  {action}: {q_val:.3f}", Colors.GREEN))
        print()

    # Show recommendations
    print(colorize("🎯 RL Recommendations for New Targets", Colors.BOLD + Colors.GREEN))
    print(colorize("-" * 40, Colors.GREEN))

    for scenario in target_scenarios[:2]:
        state = rl_learner.get_state_key(scenario)
        recommendations = rl_learner.get_recommendations(state, top_k=2)
        if recommendations:
            print(colorize(f"Target: {scenario['url']}", Colors.CYAN))
            for action, q_val in recommendations:
                print(colorize(f"  → {action.upper()}: {q_val:.3f} confidence", Colors.GREEN))
            print()

    print(colorize("✅ Reinforcement Learning Demonstration Complete!", Colors.BOLD + Colors.GREEN))
    print(colorize("The system now adapts attack strategies based on learned patterns.", Colors.CYAN))

async def demonstrate_integrated_learning():
    """Demonstrate integrated learning with behavior patterns."""
    print(colorize("\n🧠 Integrated Learning System Demonstration", Colors.BOLD + Colors.BLUE))
    print(colorize("=" * 50, Colors.BLUE))

    # Initialize behavior learner with RL
    learner = BehaviorLearner()

    # Set up real-time logging
    def integrated_log_callback(event):
        rl_log_callback(event)

    learner.set_realtime_logging(integrated_log_callback)

    # Simulate learning from multiple scan sessions
    print(colorize("🔄 Learning from Simulated Scan Sessions...", Colors.CYAN))
    print()

    sessions = [
        {
            'target_features': {'has_forms': True, 'is_api': True, 'technologies': ['node']},
            'scan_results': {'findings': [{'attack_type': 'xss', 'severity': 'High'}], 'duration': 30, 'requests_made': 150}
        },
        {
            'target_features': {'has_params': True, 'technologies': ['php', 'mysql']},
            'scan_results': {'findings': [{'attack_type': 'sqli', 'severity': 'Critical'}], 'duration': 45, 'requests_made': 200}
        },
        {
            'target_features': {'has_forms': True, 'has_params': True, 'uses_https': True},
            'scan_results': {'findings': [{'attack_type': 'csrf', 'severity': 'Medium'}, {'attack_type': 'xss', 'severity': 'High'}], 'duration': 35, 'requests_made': 180}
        }
    ]

    for i, session in enumerate(sessions, 1):
        print(colorize(f"Session {i}: Learning from scan results...", Colors.YELLOW))

        # Start learning session
        state = learner.start_learning_session(session['target_features'])

        # Learn from results
        learner.learn_from_scan_results(state, session['scan_results'])

        print()

    # Show integrated learning dashboard
    dashboard = learner.get_learning_dashboard()

    print(colorize("📈 Integrated Learning Dashboard", Colors.BOLD + Colors.MAGENTA))
    print(colorize("=" * 40, Colors.MAGENTA))

    rl = dashboard['reinforcement_learning']
    patterns = dashboard['behavior_patterns']

    print(colorize(f"RL Episodes: {rl['total_episodes']}", Colors.CYAN))
    print(colorize(f"Pattern Learning: {patterns['training_samples']} samples", Colors.CYAN))
    print(colorize(f"Attack Preferences: {patterns['attack_weights']}", Colors.GREEN))

    print()
    print(colorize("🎯 System now combines RL optimization with pattern recognition!", Colors.BOLD + Colors.GREEN))

if __name__ == "__main__":
    print("Starting PennyWise Reinforcement Learning Demonstration...")
    print()

    # Run RL demonstration
    asyncio.run(demonstrate_reinforcement_learning())

    # Run integrated learning demonstration
    asyncio.run(demonstrate_integrated_learning())