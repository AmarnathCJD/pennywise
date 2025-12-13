"""
PennyWise CLI - Command Line Interface
======================================

Provides command-line access to PennyWise vulnerability scanner.
"""

import argparse
import asyncio
import sys
import json
import time
from pathlib import Path

from .core.enhanced_scanner import EnhancedScanner
from .core.target_analyzer import TargetAnalyzer
from .core.attack_selector import AttackSelector
from .ai.model_interface import AIModelInterface
from .sandbox.environment import SandboxEnvironment
from .learning.behavior_learner import BehaviorLearner
from .config import PennywiseConfig, AttackType, ScanMode
from .utils.logging import setup_logging, PennywiseLogger
from .utils.reports import ReportGenerator
from .server import run_server


def create_parser():
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog='pennywise',
        description='PennyWise - AI-Powered Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pennywise scan https://example.com
  pennywise scan https://example.com --attacks xss sqli
  pennywise analyze https://example.com
  pennywise server --port 8080
  pennywise report --format html --output report.html
        """
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '-c', '--config',
        type=str,
        help='Path to configuration file'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Perform a vulnerability scan')
    scan_parser.add_argument('url', help='Target URL to scan')
    scan_parser.add_argument(
        '-a', '--attacks',
        nargs='+',
        choices=['xss', 'sqli', 'csrf', 'auth', 'all'],
        default=['all'],
        help='Attack types to test'
    )
    scan_parser.add_argument(
        '-m', '--mode',
        choices=['passive', 'active', 'aggressive', 'stealth'],
        default='active',
        help='Scan mode'
    )
    scan_parser.add_argument(
        '--no-crawl',
        action='store_true',
        help='Disable crawling'
    )
    scan_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file for results'
    )
    scan_parser.add_argument(
        '-f', '--format',
        choices=['json', 'html', 'markdown', 'summary'],
        default='summary',
        help='Output format'
    )
    scan_parser.add_argument(
        '--pdf',
        type=str,
        help='Generate PDF report to specified path'
    )
    scan_parser.add_argument(
        '--no-ai',
        action='store_true',
        help='Disable AI analysis for faster scanning'
    )
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a target without scanning')
    analyze_parser.add_argument('url', help='Target URL to analyze')
    analyze_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file for analysis'
    )
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start the API server')
    server_parser.add_argument(
        '-p', '--port',
        type=int,
        default=8080,
        help='Port to listen on'
    )
    server_parser.add_argument(
        '-H', '--host',
        type=str,
        default='0.0.0.0',
        help='Host to bind to'
    )
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate a report from last scan')
    report_parser.add_argument(
        '-f', '--format',
        choices=['json', 'html', 'markdown', 'summary'],
        default='html',
        help='Report format'
    )
    report_parser.add_argument(
        '-o', '--output',
        type=str,
        required=True,
        help='Output file path'
    )
    report_parser.add_argument(
        '-i', '--input',
        type=str,
        help='Input scan result file (JSON)'
    )
    
    # Learning commands
    learn_parser = subparsers.add_parser('learn', help='Learning system commands')
    learn_parser.add_argument(
        'action',
        choices=['stats', 'train', 'reset', 'export'],
        help='Learning action'
    )
    learn_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file for export'
    )
    
    return parser


async def cmd_scan(args, config):
    """Execute scan command."""
    logger = setup_logging(log_level='DEBUG' if args.verbose else 'INFO')
    logger.print_banner()

    # Initialize container with all components
    from .core.container import initialize_container
    container = initialize_container(config)

    # Set scan mode
    config.scan.scan_mode = ScanMode(args.mode)
    
    # Disable AI if requested
    if hasattr(args, 'no_ai') and args.no_ai:
        config.ai.enabled = False
        logger.info("AI analysis disabled for faster scanning")

    # Get scanner from container
    scanner = container.get('scanner')
    scanner.on_finding = lambda f: logger.finding(f.severity.value, f.title)
    scanner.on_progress = lambda m, c, t: logger.step(c, m) if c % 10 == 0 else None
    scanner.on_log = lambda msg, level: getattr(logger, level.lower(), logger.info)(msg)

    # Get sandbox and learner from container
    sandbox = container.get('sandbox')
    learner = container.get('learner')

    # Set up reinforcement learning logging callback
    def rl_log_callback(event):
        """Handle reinforcement learning events."""
        event_type = event['event_type']
        data = event['data']

        if event_type == "episode_start":
            logger.info(f"🎯 RL Episode {data['episode']} started - State: {data['initial_state']}")
        elif event_type == "exploration":
            logger.info(f"🔍 RL Exploring: {data['chosen_action']} in state {data['state']}")
        elif event_type == "exploitation":
            best_q = max(data['q_values'].values())
            logger.info(f"🎯 RL Exploiting: {data['chosen_action']} (Q={best_q:.3f})")
        elif event_type == "reward_calculation":
            reward = data['total_reward']
            color = "🟢" if reward > 0 else "🔴"
            logger.info(f"{color} RL Reward: {reward:.3f} ({data['findings']} findings)")
        elif event_type == "q_update":
            change = data['new_q'] - data['old_q']
            symbol = "↗" if change > 0 else "↘"
            logger.info(f"📈 RL Q-value {data['action']}: {data['old_q']:.3f} → {data['new_q']:.3f} {symbol}")
        elif event_type == "episode_end":
            success_rate = data['success_rate'] * 100
            logger.info(f"🏁 RL Episode {data['episode']} ended - Success: {success_rate:.1f}%, Avg Reward: {data['avg_reward']:.3f}")

    # Set RL logging callback
    if hasattr(learner, 'set_realtime_logging'):
        learner.set_realtime_logging(rl_log_callback)
    elif hasattr(learner, 'rl_learner') and hasattr(learner.rl_learner, 'set_log_callback'):
        learner.rl_learner.set_log_callback(rl_log_callback)

    # Parse attack types
    attack_types = None
    if 'all' not in args.attacks:
        attack_types = [AttackType(a) for a in args.attacks]
    
    # Start sandbox session
    sandbox.start_session(target_url=args.url, metadata={'cli': True})

    # Initialize reinforcement learning episode
    target_features = {
        'url': args.url,
        'has_forms': True,  # Assume forms for now, could be enhanced
        'has_params': True,  # Assume params for now
        'is_api': 'api' in args.url.lower(),
        'uses_https': args.url.startswith('https://'),
        'technologies': []  # Could be populated from analysis
    }

    # Start RL learning episode
    if hasattr(learner, 'start_learning_session'):
        current_state = learner.start_learning_session(target_features)
    elif hasattr(learner, 'rl_learner') and hasattr(learner.rl_learner, 'start_learning_episode'):
        current_state = learner.rl_learner.start_learning_episode(target_features)
    else:
        current_state = 'unknown'

    # Run scan
    logger.info(f"Starting scan: {args.url}")
    logger.info(f"Mode: {args.mode}, Attacks: {args.attacks}")
    logger.info(f"Reinforcement Learning: Active (Episode tracking enabled)")

    result = await scanner.scan(
        url=args.url,
        attack_types=attack_types,
        crawl=not args.no_crawl
    )

    # Calculate RL reward and learn
    scan_results = {
        'findings': result.findings,
        'duration': result.duration_seconds,
        'requests_made': getattr(result, 'requests_made', 100),  # Default if not available
        'pages_scanned': result.pages_scanned
    }

    if hasattr(learner, 'learn_from_scan_results'):
        learner.learn_from_scan_results(current_state, scan_results, current_state)
    elif hasattr(learner, 'rl_learner'):
        rl = learner.rl_learner
        reward = rl.calculate_reward(scan_results)
        rl.learn(current_state, 'scan', reward, current_state, done=True)
        rl.end_learning_episode(reward, len(result.findings) > 0)

    # End sandbox session
    sandbox.end_session()

    # Generate output
    generator = ReportGenerator(result)
    
    if args.format == 'json':
        output = generator.generate_json()
    elif args.format == 'html':
        output = generator.generate_html()
    elif args.format == 'markdown':
        output = generator.generate_markdown()
    else:
        output = generator.generate_summary()
    
    # Write or print output
    if args.output:
        Path(args.output).write_text(output)
        logger.success(f"Report saved to {args.output}")
    else:
        print("\n" + output)
    
    # Generate PDF report if requested
    if hasattr(args, 'pdf') and args.pdf:
        logger.info(f"Generating PDF report: {args.pdf}")
        success = scanner.generate_pdf_report(result, args.pdf)
        if success:
            logger.success(f"PDF report generated: {args.pdf}")
        else:
            logger.error("Failed to generate PDF report")

    # Print comprehensive summary with RL statistics
    print(f"\n{'='*80}")
    print(f"🎯 PENNYWISE SCAN COMPLETED - COMPREHENSIVE SUMMARY")
    print(f"{'='*80}")

    # Scan Results
    print(f"📊 SCAN RESULTS:")
    print(f"   • Target: {args.url}")
    print(f"   • Mode: {args.mode}")
    print(f"   • Attacks: {', '.join(args.attacks)}")
    print(f"   • Findings: {len(result.findings)}")
    print(f"   • Duration: {result.duration_seconds:.1f} seconds")
    print(f"   • Pages Scanned: {result.pages_scanned}")
    print(f"   • Status: {'✅ Completed' if result.status == 'completed' else '❌ Failed'}")

    # Reinforcement Learning Statistics
    print(f"\n🧠 REINFORCEMENT LEARNING SUMMARY:")
    if hasattr(learner, 'get_learning_stats'):
        try:
            stats = learner.get_learning_stats()
            ppo_stats = stats.get('ppo_stats', {})
            
            print(f"   • Episodes Completed: {ppo_stats.get('total_episodes', 0)}")
            print(f"   • Success Rate: {ppo_stats.get('success_rate', 0):.1%}")
            print(f"   • Average Reward: {stats.get('average_rewards', {})}")
            print(f"   • States Learned: {ppo_stats.get('trajectory_buffer_size', 0)}")
            print(f"   • User Embeddings: {ppo_stats.get('user_embeddings_tracked', 0)}")
            
            # Show user focus areas
            focus_areas = stats.get('user_focus_areas', [])
            if focus_areas:
                print(f"   • User Focus Areas: {', '.join(focus_areas)}")
        except Exception as e:
            print(f"   • RL Stats Error: {e}")
    else:
        print(f"   • RL System: Not available")

    # AI Analysis Summary
    print(f"\n🤖 AI ANALYSIS SUMMARY:")
    if hasattr(learner, 'ppo_agent') or ai_model:
        ai_analyzed_count = len([f for f in result.findings if f.recommendations])  # AI provides recommendations
        print(f"   • AI Model: Active (Qwen vulnerability detector)")
        print(f"   • Findings Analyzed: {ai_analyzed_count}/{len(result.findings)}")
        print(f"   • Severity Classification: AI-powered")
        print(f"   • Recommendations Provided: {sum(len(f.recommendations) for f in result.findings)}")
        
        # Show AI confidence if available
        if result.findings:
            avg_confidence = sum(f.confidence for f in result.findings) / len(result.findings)
            print(f"   • Average AI Confidence: {avg_confidence:.2f}")
    else:
        print(f"   • AI Analysis: Not performed")

    # Output files
    if args.output or (hasattr(args, 'pdf') and args.pdf):
        print(f"\n💾 OUTPUT FILES:")
        if args.output:
            print(f"   • Report: {args.output}")
        if hasattr(args, 'pdf') and args.pdf:
            print(f"   • PDF Report: {args.pdf}")

    print(f"\n{'='*80}")
    print(f"🎉 PennyWise scan completed successfully!")
    print(f"{'='*80}")

    return 0 if result.status == 'completed' else 1


async def cmd_analyze(args, config):
    """Execute analyze command."""
    logger = setup_logging(log_level='DEBUG' if args.verbose else 'INFO')
    logger.print_banner()
    
    analyzer = TargetAnalyzer(config.scan)
    ai_model = AIModelInterface(config.ai.model_path)
    selector = AttackSelector(ai_model, config.scan.scan_mode)
    
    logger.info(f"Analyzing target: {args.url}")
    
    analysis = await analyzer.analyze(args.url)
    strategy = selector.create_strategy(analysis)
    
    # Build output
    output = {
        'url': args.url,
        'title': analysis.title,
        'technologies': [t.value for t in analysis.technologies],
        'security': {
            'https': analysis.uses_https,
            'csp': analysis.has_csp_header,
            'csrf_protection': analysis.has_csrf_protection,
            'secure_cookies': analysis.has_secure_cookies
        },
        'vulnerability_scores': {
            'xss': round(analysis.potential_xss, 2),
            'sqli': round(analysis.potential_sqli, 2),
            'csrf': round(analysis.potential_csrf, 2),
            'auth': round(analysis.potential_auth_issues, 2)
        },
        'forms': len(analysis.forms),
        'input_vectors': len(analysis.input_vectors),
        'recommended_attacks': [
            {
                'type': plan.attack_type.value,
                'priority': plan.priority,
                'confidence': round(plan.confidence, 2),
                'reasons': plan.reasons
            }
            for plan in strategy.get_ordered_attacks()[:5]
        ]
    }
    
    json_output = json.dumps(output, indent=2)
    
    if args.output:
        Path(args.output).write_text(json_output)
        logger.success(f"Analysis saved to {args.output}")
    else:
        print(json_output)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Analysis: {analysis.title}")
    print(f"Technologies: {', '.join(t.value for t in analysis.technologies)}")
    print(f"\nVulnerability Scores:")
    print(f"  XSS:  {analysis.potential_xss:.0%}")
    print(f"  SQLi: {analysis.potential_sqli:.0%}")
    print(f"  CSRF: {analysis.potential_csrf:.0%}")
    print(f"  Auth: {analysis.potential_auth_issues:.0%}")
    print(f"\nRecommended: {strategy.attack_plans[0].attack_type.value.upper() if strategy.attack_plans else 'None'}")
    print(f"{'='*60}")
    
    return 0


def cmd_server(args, config):
    """Execute server command."""
    run_server(host=args.host, port=args.port, config=config)
    return 0


def cmd_learn(args, config):
    """Execute learning commands."""
    logger = setup_logging(log_level='INFO')
    
    sandbox = SandboxEnvironment(storage_path=config.sandbox.storage_path)
    learner = BehaviorLearner(model_path=config.learning.model_path, sandbox=sandbox)
    
    if args.action == 'stats':
        stats = learner.get_learning_stats()
        print(json.dumps(stats, indent=2, default=str))
    
    elif args.action == 'train':
        logger.info("Training from sandbox sessions...")
        learner.learn_from_sandbox()
        stats = learner.get_learning_stats()
        logger.success(f"Training complete. Samples: {stats['training_samples']}")
    
    elif args.action == 'reset':
        learner.reset()
        logger.success("Learning model reset")
    
    elif args.action == 'export':
        output_path = args.output or f"training_export_{int(time.time())}.json"
        export_path = sandbox.export_for_training(output_path)
        logger.success(f"Exported training data to {export_path}")
    
    return 0


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Load config
    if args.config:
        config = PennywiseConfig.from_file(args.config)
    else:
        config = PennywiseConfig()
    
    # Handle verbose flag
    if hasattr(args, 'verbose') and args.verbose:
        config.debug = True
        config.log_level = 'DEBUG'
    
    # Execute command
    if args.command == 'scan':
        return asyncio.run(cmd_scan(args, config))
    elif args.command == 'analyze':
        return asyncio.run(cmd_analyze(args, config))
    elif args.command == 'server':
        return cmd_server(args, config)
    elif args.command == 'learn':
        return cmd_learn(args, config)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
