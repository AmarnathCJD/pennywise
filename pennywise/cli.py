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

from .core.scanner import VulnerabilityScanner
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
    
    # Initialize components
    ai_model = AIModelInterface(config.ai.model_path)
    sandbox = SandboxEnvironment(storage_path=config.sandbox.storage_path)
    learner = BehaviorLearner(model_path=config.learning.model_path, sandbox=sandbox)
    
    # Set scan mode
    config.scan.scan_mode = ScanMode(args.mode)
    
    scanner = VulnerabilityScanner(
        config=config,
        ai_model=ai_model,
        on_finding=lambda f: logger.finding(f.severity.value, f.title),
        on_progress=lambda m, c, t: logger.step(c, m) if c % 10 == 0 else None
    )
    
    # Parse attack types
    attack_types = None
    if 'all' not in args.attacks:
        attack_types = [AttackType(a) for a in args.attacks]
    
    # Start sandbox session
    sandbox.start_session(target_url=args.url, metadata={'cli': True})
    
    # Run scan
    logger.info(f"Starting scan: {args.url}")
    logger.info(f"Mode: {args.mode}, Attacks: {args.attacks}")
    
    result = await scanner.scan(
        url=args.url,
        attack_types=attack_types,
        crawl=not args.no_crawl
    )
    
    # End sandbox and learn
    sandbox.end_session()
    learner.learn_from_sandbox()
    
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
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Scan completed: {len(result.findings)} findings")
    print(f"Duration: {result.duration_seconds:.1f} seconds")
    print(f"Pages scanned: {result.pages_scanned}")
    print(f"{'='*60}")
    
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
