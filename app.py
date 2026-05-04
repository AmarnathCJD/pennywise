#!/usr/bin/env python3
"""
PennyWise - AI-Powered Vulnerability Scanner

Usage:
    python app.py              # Start web server on :8080
    python app.py --port 9090  # Custom port
    python app.py --rb         # Rule-based only (no AI model)
    python app.py server       # Explicit server command (same as above)
    python app.py scan https://example.com
    python app.py analyze https://example.com
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pennywise.cli import main, create_parser
from pennywise.config import PennywiseConfig
from pennywise.server import run_server

if __name__ == '__main__':
    # If no subcommand given (or only flags like --rb/--port), default to server
    args = sys.argv[1:]
    known_cmds = {'scan', 'analyze', 'server', 'learn', 'report'}
    has_cmd = any(a in known_cmds for a in args)

    if not has_cmd:
        # Parse simple server flags directly
        import argparse
        p = argparse.ArgumentParser(add_help=False)
        p.add_argument('--port', '-p', type=int, default=8080)
        p.add_argument('--host', '-H', type=str, default='0.0.0.0')
        p.add_argument('--rb', action='store_true')
        parsed, _ = p.parse_known_args(args)
        config = PennywiseConfig()
        run_server(host=parsed.host, port=parsed.port, config=config, rule_based_only=parsed.rb)
    else:
        sys.exit(main())
