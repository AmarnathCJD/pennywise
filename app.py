#!/usr/bin/env python3
"""
PennyWise - AI-Powered Vulnerability Scanner
=============================================

A professional-grade web application security scanner with:
- AI-assisted vulnerability detection (powered by Qwen model)
- Intelligent attack selection based on target analysis
- Sandbox environment for behavior capture
- Reinforcement learning for user pattern adaptation

Usage:
    # Start the API server
    python app.py server
    
    # Run a scan from command line
    python app.py scan https://example.com
    
    # Analyze a target
    python app.py analyze https://example.com
    
    # See all options
    python app.py --help

Author: PennyWise Team
Version: 2.0.0
"""

import sys
import os

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pennywise.cli import main

if __name__ == '__main__':
    sys.exit(main())
