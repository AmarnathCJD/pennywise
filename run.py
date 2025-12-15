#!/usr/bin/env python3
"""
PennyWise Main Application
===========================

Main entry point for the PennyWise vulnerability scanner.

Usage:
    python run.py  # Starts the server on port 8080
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pennywise.server import run_server
from pennywise.config import PennywiseConfig
from pennywise.utils.logging import setup_logging


def main():
    """Main entry point."""
    logger = setup_logging(log_level="INFO")
    logger.print_banner()
    
    config = PennywiseConfig()
    
    logger.info("Starting PennyWise Vulnerability Scanner...")
    logger.info("Server will be available at http://localhost:8080")
    
    run_server(host='0.0.0.0', port=8080, config=config)


if __name__ == '__main__':
    main()
