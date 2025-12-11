#!/usr/bin/env python3
"""
PennyWise Main Application (Legacy Entry Point)
================================================

This file provides backward compatibility with the old API structure.
For new implementations, use app.py or the pennywise package directly.

Usage:
    python n.py  # Starts the server on port 8080
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the new modular system
try:
    from pennywise.server import run_server
    from pennywise.config import PennywiseConfig
    from pennywise.utils.logging import setup_logging
except ImportError as e:
    print(f"Error: Could not import pennywise modules: {e}")
    print("Falling back to legacy mode...")
    
    # Fallback to old implementation
    import subprocess
    import json
    import asyncio
    import time
    import logging
    import aiohttp
    from aiohttp import web
    from bs4 import BeautifulSoup
    import colorama
    
    colorama.init()
    
    # Legacy implementation continues below...
    class ColoredFormatter(logging.Formatter):
        def format(self, record):
            if record.levelno == logging.INFO:
                record.msg = f"{record.msg}"
            return super().format(record)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColoredFormatter('[@PW %(asctime)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S'))
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    
    class LocalSecurityModel:
        def __init__(self, model_path="./qwen-vuln-detector/localmodel"):
            banner = """
        ╔═╗╔═╗╔╗╔╔╗╔╦ ╦╦ ╦╦╔═╗╔═╗
        ╠═╝║╣ ║║║║║║╚╦╝║║║║╚═╗║╣ 
        ╩  ╚═╝╝╚╝╝╚╝ ╩ ╚╩╝╩╚═╝╚═╝
            """
            logger.info(colorama.Fore.CYAN + banner + colorama.Style.RESET_ALL)
            logger.info(colorama.Fore.CYAN + "Initializing Pennywise (Legacy Mode)..." + colorama.Style.RESET_ALL)
            self.binary = model_path
            logger.info(colorama.Fore.GREEN + "Pennywise loaded successfully." + colorama.Style.RESET_ALL)
        
        def _call_cli(self, mode, data):
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.json') as tmp:
                json.dump(data, tmp)
                tmp_path = tmp.name
            cmd = [self.binary, mode, tmp_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            try:
                resp = json.loads(result.stdout.replace('```json\n', '').replace('\n```', '').strip())
                return resp
            except json.JSONDecodeError:
                return {"error": "E999", "message": result.stdout.strip()}
        
        def analyze_vuln(self, data): return self._call_cli("vuln-info", data)
        def site_audit(self, data): return self._call_cli("site-audit", data)
        def classify(self, data): return self._call_cli("classify-severity", data)
    
    model = LocalSecurityModel()
    
    async def analyze_vuln_handler(request):
        data = await request.json()
        result = model.analyze_vuln(data)
        return web.json_response(result)
    
    async def site_audit_handler(request):
        url = (await request.text()).strip()
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                html = await response.text()
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
        html = html[:4000]
        data = {"url": url, "html": html, "title": title}
        result = model.site_audit(data)
        return web.json_response(result)
    
    async def index_handler(request):
        return web.FileResponse('index.html')
    
    app = web.Application()
    app.router.add_get('/', index_handler)
    app.router.add_post('/analyze_vuln', analyze_vuln_handler)
    app.router.add_post('/site_audit', site_audit_handler)
    
    if __name__ == '__main__':
        logger.info(colorama.Fore.GREEN + "Starting Pennywise HTTP Server (Legacy) on port 8080..." + colorama.Style.RESET_ALL)
        web.run_app(app, port=8080)
    
    sys.exit(0)


def main():
    """Main entry point using the new modular system."""
    logger = setup_logging(log_level="INFO")
    logger.print_banner()
    
    config = PennywiseConfig()
    
    logger.info("Starting PennyWise with the new modular architecture...")
    logger.info("For CLI options, run: python app.py --help")
    
    run_server(host='0.0.0.0', port=8080, config=config)


if __name__ == '__main__':
    main()
