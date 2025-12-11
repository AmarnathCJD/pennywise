"""
PennyWise Web UI - Backend API Server.
Provides REST API endpoints for the web interface.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

from aiohttp import web
import aiohttp_cors

from ..core.enhanced_scanner import EnhancedScanner, VulnerabilityFinding, ScanProgress
from ..ai.analyzer import get_ai_analyzer
from ..config import AttackType, PennywiseConfig

logger = logging.getLogger(__name__)

# Store active scans
active_scans: Dict[str, Dict[str, Any]] = {}
scan_results: Dict[str, Dict[str, Any]] = {}


async def handle_scan_start(request: web.Request) -> web.Response:
    """Start a new vulnerability scan."""
    try:
        data = await request.json()
    except:
        data = {}
    
    # Support both 'target' and 'target_url' from frontend
    target = data.get('target_url') or data.get('target')
    if not target:
        return web.json_response({'error': 'Target URL is required'}, status=400)
    
    # Parse options from frontend format
    options = data.get('options', {})
    attacks = data.get('attacks', ['xss', 'sqli', 'csrf', 'auth'])
    crawl = options.get('crawl', data.get('crawl', True))
    max_pages = data.get('max_pages', 50)
    threads = options.get('concurrency', data.get('threads', 10))
    
    # Map attack types
    attack_map = {
        'xss': AttackType.XSS,
        'sqli': AttackType.SQLI,
        'csrf': AttackType.CSRF,
        'auth': AttackType.AUTH,
        'ssrf': AttackType.SSRF if hasattr(AttackType, 'SSRF') else AttackType.XSS,
        'lfi': AttackType.LFI if hasattr(AttackType, 'LFI') else AttackType.XSS,
    }
    
    attack_types = [attack_map[a] for a in attacks if a in attack_map]
    if not attack_types:
        attack_types = [AttackType.XSS, AttackType.SQLI]
    
    # Generate scan ID
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(target) % 10000:04d}"
    
    # Initialize scan status
    active_scans[scan_id] = {
        'id': scan_id,
        'target': target,
        'status': 'running',
        'progress': 0,
        'phase': 'Initializing...',
        'findings_count': 0,
        'requests_made': 0,
        'started_at': datetime.now().isoformat(),
        'findings': [],
        'logs': []  # Store logs for UI
    }
    
    # Start scan in background
    asyncio.create_task(_run_scan_task(scan_id, target, attack_types, crawl, max_pages, threads))
    
    return web.json_response({
        'scan_id': scan_id,
        'status': 'started',
        'target': target
    })


async def _run_scan_task(scan_id: str, 
                         target: str, 
                         attack_types: List[AttackType],
                         crawl: bool,
                         max_pages: int,
                         threads: int):
    """Run the scan in background."""
    
    def on_finding(finding: VulnerabilityFinding):
        if scan_id in active_scans:
            active_scans[scan_id]['findings'].append(finding.to_dict())
            active_scans[scan_id]['findings_count'] = len(active_scans[scan_id]['findings'])
    
    def on_progress(progress: ScanProgress):
        if scan_id in active_scans:
            active_scans[scan_id]['progress'] = progress.percentage
            active_scans[scan_id]['phase'] = progress.current_phase
            active_scans[scan_id]['requests_made'] = progress.requests_made
            active_scans[scan_id]['pages_scanned'] = progress.pages_crawled
    
    def on_log(message: str, level: str):
        """Capture logs for the UI."""
        if scan_id in active_scans:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'message': message,
                'level': level
            }
            active_scans[scan_id]['logs'].append(log_entry)
            # Keep only last 100 logs to avoid memory issues
            if len(active_scans[scan_id]['logs']) > 100:
                active_scans[scan_id]['logs'].pop(0)
    
    try:
        # Use high concurrency for speed (default 50 or user-specified)
        concurrency = max(threads, 100)
        scanner = EnhancedScanner(
            max_concurrent_requests=concurrency,
            on_finding=on_finding,
            on_progress=on_progress,
            on_log=on_log  # Add log callback
        )
        
        result = await scanner.scan(
            url=target,
            attack_types=attack_types,
            crawl=crawl,
            max_pages=max_pages
        )
        
        # Store result
        scan_results[scan_id] = result
        
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'completed'
            active_scans[scan_id]['progress'] = 100
            active_scans[scan_id]['completed_at'] = datetime.now().isoformat()
    
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'failed'
            active_scans[scan_id]['error'] = str(e)


async def handle_scan_status(request: web.Request) -> web.Response:
    """Get the status of a scan."""
    scan_id = request.match_info.get('scan_id')
    
    if scan_id not in active_scans:
        return web.json_response({'error': 'Scan not found'}, status=404)
    
    scan_info = active_scans[scan_id]
    
    # Format response for frontend
    return web.json_response({
        'status': scan_info['status'],
        'progress': scan_info['progress'],
        'requests': scan_info.get('requests_made', 0),
        'vulnerabilities': scan_info['findings_count'],
        'phase': scan_info.get('phase', ''),
        'logs': scan_info.get('logs', [])[-20:]  # Send last 20 logs
    })


async def handle_scan_result(request: web.Request) -> web.Response:
    """Get the full result of a completed scan."""
    scan_id = request.match_info.get('scan_id')
    
    # Check if scan exists in active_scans for findings
    if scan_id in active_scans:
        scan_info = active_scans[scan_id]
        
        if scan_info['status'] == 'running':
            return web.json_response({'error': 'Scan still in progress'}, status=202)
        
        # Format vulnerabilities for frontend
        vulnerabilities = []
        for finding in scan_info.get('findings', []):
            vulnerabilities.append({
                'severity': finding.get('severity', 'info'),
                'type': finding.get('vuln_type', finding.get('attack_type', 'unknown')),
                'url': finding.get('url', ''),
                'payload': finding.get('payload', ''),
                'parameter': finding.get('parameter', ''),
                'details': finding.get('evidence', ''),
                'evidence': finding.get('evidence', ''),
                'db_structure': finding.get('db_structure', ''),
                'remediation': finding.get('remediation', '')
            })
        
        return web.json_response({
            'target': scan_info['target'],
            'vulnerabilities': vulnerabilities,
            'scan_id': scan_id,
            'timestamp': scan_info.get('completed_at', scan_info.get('started_at', ''))
        })
    
    if scan_id in scan_results:
        return web.json_response(scan_results[scan_id])
    
    return web.json_response({'error': 'Scan not found'}, status=404)


async def handle_list_scans(request: web.Request) -> web.Response:
    """List all scans."""
    scans = []
    for scan_id, scan_info in active_scans.items():
        scans.append({
            'id': scan_id,
            'target': scan_info['target'],
            'status': scan_info['status'],
            'progress': scan_info['progress'],
            'findings_count': scan_info['findings_count'],
            'started_at': scan_info['started_at']
        })
    
    return web.json_response({'scans': scans})


async def handle_analyze_target(request: web.Request) -> web.Response:
    """Quick AI analysis of a target."""
    try:
        data = await request.json()
    except:
        data = {}
    
    target = data.get('target')
    if not target:
        return web.json_response({'error': 'Target URL is required'}, status=400)
    
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(target, timeout=aiohttp.ClientTimeout(total=10)) as response:
                html = await response.text()
                headers = dict(response.headers)
        
        analyzer = get_ai_analyzer()
        recommendations = analyzer.analyze_target(target, html, headers)
        
        return web.json_response({
            'target': target,
            'recommendations': [
                {
                    'attack_type': r.attack_type.value,
                    'probability': r.probability,
                    'confidence': r.confidence,
                    'reasons': r.reasons,
                    'priority': r.priority
                } for r in recommendations
            ]
        })
    
    except Exception as e:
        return web.json_response({'error': str(e)}, status=500)


async def handle_index(request: web.Request) -> web.Response:
    """Serve the main web UI."""
    html_path = Path(__file__).parent / 'static' / 'index.html'
    if html_path.exists():
        return web.FileResponse(html_path)
    
    # Fallback inline HTML
    return web.Response(
        text=get_inline_html(),
        content_type='text/html'
    )


def get_inline_html() -> str:
    """Get the inline HTML for the web UI."""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PennyWise - AI Vulnerability Scanner</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a1a;
            --bg-secondary: #12122a;
            --bg-card: #1a1a3a;
            --accent: #00d4ff;
            --accent-dim: rgba(0, 212, 255, 0.1);
            --text-primary: #ffffff;
            --text-secondary: #a0a0b0;
            --border: rgba(255, 255, 255, 0.1);
            --success: #00ff88;
            --warning: #ffaa00;
            --danger: #ff4444;
            --critical: #ff0066;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Header */
        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 16px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .logo-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--accent), #0066ff);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        
        .logo-text {
            font-size: 1.5em;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent), #0066ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .nav-links {
            display: flex;
            gap: 24px;
        }
        
        .nav-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s;
        }
        
        .nav-link:hover, .nav-link.active {
            color: var(--accent);
        }
        
        /* Main Content */
        .main {
            max-width: 1400px;
            margin: 0 auto;
            padding: 32px;
        }
        
        /* Scan Form */
        .scan-form-card {
            background: var(--bg-card);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 32px;
            border: 1px solid var(--border);
        }
        
        .scan-form-card h2 {
            margin-bottom: 24px;
            font-size: 1.25em;
            font-weight: 600;
        }
        
        .form-row {
            display: flex;
            gap: 16px;
            margin-bottom: 20px;
        }
        
        .form-group {
            flex: 1;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 0.875em;
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 1em;
            font-family: 'JetBrains Mono', monospace;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-dim);
        }
        
        .form-input::placeholder {
            color: var(--text-secondary);
            opacity: 0.5;
        }
        
        /* Checkboxes */
        .checkbox-group {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }
        
        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .checkbox-item:hover {
            border-color: var(--accent);
        }
        
        .checkbox-item.checked {
            background: var(--accent-dim);
            border-color: var(--accent);
        }
        
        .checkbox-item input {
            display: none;
        }
        
        .checkbox-box {
            width: 18px;
            height: 18px;
            border: 2px solid var(--text-secondary);
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
        }
        
        .checkbox-item.checked .checkbox-box {
            background: var(--accent);
            border-color: var(--accent);
        }
        
        .checkbox-box::after {
            content: '✓';
            color: var(--bg-primary);
            font-size: 12px;
            opacity: 0;
            transition: opacity 0.2s;
        }
        
        .checkbox-item.checked .checkbox-box::after {
            opacity: 1;
        }
        
        /* Buttons */
        .btn {
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 1em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--accent), #0066ff);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0, 212, 255, 0.4);
        }
        
        .btn-primary:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-secondary {
            background: var(--bg-secondary);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }
        
        .btn-secondary:hover {
            border-color: var(--accent);
        }
        
        /* Progress Section */
        .scan-progress {
            display: none;
            background: var(--bg-card);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 32px;
            border: 1px solid var(--border);
        }
        
        .scan-progress.active {
            display: block;
        }
        
        .progress-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .progress-bar-container {
            height: 8px;
            background: var(--bg-secondary);
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 16px;
        }
        
        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), #0066ff);
            border-radius: 4px;
            transition: width 0.3s ease;
            width: 0%;
        }
        
        .progress-stats {
            display: flex;
            gap: 32px;
            color: var(--text-secondary);
            font-size: 0.875em;
        }
        
        .progress-stat {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .progress-stat .value {
            color: var(--text-primary);
            font-weight: 600;
        }
        
        /* Results Section */
        .results-section {
            display: none;
        }
        
        .results-section.active {
            display: block;
        }
        
        .results-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }
        
        .summary-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid var(--border);
        }
        
        .summary-card .value {
            font-size: 2em;
            font-weight: 700;
            margin-bottom: 4px;
        }
        
        .summary-card .label {
            color: var(--text-secondary);
            font-size: 0.875em;
        }
        
        .summary-card.critical { border-color: var(--critical); }
        .summary-card.critical .value { color: var(--critical); }
        
        .summary-card.high { border-color: var(--danger); }
        .summary-card.high .value { color: var(--danger); }
        
        .summary-card.medium { border-color: var(--warning); }
        .summary-card.medium .value { color: var(--warning); }
        
        .summary-card.low { border-color: var(--accent); }
        .summary-card.low .value { color: var(--accent); }
        
        /* Findings List */
        .findings-list {
            background: var(--bg-card);
            border-radius: 16px;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        
        .findings-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .findings-header h3 {
            font-size: 1.125em;
            font-weight: 600;
        }
        
        .finding-item {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            transition: background 0.2s;
        }
        
        .finding-item:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        
        .finding-item:last-child {
            border-bottom: none;
        }
        
        .finding-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }
        
        .severity-badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical { background: var(--critical); }
        .severity-high { background: var(--danger); }
        .severity-medium { background: var(--warning); color: #000; }
        .severity-low { background: var(--accent); color: #000; }
        .severity-info { background: var(--text-secondary); }
        
        .finding-title {
            font-weight: 600;
        }
        
        .finding-url {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875em;
            color: var(--text-secondary);
            margin-bottom: 8px;
            word-break: break-all;
        }
        
        .finding-description {
            color: var(--text-secondary);
            font-size: 0.875em;
            line-height: 1.5;
        }
        
        .finding-meta {
            display: flex;
            gap: 16px;
            margin-top: 12px;
            font-size: 0.8em;
            color: var(--text-secondary);
        }
        
        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-secondary);
        }
        
        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        
        /* Animations */
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .scanning-indicator {
            animation: pulse 1.5s infinite;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .header {
                padding: 12px 16px;
            }
            
            .main {
                padding: 16px;
            }
            
            .form-row {
                flex-direction: column;
            }
            
            .progress-stats {
                flex-wrap: wrap;
                gap: 16px;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">
            <div class="logo-icon">🔒</div>
            <span class="logo-text">PennyWise</span>
        </div>
        <nav class="nav-links">
            <a href="#" class="nav-link active">Scanner</a>
            <a href="/sandbox" class="nav-link">Sandbox</a>
            <a href="#" class="nav-link" onclick="showHistory()">History</a>
        </nav>
    </header>
    
    <main class="main">
        <!-- Scan Form -->
        <div class="scan-form-card">
            <h2>🎯 New Security Scan</h2>
            <form id="scanForm">
                <div class="form-row">
                    <div class="form-group" style="flex: 3;">
                        <label for="targetUrl">Target URL</label>
                        <input type="url" id="targetUrl" class="form-input" 
                               placeholder="https://example.com" required>
                    </div>
                    <div class="form-group" style="flex: 1;">
                        <label for="maxPages">Max Pages</label>
                        <input type="number" id="maxPages" class="form-input" 
                               value="50" min="1" max="500">
                    </div>
                    <div class="form-group" style="flex: 1;">
                        <label for="threads">Threads</label>
                        <input type="number" id="threads" class="form-input" 
                               value="10" min="1" max="50">
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Attack Types</label>
                    <div class="checkbox-group">
                        <label class="checkbox-item checked" data-value="xss">
                            <input type="checkbox" checked>
                            <span class="checkbox-box"></span>
                            <span>XSS</span>
                        </label>
                        <label class="checkbox-item checked" data-value="sqli">
                            <input type="checkbox" checked>
                            <span class="checkbox-box"></span>
                            <span>SQL Injection</span>
                        </label>
                        <label class="checkbox-item checked" data-value="csrf">
                            <input type="checkbox" checked>
                            <span class="checkbox-box"></span>
                            <span>CSRF</span>
                        </label>
                        <label class="checkbox-item checked" data-value="auth">
                            <input type="checkbox" checked>
                            <span class="checkbox-box"></span>
                            <span>Auth Issues</span>
                        </label>
                        <label class="checkbox-item" data-value="crawl">
                            <input type="checkbox" checked>
                            <span class="checkbox-box"></span>
                            <span>Enable Crawling</span>
                        </label>
                    </div>
                </div>
                
                <div style="margin-top: 24px;">
                    <button type="submit" class="btn btn-primary" id="startScanBtn">
                        <span>🚀</span> Start Scan
                    </button>
                    <button type="button" class="btn btn-secondary" onclick="quickAnalyze()" style="margin-left: 12px;">
                        <span>⚡</span> Quick Analyze
                    </button>
                </div>
            </form>
        </div>
        
        <!-- Progress Section -->
        <div class="scan-progress" id="progressSection">
            <div class="progress-header">
                <h3 class="scanning-indicator">🔍 Scanning in progress...</h3>
                <span id="progressPhase">Initializing...</span>
            </div>
            <div class="progress-bar-container">
                <div class="progress-bar" id="progressBar"></div>
            </div>
            <div class="progress-stats">
                <div class="progress-stat">
                    <span>Progress:</span>
                    <span class="value" id="progressPercent">0%</span>
                </div>
                <div class="progress-stat">
                    <span>Findings:</span>
                    <span class="value" id="findingsCount">0</span>
                </div>
                <div class="progress-stat">
                    <span>Requests:</span>
                    <span class="value" id="requestsCount">0</span>
                </div>
                <div class="progress-stat">
                    <span>Pages:</span>
                    <span class="value" id="pagesCount">0</span>
                </div>
            </div>
        </div>
        
        <!-- Results Section -->
        <div class="results-section" id="resultsSection">
            <div class="results-summary" id="resultsSummary">
                <!-- Summary cards will be inserted here -->
            </div>
            
            <div class="findings-list">
                <div class="findings-header">
                    <h3>📋 Vulnerability Findings</h3>
                    <button class="btn btn-secondary" onclick="downloadReport()">
                        📥 Download Report
                    </button>
                </div>
                <div id="findingsList">
                    <!-- Findings will be inserted here -->
                </div>
            </div>
        </div>
    </main>
    
    <script>
        let currentScanId = null;
        let pollInterval = null;
        let scanResult = null;
        
        // Checkbox toggle
        document.querySelectorAll('.checkbox-item').forEach(item => {
            item.addEventListener('click', () => {
                item.classList.toggle('checked');
                const input = item.querySelector('input');
                input.checked = item.classList.contains('checked');
            });
        });
        
        // Form submission
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await startScan();
        });
        
        async function startScan() {
            const target = document.getElementById('targetUrl').value;
            const maxPages = parseInt(document.getElementById('maxPages').value);
            const threads = parseInt(document.getElementById('threads').value);
            
            // Get selected attacks
            const attacks = [];
            document.querySelectorAll('.checkbox-item[data-value]').forEach(item => {
                if (item.classList.contains('checked') && item.dataset.value !== 'crawl') {
                    attacks.push(item.dataset.value);
                }
            });
            
            const crawl = document.querySelector('.checkbox-item[data-value="crawl"]').classList.contains('checked');
            
            // Disable button
            const btn = document.getElementById('startScanBtn');
            btn.disabled = true;
            btn.innerHTML = '<span>⏳</span> Starting...';
            
            try {
                const response = await fetch('/api/scan/start', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        target,
                        attacks,
                        crawl,
                        max_pages: maxPages,
                        threads
                    })
                });
                
                const data = await response.json();
                
                if (data.scan_id) {
                    currentScanId = data.scan_id;
                    showProgress();
                    startPolling();
                } else {
                    alert('Failed to start scan: ' + (data.error || 'Unknown error'));
                }
            } catch (err) {
                alert('Error starting scan: ' + err.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<span>🚀</span> Start Scan';
            }
        }
        
        function showProgress() {
            document.getElementById('progressSection').classList.add('active');
            document.getElementById('resultsSection').classList.remove('active');
        }
        
        function startPolling() {
            pollInterval = setInterval(async () => {
                try {
                    const response = await fetch(`/api/scan/status/${currentScanId}`);
                    const data = await response.json();
                    
                    updateProgress(data);
                    
                    if (data.status === 'completed' || data.status === 'failed') {
                        clearInterval(pollInterval);
                        
                        if (data.status === 'completed') {
                            // Fetch full results
                            const resultResponse = await fetch(`/api/scan/result/${currentScanId}`);
                            scanResult = await resultResponse.json();
                            showResults(scanResult);
                        } else {
                            alert('Scan failed: ' + (data.error || 'Unknown error'));
                        }
                    }
                } catch (err) {
                    console.error('Polling error:', err);
                }
            }, 1000);
        }
        
        function updateProgress(data) {
            document.getElementById('progressBar').style.width = data.progress + '%';
            document.getElementById('progressPercent').textContent = data.progress + '%';
            document.getElementById('progressPhase').textContent = data.phase || 'Processing...';
            document.getElementById('findingsCount').textContent = data.findings_count || 0;
            document.getElementById('requestsCount').textContent = data.requests_made || 0;
            document.getElementById('pagesCount').textContent = data.pages_scanned || 0;
        }
        
        function showResults(result) {
            document.getElementById('progressSection').classList.remove('active');
            document.getElementById('resultsSection').classList.add('active');
            
            const summary = result.summary || {};
            const findings = result.findings || [];
            const severityBreakdown = summary.severity_breakdown || {};
            
            // Render summary cards
            const summaryHtml = `
                <div class="summary-card">
                    <div class="value">${summary.overall_risk || 'N/A'}</div>
                    <div class="label">Overall Risk</div>
                </div>
                <div class="summary-card critical">
                    <div class="value">${severityBreakdown.Critical || 0}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-card high">
                    <div class="value">${severityBreakdown.High || 0}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-card medium">
                    <div class="value">${severityBreakdown.Medium || 0}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-card low">
                    <div class="value">${(severityBreakdown.Low || 0) + (severityBreakdown.Info || 0)}</div>
                    <div class="label">Low/Info</div>
                </div>
            `;
            document.getElementById('resultsSummary').innerHTML = summaryHtml;
            
            // Render findings
            if (findings.length === 0) {
                document.getElementById('findingsList').innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">✅</div>
                        <p>No vulnerabilities detected!</p>
                    </div>
                `;
            } else {
                const findingsHtml = findings.map(f => `
                    <div class="finding-item">
                        <div class="finding-header">
                            <span class="severity-badge severity-${f.severity}">${f.severity}</span>
                            <span class="finding-title">${f.title}</span>
                        </div>
                        <div class="finding-url">${f.url}</div>
                        <div class="finding-description">${f.description || ''}</div>
                        ${f.parameter ? `<div class="finding-meta"><span>Parameter: <strong>${f.parameter}</strong></span></div>` : ''}
                        ${f.recommendations && f.recommendations.length > 0 ? `
                            <div class="finding-meta" style="flex-direction: column; align-items: flex-start; gap: 4px;">
                                <span style="color: var(--accent);">Recommendations:</span>
                                ${f.recommendations.map(r => `<span>• ${r}</span>`).join('')}
                            </div>
                        ` : ''}
                    </div>
                `).join('');
                document.getElementById('findingsList').innerHTML = findingsHtml;
            }
        }
        
        async function quickAnalyze() {
            const target = document.getElementById('targetUrl').value;
            if (!target) {
                alert('Please enter a target URL');
                return;
            }
            
            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target})
                });
                
                const data = await response.json();
                
                if (data.recommendations) {
                    let msg = 'AI Analysis Results:\\n\\n';
                    data.recommendations.forEach(r => {
                        msg += `${r.attack_type.toUpperCase()}: ${(r.probability * 100).toFixed(0)}% likely\\n`;
                        msg += `  Reasons: ${r.reasons.join(', ')}\\n\\n`;
                    });
                    alert(msg);
                } else {
                    alert('Analysis failed: ' + (data.error || 'Unknown error'));
                }
            } catch (err) {
                alert('Error: ' + err.message);
            }
        }
        
        function downloadReport() {
            if (!scanResult) return;
            
            const blob = new Blob([JSON.stringify(scanResult, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `pennywise_report_${currentScanId}.json`;
            a.click();
            URL.revokeObjectURL(url);
        }
        
        function showHistory() {
            alert('Scan history feature coming soon!');
        }
    </script>
</body>
</html>'''


# Configuration storage
app_config: Dict[str, Any] = {
    'timeout': 10,
    'maxDepth': 3,
    'userAgent': 'PennyWise Security Scanner v1.0',
    'concurrency': 10,
    'aiModel': 'local',
    'apiKey': '',
    'aiSeverity': False,
    'aiRemediation': False,
    'payloadEvasion': False,
    'payloadAggressive': False,
    'timeBased': True,
    'reportFormat': 'json',
    'autoSave': True,
    'includeEvidence': True
}


async def handle_config_get(request: web.Request) -> web.Response:
    """Get current configuration."""
    return web.json_response(app_config)


async def handle_config_post(request: web.Request) -> web.Response:
    """Update configuration."""
    try:
        data = await request.json()
        app_config.update(data)
        return web.json_response({'status': 'ok'})
    except Exception as e:
        return web.json_response({'error': str(e)}, status=400)


async def handle_reports_list(request: web.Request) -> web.Response:
    """List saved reports."""
    reports_dir = Path(__file__).parent.parent.parent / 'reports'
    reports = []
    
    if reports_dir.exists():
        for f in reports_dir.glob('*.json'):
            try:
                with open(f) as fp:
                    data = json.load(fp)
                reports.append({
                    'filename': f.name,
                    'name': data.get('target', f.stem),
                    'date': data.get('timestamp', 'Unknown'),
                    'vulnerabilities': len(data.get('vulnerabilities', []))
                })
            except:
                reports.append({
                    'filename': f.name,
                    'name': f.stem,
                    'date': 'Unknown',
                    'vulnerabilities': 0
                })
    
    return web.json_response({'reports': reports})


async def handle_report_get(request: web.Request) -> web.Response:
    """Get a specific report."""
    filename = request.match_info.get('filename')
    reports_dir = Path(__file__).parent.parent.parent / 'reports'
    report_path = reports_dir / filename
    
    if not report_path.exists():
        return web.json_response({'error': 'Report not found'}, status=404)
    
    return web.FileResponse(report_path)


async def handle_report_delete(request: web.Request) -> web.Response:
    """Delete a report."""
    filename = request.match_info.get('filename')
    reports_dir = Path(__file__).parent.parent.parent / 'reports'
    report_path = reports_dir / filename
    
    if report_path.exists():
        report_path.unlink()
        return web.json_response({'status': 'deleted'})
    
    return web.json_response({'error': 'Report not found'}, status=404)


def create_app() -> web.Application:
    """Create the web application."""
    app = web.Application()
    
    # Setup CORS
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
            allow_methods="*"
        )
    })
    
    # Routes - UI
    app.router.add_get('/', handle_index)
    
    # Routes - Scan API (matching frontend expectations)
    app.router.add_post('/api/scan', handle_scan_start)
    app.router.add_get('/api/status/{scan_id}', handle_scan_status)
    app.router.add_get('/api/results/{scan_id}', handle_scan_result)
    app.router.add_get('/api/scans', handle_list_scans)
    app.router.add_post('/api/analyze', handle_analyze_target)
    
    # Routes - Configuration
    app.router.add_get('/api/config', handle_config_get)
    app.router.add_post('/api/config', handle_config_post)
    
    # Routes - Reports
    app.router.add_get('/api/reports', handle_reports_list)
    app.router.add_get('/api/reports/{filename}', handle_report_get)
    app.router.add_delete('/api/reports/{filename}', handle_report_delete)
    
    # Apply CORS to all routes
    for route in list(app.router.routes()):
        cors.add(route)
    
    # Static files
    static_path = Path(__file__).parent / 'static'
    if static_path.exists():
        app.router.add_static('/static/', static_path)
    
    return app


async def run_webui(host: str = '127.0.0.1', port: int = 8080):
    """Run the web UI server."""
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    
    print(f"\n🌐 PennyWise Web UI running at http://{host}:{port}")
    print("   Press Ctrl+C to stop\n")
    
    await site.start()
    
    # Keep running
    while True:
        await asyncio.sleep(3600)


if __name__ == '__main__':
    import asyncio
    asyncio.run(run_webui())
