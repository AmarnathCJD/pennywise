"""
PennyWise HTTP API Server
=========================

Provides REST API endpoints for the vulnerability scanner.
"""

import asyncio
import json
from datetime import datetime
from aiohttp import web

from .core.scanner import VulnerabilityScanner, ScanResult
from .core.target_analyzer import TargetAnalyzer
from .core.attack_selector import AttackSelector
from .ai.model_interface import AIModelInterface
from .sandbox.environment import SandboxEnvironment, ActionType
from .learning.behavior_learner import BehaviorLearner
from .config import PennywiseConfig, AttackType, ScanMode
from .utils.logging import setup_logging, PennywiseLogger
from .utils.reports import ReportGenerator


class PennywiseAPI:
    """
    HTTP API server for PennyWise vulnerability scanner.
    
    Endpoints:
    - POST /api/scan - Start a full vulnerability scan
    - POST /api/analyze - Analyze a target without scanning
    - POST /api/attack/select - Get attack recommendations
    - GET /api/findings - Get all findings from current session
    - GET /api/report/:format - Generate a report
    - POST /api/sandbox/start - Start sandbox session
    - POST /api/sandbox/action - Record sandbox action
    - GET /api/learning/stats - Get learning statistics
    """
    
    def __init__(self, config: PennywiseConfig = None):
        """Initialize the API server."""
        self.config = config or PennywiseConfig()
        self.logger = setup_logging(
            log_level=self.config.log_level,
            log_file=self.config.log_file
        )
        
        # Initialize components
        self.ai_model = AIModelInterface(self.config.ai.model_path)
        self.scanner = VulnerabilityScanner(
            config=self.config,
            ai_model=self.ai_model,
            on_finding=self._on_finding,
            on_progress=self._on_progress
        )
        self.target_analyzer = TargetAnalyzer(self.config.scan)
        self.attack_selector = AttackSelector(self.ai_model, self.config.scan.scan_mode)
        self.sandbox = SandboxEnvironment(
            storage_path=self.config.sandbox.storage_path,
            on_action=self._on_sandbox_action
        )
        self.learner = BehaviorLearner(
            model_path=self.config.learning.model_path,
            sandbox=self.sandbox
        )
        
        # Current scan result
        self.current_result: ScanResult = None
        
        # Create web app
        self.app = web.Application()
        self._setup_routes()
        
        self.logger.info("PennyWise API initialized")
    
    def _setup_routes(self):
        """Set up API routes."""
        import os
        base_dir = os.path.dirname(os.path.abspath(__file__))
        static_dir = os.path.join(base_dir, 'webui', 'static')
        
        self.app.router.add_get('/', self._handle_index)
        self.app.router.add_static('/static', static_dir, show_index=True)
        
        # Scan endpoints
        self.app.router.add_post('/api/scan', self._handle_scan)
        self.app.router.add_post('/api/analyze', self._handle_analyze)
        self.app.router.add_post('/api/attack/select', self._handle_attack_select)
        
        # Findings and reports
        self.app.router.add_get('/api/findings', self._handle_get_findings)
        self.app.router.add_get('/api/report/{format}', self._handle_report)
        
        # Sandbox endpoints
        self.app.router.add_post('/api/sandbox/start', self._handle_sandbox_start)
        self.app.router.add_post('/api/sandbox/end', self._handle_sandbox_end)
        self.app.router.add_post('/api/sandbox/action', self._handle_sandbox_action)
        self.app.router.add_get('/api/sandbox/session', self._handle_sandbox_session)
        
        # Learning endpoints
        self.app.router.add_get('/api/learning/stats', self._handle_learning_stats)
        self.app.router.add_post('/api/learning/train', self._handle_learning_train)
        self.app.router.add_get('/api/learning/recommend', self._handle_learning_recommend)
        
        # Test local server endpoint
        self.app.router.add_post('/api/test-local', self._handle_test_local)
        self.app.router.add_get('/api/test-local/status', self._handle_test_local_status)
        
        # Streaming scan endpoints (SSE) - GET for EventSource
        self.app.router.add_get('/api/scan/stream', self._handle_scan_stream)
        self.app.router.add_get('/api/test-local/stream', self._handle_test_local_stream)
        
        # Legacy endpoints (for compatibility)
        self.app.router.add_post('/analyze_vuln', self._handle_legacy_analyze_vuln)
        self.app.router.add_post('/site_audit', self._handle_legacy_site_audit)
        self.app.router.add_post('/classify', self._handle_legacy_classify)
        self.app.router.add_post('/xss_scan', self._handle_legacy_xss_scan)
    
    async def _handle_index(self, request):
        """Serve the main page."""
        import os
        base_dir = os.path.dirname(os.path.abspath(__file__))
        index_path = os.path.join(base_dir, 'webui', 'static', 'index.html')
        return web.FileResponse(index_path)

    async def _handle_scan(self, request):
        """
        Start a full vulnerability scan.
        
        Request body:
        {
            "url": "https://target.com",
            "attack_types": ["xss", "sqli"],  // optional
            "crawl": true,  // optional
            "scan_mode": "active"  // optional
        }
        """
        try:
            data = await request.json()
            url = data.get('url', '').strip()
            
            if not url:
                return web.json_response(
                    {'error': 'URL is required'},
                    status=400
                )
            
            # Parse attack types
            attack_types = None
            if 'attack_types' in data:
                attack_types = [
                    AttackType(t.lower()) for t in data['attack_types']
                    if t.lower() in [at.value for at in AttackType]
                ]
            
            crawl = data.get('crawl', True)
            
            # Update scan mode if provided
            if 'scan_mode' in data:
                try:
                    self.config.scan.scan_mode = ScanMode(data['scan_mode'])
                except ValueError:
                    pass
            
            # Record in sandbox
            self.sandbox.capture_target_selection(url)
            
            # Start scan
            self.logger.step(1, f"Starting scan for {url}")
            
            result = await self.scanner.scan(
                url=url,
                attack_types=attack_types,
                crawl=crawl
            )
            
            self.current_result = result
            
            # Learn from this scan if sandbox has session
            if self.sandbox.get_current_session():
                for finding in result.findings:
                    self.sandbox.capture_finding_interaction(
                        finding.id, 'review',
                        {'severity': finding.severity.value}
                    )
            
            return web.json_response(result.to_dict())
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            return web.json_response(
                {'error': str(e)},
                status=500
            )
    
    async def _handle_analyze(self, request):
        """
        Analyze a target without active scanning.
        
        Request body: {"url": "https://target.com"}
        """
        try:
            data = await request.json()
            url = data.get('url', '').strip()
            
            if not url:
                return web.json_response(
                    {'error': 'URL is required'},
                    status=400
                )
            
            # Analyze target
            analysis = await self.target_analyzer.analyze(url)
            
            # Get attack recommendations
            recommendations = analysis.get_recommended_attacks()
            
            # Get AI insights
            ai_response = self.ai_model.audit_site(
                url=url,
                html=analysis.html_sample,
                title=analysis.title
            )
            
            response = {
                'url': url,
                'title': analysis.title,
                'technologies': [t.value for t in analysis.technologies],
                'security_indicators': {
                    'has_https': analysis.uses_https,
                    'has_csp': analysis.has_csp_header,
                    'has_csrf_protection': analysis.has_csrf_protection,
                    'has_secure_cookies': analysis.has_secure_cookies
                },
                'vulnerability_scores': {
                    'xss': analysis.potential_xss,
                    'sqli': analysis.potential_sqli,
                    'csrf': analysis.potential_csrf,
                    'auth': analysis.potential_auth_issues
                },
                'recommendations': [
                    {
                        'attack_type': r['attack_type'].value if hasattr(r['attack_type'], 'value') else r['attack_type'],
                        'priority': r['priority'],
                        'confidence': r['confidence'],
                        'reasons': r.get('reasons', [])
                    }
                    for r in recommendations
                ],
                'ai_analysis': ai_response.data if ai_response.success else None,
                'forms_found': len(analysis.forms),
                'input_vectors': len(analysis.input_vectors)
            }
            
            return web.json_response(response)
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return web.json_response(
                {'error': str(e)},
                status=500
            )
    
    async def _handle_attack_select(self, request):
        """
        Get attack recommendations for a target.
        
        Request body: {"url": "https://target.com"}
        """
        try:
            data = await request.json()
            url = data.get('url', '').strip()
            
            if not url:
                return web.json_response(
                    {'error': 'URL is required'},
                    status=400
                )
            
            # Analyze target
            analysis = await self.target_analyzer.analyze(url)
            
            # Get learned recommendations
            learned_recs = self.learner.get_attack_recommendation({
                'has_forms': len(analysis.forms) > 0,
                'has_params': len(analysis.input_vectors) > 0,
                'target_type': 'web'
            })
            
            # Create attack strategy
            strategy = self.attack_selector.create_strategy(analysis)
            
            response = {
                'url': url,
                'learned_recommendations': [
                    {'attack_type': at, 'confidence': conf}
                    for at, conf in learned_recs
                ],
                'attack_strategy': {
                    'total_plans': len(strategy.attack_plans),
                    'estimated_requests': strategy.total_estimated_requests,
                    'estimated_time_seconds': strategy.total_estimated_time_seconds,
                    'plans': [
                        {
                            'attack_type': plan.attack_type.value,
                            'priority': plan.priority,
                            'confidence': plan.confidence,
                            'reasons': plan.reasons,
                            'vectors_count': len(plan.vectors),
                            'payloads_count': len(plan.payloads)
                        }
                        for plan in strategy.get_ordered_attacks()
                    ]
                }
            }
            
            return web.json_response(response)
            
        except Exception as e:
            self.logger.error(f"Attack selection failed: {e}")
            return web.json_response(
                {'error': str(e)},
                status=500
            )
    
    async def _handle_get_findings(self, request):
        """Get findings from current scan."""
        if not self.current_result:
            return web.json_response(
                {'findings': [], 'message': 'No scan results available'}
            )
        
        return web.json_response({
            'findings': [f.to_dict() for f in self.current_result.findings],
            'total': len(self.current_result.findings)
        })
    
    async def _handle_report(self, request):
        """Generate a report in the specified format."""
        format_type = request.match_info.get('format', 'json')
        
        if not self.current_result:
            return web.json_response(
                {'error': 'No scan results available'},
                status=404
            )
        
        generator = ReportGenerator(self.current_result)
        
        if format_type == 'json':
            return web.json_response(json.loads(generator.generate_json()))
        
        elif format_type == 'html':
            html = generator.generate_html()
            return web.Response(text=html, content_type='text/html')
        
        elif format_type == 'markdown' or format_type == 'md':
            md = generator.generate_markdown()
            return web.Response(text=md, content_type='text/markdown')
        
        elif format_type == 'summary':
            summary = generator.generate_summary()
            return web.Response(text=summary, content_type='text/plain')
        
        else:
            return web.json_response(
                {'error': f'Unknown format: {format_type}'},
                status=400
            )
    
    async def _handle_sandbox_start(self, request):
        """Start a new sandbox session."""
        try:
            data = await request.json()
            target_url = data.get('url')
            metadata = data.get('metadata', {})
            
            session_id = self.sandbox.start_session(
                target_url=target_url,
                metadata=metadata
            )
            
            return web.json_response({
                'session_id': session_id,
                'message': 'Sandbox session started'
            })
            
        except Exception as e:
            return web.json_response(
                {'error': str(e)},
                status=500
            )
    
    async def _handle_sandbox_end(self, request):
        """End the current sandbox session."""
        session = self.sandbox.end_session()
        
        if session:
            # Learn from the completed session
            self.learner.learn_from_session(session)
            
            return web.json_response({
                'session_id': session.id,
                'actions': session.action_count,
                'duration': session.duration_seconds,
                'message': 'Session ended and learned from'
            })
        
        return web.json_response({
            'message': 'No active session'
        })
    
    async def _handle_sandbox_action(self, request):
        """Record an action in the sandbox."""
        try:
            data = await request.json()
            action_type = ActionType(data.get('action_type'))
            action_data = data.get('data', {})
            context = data.get('context', {})
            
            action_id = self.sandbox.capture_action(
                action_type=action_type,
                data=action_data,
                context=context
            )
            
            return web.json_response({
                'action_id': action_id,
                'recorded': True
            })
            
        except Exception as e:
            return web.json_response(
                {'error': str(e)},
                status=400
            )
    
    async def _handle_sandbox_session(self, request):
        """Get current sandbox session info."""
        session = self.sandbox.get_current_session()
        
        if session:
            return web.json_response({
                'active': True,
                'session_id': session.id,
                'target_url': session.target_url,
                'actions': session.action_count,
                'duration': session.duration_seconds
            })
        
        return web.json_response({
            'active': False
        })
    
    async def _handle_learning_stats(self, request):
        """Get learning system statistics."""
        stats = self.learner.get_learning_stats()
        return web.json_response(stats)
    
    async def _handle_learning_train(self, request):
        """Trigger learning from sandbox sessions."""
        self.learner.learn_from_sandbox()
        stats = self.learner.get_learning_stats()
        
        return web.json_response({
            'message': 'Learning complete',
            'stats': stats
        })
    
    async def _handle_learning_recommend(self, request):
        """Get learned recommendations."""
        data = await request.json() if request.can_read_body else {}
        
        features = {
            'has_forms': data.get('has_forms', True),
            'has_params': data.get('has_params', True),
            'target_type': data.get('target_type', 'web')
        }
        
        recommendations = self.learner.get_attack_recommendation(features)
        
        return web.json_response({
            'recommendations': [
                {'attack_type': at, 'confidence': conf}
                for at, conf in recommendations
            ],
            'ready': self.learner.state.training_samples >= self.learner.min_samples
        })
    
    # Streaming Scan Endpoints (Server-Sent Events)
    
    async def _handle_scan_stream(self, request):
        """
        Stream scan results in real-time using Server-Sent Events.
        Accepts GET with query params: url, attack_types (comma-separated), crawl
        """
        try:
            # Get params from query string (GET) or JSON body (POST)
            if request.method == 'GET':
                url = request.query.get('url', '').strip()
                attack_types_str = request.query.get('attack_types', '')
                crawl = request.query.get('crawl', 'true').lower() == 'true'
                attack_types_list = [t.strip() for t in attack_types_str.split(',') if t.strip()] if attack_types_str else []
            else:
                data = await request.json()
                url = data.get('url', '').strip()
                attack_types_list = data.get('attack_types', [])
                crawl = data.get('crawl', True)
            
            if not url:
                return web.json_response({'error': 'URL is required'}, status=400)
            
            attack_types = None
            if attack_types_list:
                attack_types = [
                    AttackType(t.lower()) for t in attack_types_list
                    if t.lower() in [at.value for at in AttackType]
                ]
            
            # Create SSE response
            response = web.StreamResponse(
                status=200,
                reason='OK',
                headers={
                    'Content-Type': 'text/event-stream',
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'Access-Control-Allow-Origin': '*'
                }
            )
            await response.prepare(request)
            
            # Send start event
            await self._send_sse(response, 'start', {
                'message': f'Starting scan on {url}',
                'target': url,
                'attack_types': [at.value for at in attack_types] if attack_types else ['all']
            })
            
            # Create a custom scanner with streaming callbacks
            findings_list = []
            pages_crawled = 0
            requests_made = 0
            start_time = datetime.now()
            
            async def on_finding(finding):
                findings_list.append(finding)
                await self._send_sse(response, 'finding', {
                    'finding': {
                        'title': finding.title,
                        'severity': finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                        'attack_type': finding.attack_type.value if hasattr(finding.attack_type, 'value') else str(finding.attack_type),
                        'url': finding.url,
                        'parameter': finding.parameter,
                        'evidence': finding.evidence[:300] if finding.evidence else None
                    }
                })
            
            async def on_progress(progress):
                nonlocal pages_crawled, requests_made
                phase = progress.current_phase if hasattr(progress, 'current_phase') else str(progress)
                pages_crawled = progress.pages_crawled if hasattr(progress, 'pages_crawled') else pages_crawled
                requests_made = progress.requests_made if hasattr(progress, 'requests_made') else requests_made
                await self._send_sse(response, 'progress', {
                    'phase': phase,
                    'percent': int((progress.urls_tested / max(progress.total_urls, 1)) * 100) if hasattr(progress, 'urls_tested') else 0,
                    'pages': pages_crawled,
                    'requests': requests_made
                })
            
            async def on_log(message, level):
                await self._send_sse(response, 'log', {
                    'message': message,
                    'level': level
                })
            
            # Create streaming scanner
            from .core.enhanced_scanner import EnhancedScanner
            streaming_scanner = EnhancedScanner(
                config=self.config,
                max_concurrent_requests=30,
                on_finding=on_finding,
                on_progress=on_progress,
                on_log=on_log
            )
            
            # Run scan
            result = await streaming_scanner.scan(url=url, attack_types=attack_types, crawl=crawl, max_pages=50)
            self.current_result = result
            
            # Send completion - handle dict result from EnhancedScanner
            findings_list = result.get('findings', []) if isinstance(result, dict) else result.findings
            severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for f in findings_list:
                if isinstance(f, dict):
                    sev = f.get('severity', 'info').lower()
                else:
                    sev = f.severity.value.lower() if hasattr(f.severity, 'value') else str(f.severity).lower()
                if sev in severity_breakdown:
                    severity_breakdown[sev] += 1
            
            pages = result.get('pages_scanned', 0) if isinstance(result, dict) else result.pages_crawled
            requests = result.get('requests_made', 0) if isinstance(result, dict) else result.requests_made
            duration = result.get('duration_seconds', 0) if isinstance(result, dict) else result.duration_seconds
            
            await self._send_sse(response, 'complete', {
                'result': {
                    'pages_scanned': pages,
                    'requests_made': requests,
                    'scan_duration': duration,
                    'total_findings': len(findings_list)
                },
                'severity_breakdown': severity_breakdown
            })
            
            await response.write_eof()
            return response
            
        except Exception as e:
            self.logger.error(f"Stream scan failed: {e}")
            if 'response' in locals():
                await self._send_sse(response, 'error', {'error': str(e)})
                await response.write_eof()
                return response
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_test_local_stream(self, request):
        """
        Stream test scan results against local vulnerable server.
        Accepts GET with query params: port, attack_types (comma-separated)
        """
        try:
            # Get params from query string (GET) or JSON body (POST)
            if request.method == 'GET':
                port = int(request.query.get('port', '8888'))
                attack_types_str = request.query.get('attack_types', '')
                attack_types_list = [t.strip() for t in attack_types_str.split(',') if t.strip()] if attack_types_str else []
            else:
                try:
                    data = await request.json()
                except:
                    data = {}
                port = data.get('port', 8888)
                attack_types_list = data.get('attack_types', [])
            
            target_url = f"http://localhost:{port}"
            
            attack_types = None
            if attack_types_list:
                attack_types = [
                    AttackType(t.lower()) for t in attack_types_list
                    if t.lower() in [at.value for at in AttackType]
                ]
            
            # Create SSE response
            response = web.StreamResponse(
                status=200,
                reason='OK',
                headers={
                    'Content-Type': 'text/event-stream',
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'Access-Control-Allow-Origin': '*'
                }
            )
            await response.prepare(request)
            
            # Use sandbox path for local testing
            sandbox_url = f"{target_url}/sandbox"
            
            # Send start event
            await self._send_sse(response, 'start', {
                'message': f'Starting test scan on {sandbox_url}',
                'target': sandbox_url
            })
            
            findings_list = []
            pages_count = 0
            requests_count = 0
            
            async def on_finding(finding):
                findings_list.append(finding)
                await self._send_sse(response, 'finding', {
                    'finding': {
                        'title': finding.title,
                        'severity': finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                        'attack_type': finding.attack_type.value if hasattr(finding.attack_type, 'value') else str(finding.attack_type),
                        'url': finding.url,
                        'parameter': finding.parameter,
                        'evidence': finding.evidence[:300] if finding.evidence else None
                    }
                })
            
            async def on_progress(progress):
                nonlocal pages_count, requests_count
                phase = progress.current_phase if hasattr(progress, 'current_phase') else str(progress)
                pages_count = progress.pages_crawled if hasattr(progress, 'pages_crawled') else pages_count
                requests_count = progress.requests_made if hasattr(progress, 'requests_made') else requests_count
                await self._send_sse(response, 'progress', {
                    'phase': phase,
                    'percent': int((progress.urls_tested / max(progress.total_urls, 1)) * 100) if hasattr(progress, 'urls_tested') else 0,
                    'pages': pages_count,
                    'requests': requests_count
                })
            
            async def on_log(message, level):
                await self._send_sse(response, 'log', {
                    'message': message,
                    'level': level
                })
            
            # Create streaming scanner
            from .core.enhanced_scanner import EnhancedScanner
            streaming_scanner = EnhancedScanner(
                config=self.config,
                max_concurrent_requests=30,
                on_finding=on_finding,
                on_progress=on_progress,
                on_log=on_log
            )
            
            # Run scan with sandbox path
            result = await streaming_scanner.scan(url=sandbox_url, attack_types=attack_types, crawl=True, max_pages=30)
            self.current_result = result
            
            # Send completion - handle dict result from EnhancedScanner
            findings_list = result.get('findings', []) if isinstance(result, dict) else result.findings
            severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for f in findings_list:
                if isinstance(f, dict):
                    sev = f.get('severity', 'info').lower()
                else:
                    sev = f.severity.value.lower() if hasattr(f.severity, 'value') else str(f.severity).lower()
                if sev in severity_breakdown:
                    severity_breakdown[sev] += 1
            
            pages = result.get('pages_scanned', 0) if isinstance(result, dict) else result.pages_crawled
            requests = result.get('requests_made', 0) if isinstance(result, dict) else result.requests_made
            duration = result.get('duration_seconds', 0) if isinstance(result, dict) else result.duration_seconds
            
            await self._send_sse(response, 'complete', {
                'result': {
                    'pages_scanned': pages,
                    'requests_made': requests,
                    'scan_duration': duration,
                    'total_findings': len(findings_list)
                },
                'severity_breakdown': severity_breakdown
            })
            
            await response.write_eof()
            return response
            
        except Exception as e:
            self.logger.error(f"Test stream failed: {e}")
            if 'response' in locals():
                await self._send_sse(response, 'error', {'error': str(e)})
                await response.write_eof()
                return response
            return web.json_response({'error': str(e)}, status=500)
    
    async def _send_sse(self, response, event_type, data):
        """Send a Server-Sent Event with type embedded in data."""
        payload = {'type': event_type, **data}
        event_data = f"data: {json.dumps(payload)}\n\n"
        await response.write(event_data.encode('utf-8'))
    
    # Test Local Scanner Endpoints
    
    async def _handle_test_local(self, request):
        """
        Run scanner against local vulnerable test server.
        
        Request body (optional):
        {
            "port": 8888,  // vulnerable server port
            "attack_types": ["xss", "sqli", "csrf"]  // optional
        }
        """
        try:
            try:
                data = await request.json()
            except:
                data = {}
            
            port = data.get('port', 8888)
            target_url = f"http://localhost:{port}"
            
            # Parse attack types
            attack_types = None
            if 'attack_types' in data:
                attack_types = [
                    AttackType(t.lower()) for t in data['attack_types']
                    if t.lower() in [at.value for at in AttackType]
                ]
            
            # Store test scan status
            self._test_scan_status = {
                'running': True,
                'progress': 0,
                'current_phase': 'Starting',
                'findings_count': 0,
                'start_time': datetime.now().isoformat()
            }
            
            self.logger.step(1, f"Starting test scan against {target_url}")
            
            # Run the scan
            result = await self.scanner.scan(
                url=target_url,
                attack_types=attack_types,
                crawl=True
            )
            
            self.current_result = result
            
            # Update status
            self._test_scan_status = {
                'running': False,
                'progress': 100,
                'current_phase': 'Complete',
                'findings_count': len(result.findings),
                'end_time': datetime.now().isoformat()
            }
            
            # Format findings by type
            findings_by_type = {}
            for finding in result.findings:
                attack_type = finding.attack_type.value if hasattr(finding.attack_type, 'value') else str(finding.attack_type)
                if attack_type not in findings_by_type:
                    findings_by_type[attack_type] = []
                findings_by_type[attack_type].append({
                    'title': finding.title,
                    'severity': finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    'url': finding.url,
                    'evidence': finding.evidence[:200] if finding.evidence else None,
                    'parameter': finding.parameter
                })
            
            # Calculate severity breakdown
            severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for finding in result.findings:
                sev = finding.severity.value.lower() if hasattr(finding.severity, 'value') else str(finding.severity).lower()
                if sev in severity_breakdown:
                    severity_breakdown[sev] += 1
            
            return web.json_response({
                'success': True,
                'target': target_url,
                'summary': {
                    'total_findings': len(result.findings),
                    'pages_crawled': result.pages_crawled,
                    'requests_made': result.requests_made,
                    'duration_seconds': result.duration_seconds
                },
                'findings_by_type': findings_by_type,
                'severity_breakdown': severity_breakdown,
                'findings': [f.to_dict() for f in result.findings]
            })
            
        except Exception as e:
            self.logger.error(f"Test scan failed: {e}")
            self._test_scan_status = {
                'running': False,
                'error': str(e)
            }
            return web.json_response(
                {'error': str(e), 'success': False},
                status=500
            )
    
    async def _handle_test_local_status(self, request):
        """Get the status of the current test scan."""
        status = getattr(self, '_test_scan_status', {'running': False, 'message': 'No scan running'})
        return web.json_response(status)
    
    # Legacy endpoint handlers for backward compatibility
    
    async def _handle_legacy_analyze_vuln(self, request):
        """Legacy endpoint: /analyze_vuln"""
        data = await request.json()
        result = self.ai_model.analyze_vulnerability(data)
        return web.json_response(result.data if result.success else {'error': result.error})
    
    async def _handle_legacy_site_audit(self, request):
        """Legacy endpoint: /site_audit"""
        url = (await request.text()).strip()
        analysis = await self.target_analyzer.analyze(url)
        result = self.ai_model.audit_site(url, analysis.html_sample, analysis.title)
        return web.json_response(result.data if result.success else {'error': result.error})
    
    async def _handle_legacy_classify(self, request):
        """Legacy endpoint: /classify"""
        data = await request.json()
        result = self.ai_model.classify_severity(data.get('vulnerabilities', []))
        return web.json_response(result.data if result.success else {'error': result.error})
    
    async def _handle_legacy_xss_scan(self, request):
        """Legacy endpoint: /xss_scan"""
        url = (await request.text()).strip()
        result = await self.scanner.scan(url, attack_types=[AttackType.XSS])
        return web.json_response(result.to_dict())
    
    def _on_finding(self, finding):
        """Callback for new findings."""
        self.logger.finding(finding.severity.value, finding.title)
    
    def _on_progress(self, message: str, current: int, total: int):
        """Callback for progress updates."""
        pass  # Already logged in scanner
    
    def _on_sandbox_action(self, action):
        """Callback for sandbox actions."""
        self.logger.debug(f"Sandbox action: {action.action_type.value}")
    
    def run(self, host: str = '0.0.0.0', port: int = 8080):
        """Run the API server."""
        self.logger.print_banner()
        self.logger.info(f"Starting PennyWise API server on {host}:{port}")
        web.run_app(self.app, host=host, port=port, print=None)


def create_app(config: PennywiseConfig = None) -> web.Application:
    """Create and configure the web application."""
    api = PennywiseAPI(config)
    return api.app


def run_server(host: str = '0.0.0.0', port: int = 8080, config: PennywiseConfig = None):
    """Run the PennyWise API server."""
    api = PennywiseAPI(config)
    api.run(host=host, port=port)
