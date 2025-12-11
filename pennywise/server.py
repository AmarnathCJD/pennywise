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
        self.app.router.add_get('/', self._handle_index)
        self.app.router.add_static('/static', './static', show_index=True)
        
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
        
        # Legacy endpoints (for compatibility)
        self.app.router.add_post('/analyze_vuln', self._handle_legacy_analyze_vuln)
        self.app.router.add_post('/site_audit', self._handle_legacy_site_audit)
        self.app.router.add_post('/classify', self._handle_legacy_classify)
        self.app.router.add_post('/xss_scan', self._handle_legacy_xss_scan)
    
    async def _handle_index(self, request):
        """Serve the main page."""
        return web.FileResponse('./index.html')
    
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
