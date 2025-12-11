"""
Vulnerability Scanner for PennyWise.
Main scanning engine that orchestrates attacks and collects findings.
"""

import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, ParseResult
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Callable
from datetime import datetime
import logging
import re
import json
import time
from collections import deque

from ..config import AttackType, SeverityLevel, ScanConfig, PennywiseConfig
from .target_analyzer import TargetAnalyzer, TargetAnalysis, InputVector
from .attack_selector import AttackSelector, AttackStrategy, AttackPlan
from ..ai.model_interface import AIModelInterface

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """A security finding/vulnerability."""
    id: str
    attack_type: AttackType
    severity: SeverityLevel
    title: str
    description: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: float = 0.8
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'attack_type': self.attack_type.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'evidence': self.evidence,
            'recommendations': self.recommendations,
            'timestamp': self.timestamp.isoformat(),
            'confidence': self.confidence
        }


@dataclass
class ScanResult:
    """Complete result of a vulnerability scan."""
    target_url: str
    scan_started: datetime
    scan_completed: Optional[datetime] = None
    target_analysis: Optional[TargetAnalysis] = None
    attack_strategy: Optional[AttackStrategy] = None
    findings: List[Finding] = field(default_factory=list)
    pages_scanned: int = 0
    requests_made: int = 0
    errors: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, running, completed, failed
    
    @property
    def duration_seconds(self) -> float:
        if self.scan_completed and self.scan_started:
            return (self.scan_completed - self.scan_started).total_seconds()
        return 0
    
    def get_findings_by_severity(self, severity: SeverityLevel) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_type(self, attack_type: AttackType) -> List[Finding]:
        return [f for f in self.findings if f.attack_type == attack_type]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'target_url': self.target_url,
            'scan_started': self.scan_started.isoformat(),
            'scan_completed': self.scan_completed.isoformat() if self.scan_completed else None,
            'pages_scanned': self.pages_scanned,
            'requests_made': self.requests_made,
            'status': self.status,
            'duration_seconds': self.duration_seconds,
            'findings_count': len(self.findings),
            'findings_by_severity': {
                'critical': len(self.get_findings_by_severity(SeverityLevel.CRITICAL)),
                'high': len(self.get_findings_by_severity(SeverityLevel.HIGH)),
                'medium': len(self.get_findings_by_severity(SeverityLevel.MEDIUM)),
                'low': len(self.get_findings_by_severity(SeverityLevel.LOW)),
                'info': len(self.get_findings_by_severity(SeverityLevel.INFO)),
            },
            'findings': [f.to_dict() for f in self.findings],
            'errors': self.errors
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class VulnerabilityScanner:
    """
    Main vulnerability scanning engine for PennyWise.
    
    Orchestrates:
    - Target analysis
    - Attack selection
    - Payload injection and testing
    - Finding collection and classification
    """
    
    def __init__(self, 
                 config: Optional[PennywiseConfig] = None,
                 ai_model: Optional[AIModelInterface] = None,
                 on_finding: Optional[Callable[[Finding], None]] = None,
                 on_progress: Optional[Callable[[str, int, int], None]] = None):
        """
        Initialize the vulnerability scanner.
        
        Args:
            config: PennyWise configuration
            ai_model: AI model interface for enhanced analysis
            on_finding: Callback for real-time finding notifications
            on_progress: Callback for progress updates (message, current, total)
        """
        self.config = config or PennywiseConfig()
        self.ai_model = ai_model
        self.on_finding = on_finding
        self.on_progress = on_progress
        
        self.target_analyzer = TargetAnalyzer(self.config.scan)
        self.attack_selector = AttackSelector(ai_model, self.config.scan.scan_mode)
        
        self._finding_counter = 0
        self._session: Optional[aiohttp.ClientSession] = None
        
        logger.info("Vulnerability Scanner initialized")
    
    async def scan(self, 
                   url: str,
                   attack_types: Optional[List[AttackType]] = None,
                   crawl: bool = True) -> ScanResult:
        """
        Perform a complete vulnerability scan on the target.
        
        Args:
            url: Target URL to scan
            attack_types: Specific attack types to test (None = auto-select)
            crawl: Whether to crawl and discover additional pages
            
        Returns:
            ScanResult with all findings
        """
        result = ScanResult(
            target_url=url,
            scan_started=datetime.now(),
            status="running"
        )
        
        try:
            self._report_progress("Analyzing target...", 0, 100)
            
            # Phase 1: Target Analysis
            result.target_analysis = await self.target_analyzer.analyze(url)
            logger.info(f"Target analysis complete: {result.target_analysis.title}")
            
            self._report_progress("Creating attack strategy...", 10, 100)
            
            # Phase 2: Attack Selection
            user_prefs = {}
            if attack_types:
                user_prefs['allowed_attacks'] = attack_types
            
            result.attack_strategy = self.attack_selector.create_strategy(
                result.target_analysis,
                user_preferences=user_prefs
            )
            
            logger.info(f"Attack strategy created with {len(result.attack_strategy.attack_plans)} plans")
            
            # Phase 3: Execute Attacks
            self._report_progress("Executing attack plans...", 20, 100)
            
            async with aiohttp.ClientSession() as session:
                self._session = session
                
                # Set up session headers
                session.headers.update({
                    "User-Agent": self.config.scan.user_agent,
                    **self.config.scan.custom_headers
                })
                
                total_plans = len(result.attack_strategy.attack_plans)
                
                for idx, plan in enumerate(result.attack_strategy.get_ordered_attacks()):
                    progress = 20 + int((idx / total_plans) * 70)
                    self._report_progress(
                        f"Testing {plan.attack_type.value.upper()}...",
                        progress, 100
                    )
                    
                    plan_findings = await self._execute_attack_plan(plan, result)
                    result.findings.extend(plan_findings)
                    
                    # Notify about new findings
                    for finding in plan_findings:
                        self._notify_finding(finding)
                
                # Phase 4: Additional crawling if enabled
                if crawl:
                    self._report_progress("Crawling for additional pages...", 90, 100)
                    await self._crawl_and_scan(url, result)
            
            # Phase 5: AI-enhanced analysis
            if self.ai_model and result.findings:
                self._report_progress("Analyzing findings with AI...", 95, 100)
                await self._enhance_findings_with_ai(result)
            
            result.status = "completed"
            result.scan_completed = datetime.now()
            
            self._report_progress("Scan complete!", 100, 100)
            logger.info(f"Scan completed: {len(result.findings)} findings in {result.duration_seconds:.1f}s")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            result.status = "failed"
            result.errors.append(str(e))
            result.scan_completed = datetime.now()
        
        return result
    
    async def _execute_attack_plan(self, 
                                   plan: AttackPlan,
                                   result: ScanResult) -> List[Finding]:
        """Execute a single attack plan and return findings."""
        findings = []
        
        if plan.attack_type == AttackType.XSS:
            findings = await self._test_xss(plan, result)
        elif plan.attack_type == AttackType.SQLI:
            findings = await self._test_sqli(plan, result)
        elif plan.attack_type == AttackType.CSRF:
            findings = await self._test_csrf(plan, result)
        elif plan.attack_type == AttackType.AUTH:
            findings = await self._test_auth(plan, result)
        
        return findings
    
    async def _test_xss(self, plan: AttackPlan, result: ScanResult) -> List[Finding]:
        """Test for XSS vulnerabilities."""
        findings = []
        
        for vector in plan.vectors:
            for payload in plan.payloads:
                try:
                    # Inject payload
                    test_url = self._inject_payload(vector, payload)
                    
                    async with self._session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=self.config.scan.request_timeout),
                        ssl=False
                    ) as response:
                        result.requests_made += 1
                        html = await response.text()
                        
                        # Check for reflection
                        if self._check_reflection(html, payload):
                            finding = self._create_finding(
                                attack_type=AttackType.XSS,
                                severity=SeverityLevel.HIGH,
                                title=f"Reflected XSS in '{vector.parameter}'",
                                description=f"The payload was reflected in the response without proper encoding.",
                                url=test_url,
                                parameter=vector.parameter,
                                payload=payload,
                                evidence=self._extract_evidence(html, payload)
                            )
                            findings.append(finding)
                            
                        # Check DOM-based XSS patterns
                        dom_findings = self._check_dom_xss(html, vector.url)
                        findings.extend(dom_findings)
                        
                except Exception as e:
                    logger.debug(f"XSS test failed for {vector.url}: {e}")
                
                # Rate limiting
                await asyncio.sleep(self.config.scan.delay_between_requests)
        
        return findings
    
    async def _test_sqli(self, plan: AttackPlan, result: ScanResult) -> List[Finding]:
        """Test for SQL Injection vulnerabilities."""
        findings = []
        
        # Error patterns indicating SQL injection
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"ORA-\d{5}",
            r"Oracle.*error",
            r"Microsoft.*SQL.*Server",
            r"ODBC.*SQL.*Server",
            r"SQLite.*error",
            r"sqlite3\.OperationalError",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
        ]
        
        for vector in plan.vectors:
            baseline_response = None
            
            for payload in plan.payloads:
                try:
                    test_url = self._inject_payload(vector, payload)
                    
                    async with self._session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=self.config.scan.request_timeout),
                        ssl=False
                    ) as response:
                        result.requests_made += 1
                        html = await response.text()
                        
                        # Check for SQL error messages
                        for pattern in sql_errors:
                            if re.search(pattern, html, re.IGNORECASE):
                                finding = self._create_finding(
                                    attack_type=AttackType.SQLI,
                                    severity=SeverityLevel.CRITICAL,
                                    title=f"SQL Injection in '{vector.parameter}'",
                                    description="SQL error message detected in response, indicating possible SQL injection vulnerability.",
                                    url=test_url,
                                    parameter=vector.parameter,
                                    payload=payload,
                                    evidence=re.search(pattern, html, re.IGNORECASE).group(0)
                                )
                                findings.append(finding)
                                break
                        
                        # Blind SQLi detection (compare response sizes/times)
                        if baseline_response is None:
                            baseline_response = len(html)
                        else:
                            # Significant difference might indicate SQLi
                            if abs(len(html) - baseline_response) > baseline_response * 0.5:
                                if "' AND '1'='1" in payload or "' AND '1'='2" in payload:
                                    finding = self._create_finding(
                                        attack_type=AttackType.SQLI,
                                        severity=SeverityLevel.HIGH,
                                        title=f"Potential Blind SQL Injection in '{vector.parameter}'",
                                        description="Response size varies significantly with boolean SQLi payloads.",
                                        url=test_url,
                                        parameter=vector.parameter,
                                        payload=payload,
                                        confidence=0.6
                                    )
                                    findings.append(finding)
                        
                except Exception as e:
                    logger.debug(f"SQLi test failed for {vector.url}: {e}")
                
                await asyncio.sleep(self.config.scan.delay_between_requests)
        
        return findings
    
    async def _test_csrf(self, plan: AttackPlan, result: ScanResult) -> List[Finding]:
        """Test for CSRF vulnerabilities."""
        findings = []
        
        if not result.target_analysis:
            return findings
        
        for form in result.target_analysis.forms:
            if form.method.upper() == 'POST' and not form.has_csrf_token:
                finding = self._create_finding(
                    attack_type=AttackType.CSRF,
                    severity=SeverityLevel.MEDIUM,
                    title=f"Missing CSRF Protection on Form",
                    description=f"POST form at {form.action} does not have CSRF token protection.",
                    url=form.action,
                    recommendations=[
                        "Implement CSRF tokens for all state-changing requests",
                        "Use SameSite cookie attribute",
                        "Verify Origin/Referer headers"
                    ]
                )
                findings.append(finding)
        
        return findings
    
    async def _test_auth(self, plan: AttackPlan, result: ScanResult) -> List[Finding]:
        """Test for authentication vulnerabilities."""
        findings = []
        
        if not result.target_analysis:
            return findings
        
        # Check cookie security
        for cookie_name, cookie_value in result.target_analysis.cookies.items():
            # These checks are based on header analysis done earlier
            pass
        
        # Check for insecure session handling
        if not result.target_analysis.has_secure_cookies:
            finding = self._create_finding(
                attack_type=AttackType.AUTH,
                severity=SeverityLevel.MEDIUM,
                title="Insecure Cookie Configuration",
                description="Session cookies are missing security flags (HttpOnly, Secure, SameSite).",
                url=result.target_url,
                recommendations=[
                    "Set HttpOnly flag on session cookies",
                    "Set Secure flag for HTTPS sites",
                    "Set SameSite=Strict or SameSite=Lax"
                ]
            )
            findings.append(finding)
        
        return findings
    
    async def _crawl_and_scan(self, start_url: str, result: ScanResult):
        """Crawl the site and scan discovered pages for vulnerabilities."""
        seen = set()
        seen.add(start_url)  # Already scanned the main URL
        queue = deque()
        
        # First, get links from the initial page
        try:
            async with self._session.get(
                start_url,
                timeout=aiohttp.ClientTimeout(total=self.config.scan.request_timeout),
                ssl=False
            ) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Find links
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(start_url, link['href'].split('#')[0].split('?')[0])
                    parsed_start = urlparse(start_url)
                    parsed_next = urlparse(next_url)
                    
                    if parsed_start.netloc == parsed_next.netloc and next_url not in seen:
                        queue.append((next_url, 1))
                        
                # Find forms
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    form_url = urljoin(start_url, action)
                    if form_url not in seen:
                        queue.append((form_url, 1))
                        
        except Exception as e:
            logger.debug(f"Initial crawl failed: {e}")
        
        result.pages_scanned = 1
        
        # Crawl discovered pages
        while queue and result.pages_scanned < self.config.scan.max_pages:
            url, depth = queue.popleft()
            
            if url in seen or depth > self.config.scan.max_depth:
                continue
            
            seen.add(url)
            result.pages_scanned += 1
            
            try:
                async with self._session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.config.scan.request_timeout),
                    ssl=False
                ) as response:
                    result.requests_made += 1
                    
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' not in content_type:
                        continue
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Quick XSS scan on this page - test URL parameters
                    await self._quick_xss_scan(url, result)
                    
                    # Check for SQL injection on ID-like parameters
                    await self._quick_sqli_scan(url, result)
                    
                    # Find more links
                    for link in soup.find_all('a', href=True):
                        next_url = urljoin(url, link['href'].split('#')[0].split('?')[0])
                        parsed_start = urlparse(start_url)
                        parsed_next = urlparse(next_url)
                        
                        if parsed_start.netloc == parsed_next.netloc and next_url not in seen:
                            queue.append((next_url, depth + 1))
                    
                    # Log progress
                    if result.pages_scanned % 5 == 0:
                        logger.info(f"Crawled {result.pages_scanned} pages, found {len(result.findings)} vulnerabilities")
                    
            except Exception as e:
                logger.debug(f"Crawl failed for {url}: {e}")
            
            await asyncio.sleep(self.config.scan.delay_between_requests)
    
    async def _quick_xss_scan(self, url: str, result: ScanResult):
        """Quick XSS scan for a single URL with common parameters."""
        # Test XSS on common parameter names
        test_params = ['q', 'search', 'query', 'id', 'name']
        xss_payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param in test_params:
            for payload in xss_payloads:
                test_url = f"{base_url}?{param}={payload}"
                
                try:
                    async with self._session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as response:
                        result.requests_made += 1
                        html = await response.text()
                        
                        if payload in html:
                            finding = self._create_finding(
                                attack_type=AttackType.XSS,
                                severity=SeverityLevel.HIGH,
                                title=f"Reflected XSS in '{param}' parameter",
                                description=f"XSS payload reflected in response on {base_url}",
                                url=test_url,
                                parameter=param,
                                payload=payload,
                                evidence=self._extract_evidence(html, payload)
                            )
                            result.findings.append(finding)
                            self._notify_finding(finding)
                            return  # Found one, move on
                            
                except Exception as e:
                    logger.debug(f"Quick XSS scan failed: {e}")
                
                await asyncio.sleep(0.1)
    
    async def _quick_sqli_scan(self, url: str, result: ScanResult):
        """Quick SQLi scan for a single URL."""
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"SQLite.*error",
            r"Unclosed quotation mark",
        ]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        test_params = ['id', 'user', 'category', 'page']
        sqli_payloads = ["'", "1'", "1 OR 1=1", "' OR '1'='1"]
        
        for param in test_params:
            for payload in sqli_payloads:
                test_url = f"{base_url}?{param}={payload}"
                
                try:
                    async with self._session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as response:
                        result.requests_made += 1
                        html = await response.text()
                        
                        for pattern in sql_errors:
                            match = re.search(pattern, html, re.IGNORECASE)
                            if match:
                                finding = self._create_finding(
                                    attack_type=AttackType.SQLI,
                                    severity=SeverityLevel.CRITICAL,
                                    title=f"SQL Injection in '{param}' parameter",
                                    description=f"SQL error detected in response on {base_url}",
                                    url=test_url,
                                    parameter=param,
                                    payload=payload,
                                    evidence=match.group(0)
                                )
                                result.findings.append(finding)
                                self._notify_finding(finding)
                                return  # Found one, move on
                                
                except Exception as e:
                    logger.debug(f"Quick SQLi scan failed: {e}")
                
                await asyncio.sleep(0.1)
    
    async def _enhance_findings_with_ai(self, result: ScanResult):
        """Use AI to enhance and classify findings."""
        if not self.ai_model:
            return
        
        for finding in result.findings:
            try:
                # Get AI analysis
                vuln_data = {
                    'type': finding.attack_type.value,
                    'url': finding.url,
                    'parameter': finding.parameter,
                    'payload': finding.payload,
                    'evidence': finding.evidence
                }
                
                response = self.ai_model.analyze_vulnerability(vuln_data)
                
                if response.success:
                    data = response.data
                    
                    # Update finding with AI insights
                    if 'recommendations' in data:
                        finding.recommendations = data['recommendations']
                    
                    if 'severity' in data:
                        severity_map = {
                            'critical': SeverityLevel.CRITICAL,
                            'high': SeverityLevel.HIGH,
                            'medium': SeverityLevel.MEDIUM,
                            'low': SeverityLevel.LOW,
                            'info': SeverityLevel.INFO
                        }
                        finding.severity = severity_map.get(
                            data['severity'].lower(),
                            finding.severity
                        )
                    
            except Exception as e:
                logger.debug(f"AI enhancement failed for finding: {e}")
    
    def _inject_payload(self, vector: InputVector, payload: str) -> str:
        """Inject payload into the vector and return the test URL."""
        if vector.location == 'query':
            parsed = urlparse(vector.url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[vector.parameter] = [payload]
            new_query = urlencode(qs, doseq=True)
            return urlunparse(ParseResult(
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        return vector.url
    
    def _check_reflection(self, html: str, payload: str) -> bool:
        """Check if payload is reflected in the response."""
        # Simple reflection check
        if payload in html:
            return True
        
        # Check for encoded versions
        import html as html_lib
        if html_lib.escape(payload) != payload and html_lib.escape(payload) in html:
            return False  # Properly encoded, not vulnerable
        
        return False
    
    def _check_dom_xss(self, html: str, url: str) -> List[Finding]:
        """Check for DOM-based XSS patterns."""
        findings = []
        
        dom_patterns = [
            (r'innerHTML\s*=\s*[^;]+location', 'innerHTML with location'),
            (r'document\.write\s*\([^)]*location', 'document.write with location'),
            (r'eval\s*\([^)]*location', 'eval with location'),
        ]
        
        for pattern, desc in dom_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                finding = self._create_finding(
                    attack_type=AttackType.XSS,
                    severity=SeverityLevel.MEDIUM,
                    title=f"DOM-based XSS Pattern: {desc}",
                    description=f"Potentially dangerous DOM manipulation pattern detected.",
                    url=url,
                    confidence=0.5
                )
                findings.append(finding)
        
        return findings
    
    def _extract_evidence(self, html: str, payload: str, context_size: int = 100) -> str:
        """Extract evidence snippet around the payload in the response."""
        try:
            idx = html.find(payload)
            if idx == -1:
                return ""
            
            start = max(0, idx - context_size)
            end = min(len(html), idx + len(payload) + context_size)
            
            return html[start:end]
        except:
            return ""
    
    def _create_finding(self, **kwargs) -> Finding:
        """Create a new finding with auto-generated ID."""
        self._finding_counter += 1
        finding_id = f"PW-{self._finding_counter:04d}"
        return Finding(id=finding_id, **kwargs)
    
    def _report_progress(self, message: str, current: int, total: int):
        """Report progress via callback."""
        logger.info(f"Progress: {message} ({current}/{total})")
        if self.on_progress:
            self.on_progress(message, current, total)
    
    def _notify_finding(self, finding: Finding):
        """Notify about a new finding via callback."""
        logger.info(f"Finding: {finding.title} ({finding.severity.value})")
        if self.on_finding:
            self.on_finding(finding)
