"""
Target Analyzer for PennyWise.
Performs comprehensive analysis of target websites to determine attack vectors.
"""

import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
import logging
import re
from enum import Enum

from ..config import AttackType, ScanConfig

logger = logging.getLogger(__name__)


class TechnologyType(Enum):
    """Detected technology types."""
    PHP = "php"
    ASP_NET = "asp.net"
    JAVA = "java"
    PYTHON = "python"
    NODEJS = "nodejs"
    ANGULAR = "angular"
    REACT = "react"
    VUE = "vue"
    WORDPRESS = "wordpress"
    DJANGO = "django"
    FLASK = "flask"
    LARAVEL = "laravel"
    UNKNOWN = "unknown"


@dataclass
class FormInfo:
    """Information about a detected form."""
    url: str
    action: str
    method: str
    fields: Dict[str, Dict[str, str]]  # field_name -> {type, value}
    has_csrf_token: bool = False
    is_login_form: bool = False
    is_search_form: bool = False
    is_file_upload: bool = False


@dataclass
class InputVector:
    """Potential input vector for testing."""
    url: str
    parameter: str
    location: str  # query, body, header, cookie
    current_value: Optional[str] = None
    suspected_type: Optional[str] = None  # id, search, filter, etc.
    method: str = "GET"  # HTTP method


@dataclass
class TargetAnalysis:
    """Complete analysis of a target website."""
    url: str
    base_url: str
    title: str
    
    # Technology detection
    technologies: List[TechnologyType] = field(default_factory=list)
    server: Optional[str] = None
    framework: Optional[str] = None
    
    # Structure analysis
    forms: List[FormInfo] = field(default_factory=list)
    input_vectors: List[InputVector] = field(default_factory=list)
    endpoints: Set[str] = field(default_factory=set)
    parameters_found: Set[str] = field(default_factory=set)
    
    # Security indicators
    has_csrf_protection: bool = False
    has_csp_header: bool = False
    has_xss_protection: bool = False
    has_secure_cookies: bool = False
    uses_https: bool = False
    
    # Content analysis
    has_database_content: bool = False
    has_user_content: bool = False
    has_file_upload: bool = False
    has_authentication: bool = False
    has_api_endpoints: bool = False
    
    # Vulnerability indicators
    potential_sqli: float = 0.0
    potential_xss: float = 0.0
    potential_csrf: float = 0.0
    potential_auth_issues: float = 0.0
    
    # Raw data
    html_sample: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    
    def get_recommended_attacks(self) -> List[Dict[str, Any]]:
        """Generate attack recommendations based on analysis."""
        recommendations = []
        
        # XSS recommendations
        if self.potential_xss > 0.3:
            priority = "high" if self.potential_xss > 0.7 else "medium"
            reasons = []
            if self.has_user_content:
                reasons.append("User-generated content detected")
            if any(f.is_search_form for f in self.forms):
                reasons.append("Search functionality present")
            if not self.has_csp_header:
                reasons.append("Missing Content-Security-Policy")
            
            recommendations.append({
                "attack_type": AttackType.XSS,
                "priority": priority,
                "confidence": self.potential_xss,
                "reasons": reasons,
                "vectors": [v for v in self.input_vectors if v.location in ["query", "body"]]
            })
        
        # SQLi recommendations
        if self.potential_sqli > 0.3:
            priority = "high" if self.potential_sqli > 0.7 else "medium"
            reasons = []
            if self.has_database_content:
                reasons.append("Database-backed content detected")
            if any(v.suspected_type == "id" for v in self.input_vectors):
                reasons.append("ID parameters in URLs")
            if 'php' in str(self.technologies).lower():
                reasons.append("PHP technology detected (common SQLi target)")
            
            recommendations.append({
                "attack_type": AttackType.SQLI,
                "priority": priority,
                "confidence": self.potential_sqli,
                "reasons": reasons,
                "vectors": [v for v in self.input_vectors if v.suspected_type in ["id", "filter", "search"]]
            })
        
        # CSRF recommendations
        if self.potential_csrf > 0.3:
            priority = "high" if self.potential_csrf > 0.7 else "medium"
            reasons = []
            if not self.has_csrf_protection:
                reasons.append("No CSRF tokens detected")
            if any(f.method.lower() == "post" and not f.has_csrf_token for f in self.forms):
                reasons.append("POST forms without CSRF protection")
            
            recommendations.append({
                "attack_type": AttackType.CSRF,
                "priority": priority,
                "confidence": self.potential_csrf,
                "reasons": reasons,
                "vectors": [f for f in self.forms if f.method.lower() == "post"]
            })
        
        # Auth recommendations
        if self.potential_auth_issues > 0.3:
            priority = "high" if self.potential_auth_issues > 0.7 else "medium"
            reasons = []
            if not self.has_secure_cookies:
                reasons.append("Insecure cookie settings")
            if self.has_authentication:
                reasons.append("Authentication forms present")
            
            recommendations.append({
                "attack_type": AttackType.AUTH,
                "priority": priority,
                "confidence": self.potential_auth_issues,
                "reasons": reasons
            })
        
        # Sort by confidence
        recommendations.sort(key=lambda x: x['confidence'], reverse=True)
        return recommendations


class TargetAnalyzer:
    """
    Analyzes target websites to determine optimal attack strategies.
    
    Performs:
    - Technology fingerprinting
    - Form and input vector detection
    - Security header analysis
    - Vulnerability indicator scoring
    """
    
    def __init__(self, config: Optional[ScanConfig] = None):
        """Initialize the target analyzer."""
        self.config = config or ScanConfig()
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Patterns for detection
        self._tech_patterns = {
            TechnologyType.PHP: [r'\.php', r'PHPSESSID'],
            TechnologyType.ASP_NET: [r'\.aspx?', r'ASP\.NET', r'__VIEWSTATE'],
            TechnologyType.JAVA: [r'\.jsp', r'JSESSIONID', r'\.do$'],
            TechnologyType.NODEJS: [r'express', r'node'],
            TechnologyType.ANGULAR: [r'ng-app', r'ng-model', r'angular\.js'],
            TechnologyType.REACT: [r'react', r'_reactRoot'],
            TechnologyType.VUE: [r'v-bind', r'v-model', r'vue\.js'],
            TechnologyType.WORDPRESS: [r'wp-content', r'wp-includes', r'wordpress'],
            TechnologyType.DJANGO: [r'csrfmiddlewaretoken', r'django'],
            TechnologyType.FLASK: [r'flask', r'werkzeug'],
            TechnologyType.LARAVEL: [r'laravel', r'XSRF-TOKEN']
        }
        
        self._sqli_indicators = [
            r'id=\d+', r'product_id', r'user_id', r'category=',
            r'order_by', r'sort=', r'filter=', r'search='
        ]
        
        self._xss_indicators = [
            r'<form.*>.*</form>', r'search', r'comment', r'message',
            r'name=', r'input.*text', r'textarea'
        ]
    
    async def analyze(self, url: str) -> TargetAnalysis:
        """
        Perform comprehensive analysis of target URL.
        
        Args:
            url: Target URL to analyze
            
        Returns:
            TargetAnalysis with all findings
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        analysis = TargetAnalysis(
            url=url,
            base_url=base_url,
            title="",
            uses_https=parsed.scheme == "https"
        )
        
        try:
            async with aiohttp.ClientSession() as session:
                self.session = session
                
                # Fetch main page
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.config.request_timeout),
                    headers={"User-Agent": self.config.user_agent},
                    ssl=False  # For testing
                ) as response:
                    html = await response.text()
                    analysis.html_sample = html[:10000]
                    analysis.headers = dict(response.headers)
                    
                    # Parse cookies
                    for cookie in response.cookies.values():
                        analysis.cookies[cookie.key] = cookie.value
                    
                    # Analyze response
                    self._analyze_headers(response, analysis)
                    self._analyze_html(html, url, analysis)
                    self._detect_technologies(html, analysis)
                    self._calculate_vulnerability_scores(analysis)
                
        except Exception as e:
            logger.error(f"Failed to analyze {url}: {e}")
        
        return analysis
    
    def _analyze_headers(self, response: aiohttp.ClientResponse, analysis: TargetAnalysis):
        """Analyze response headers for security indicators."""
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Server detection
        analysis.server = headers.get('server', 'Unknown')
        
        # Security headers
        analysis.has_csp_header = 'content-security-policy' in headers
        analysis.has_xss_protection = 'x-xss-protection' in headers
        
        # Cookie security
        set_cookie = headers.get('set-cookie', '')
        analysis.has_secure_cookies = all([
            'httponly' in set_cookie.lower() if set_cookie else True,
            'secure' in set_cookie.lower() if set_cookie else True
        ])
    
    def _analyze_html(self, html: str, base_url: str, analysis: TargetAnalysis):
        """Analyze HTML content for forms, inputs, and patterns."""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Get title
        title_tag = soup.find('title')
        analysis.title = title_tag.string.strip() if title_tag and title_tag.string else "No title"
        
        # Analyze forms
        for form in soup.find_all('form'):
            form_info = self._parse_form(form, base_url)
            analysis.forms.append(form_info)
            
            # Check for CSRF protection
            if form_info.has_csrf_token:
                analysis.has_csrf_protection = True
            
            # Add form fields as input vectors
            for field_name, field_info in form_info.fields.items():
                analysis.input_vectors.append(InputVector(
                    url=form_info.action,
                    parameter=field_name,
                    location="body",
                    current_value=field_info.get('value'),
                    suspected_type=self._guess_parameter_type(field_name)
                ))
        
        # Find URL parameters
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            
            if parsed.query:
                analysis.endpoints.add(parsed.path)
                for param, values in parse_qs(parsed.query).items():
                    analysis.parameters_found.add(param)
                    analysis.input_vectors.append(InputVector(
                        url=full_url,
                        parameter=param,
                        location="query",
                        current_value=values[0] if values else None,
                        suspected_type=self._guess_parameter_type(param)
                    ))
        
        # Content indicators
        analysis.has_user_content = bool(soup.find_all(['comment', 'review', 'message']))
        analysis.has_file_upload = bool(soup.find('input', {'type': 'file'}))
        analysis.has_authentication = bool(soup.find('input', {'type': 'password'}))
        
        # Database content indicators
        db_patterns = [r'id=\d+', r'page=\d+', r'product', r'user', r'article']
        html_lower = html.lower()
        analysis.has_database_content = any(re.search(p, html_lower) for p in db_patterns)
        
        # API indicators
        api_patterns = [r'/api/', r'/v1/', r'/v2/', r'json', r'graphql']
        analysis.has_api_endpoints = any(re.search(p, html_lower) for p in api_patterns)
    
    def _parse_form(self, form, base_url: str) -> FormInfo:
        """Parse a form element into FormInfo."""
        action = form.get('action', '')
        full_action = urljoin(base_url, action) if action else base_url
        method = form.get('method', 'get').upper()
        
        fields = {}
        has_csrf = False
        is_login = False
        is_search = False
        has_file = False
        
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if not name:
                continue
            
            input_type = inp.get('type', 'text').lower()
            value = inp.get('value', '')
            
            fields[name] = {
                'type': input_type,
                'value': value
            }
            
            # Detect CSRF token
            csrf_names = ['csrf', 'token', '_token', 'csrfmiddlewaretoken', '__requestverificationtoken']
            if any(csrf in name.lower() for csrf in csrf_names):
                has_csrf = True
            
            # Detect login form
            if input_type == 'password':
                is_login = True
            
            # Detect search form
            if 'search' in name.lower() or 'query' in name.lower() or 'q' == name.lower():
                is_search = True
            
            # Detect file upload
            if input_type == 'file':
                has_file = True
        
        return FormInfo(
            url=base_url,
            action=full_action,
            method=method,
            fields=fields,
            has_csrf_token=has_csrf,
            is_login_form=is_login,
            is_search_form=is_search,
            is_file_upload=has_file
        )
    
    def _detect_technologies(self, html: str, analysis: TargetAnalysis):
        """Detect technologies used by the target."""
        html_lower = html.lower()
        headers_str = str(analysis.headers).lower()
        
        for tech, patterns in self._tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE) or \
                   re.search(pattern, headers_str, re.IGNORECASE):
                    if tech not in analysis.technologies:
                        analysis.technologies.append(tech)
                    break
        
        if not analysis.technologies:
            analysis.technologies.append(TechnologyType.UNKNOWN)
    
    def _guess_parameter_type(self, param_name: str) -> str:
        """Guess the purpose of a parameter based on its name."""
        param_lower = param_name.lower()
        
        if any(x in param_lower for x in ['id', 'uid', 'pid', 'cid']):
            return 'id'
        elif any(x in param_lower for x in ['search', 'query', 'q', 'keyword']):
            return 'search'
        elif any(x in param_lower for x in ['filter', 'category', 'type', 'sort']):
            return 'filter'
        elif any(x in param_lower for x in ['page', 'offset', 'limit']):
            return 'pagination'
        elif any(x in param_lower for x in ['user', 'username', 'email']):
            return 'user_input'
        elif any(x in param_lower for x in ['url', 'redirect', 'next', 'return']):
            return 'redirect'
        else:
            return 'unknown'
    
    def _calculate_vulnerability_scores(self, analysis: TargetAnalysis):
        """Calculate vulnerability potential scores based on analysis."""
        
        # XSS score
        xss_score = 0.0
        if any(f.is_search_form for f in analysis.forms):
            xss_score += 0.3
        if not analysis.has_csp_header:
            xss_score += 0.2
        if not analysis.has_xss_protection:
            xss_score += 0.1
        if analysis.has_user_content:
            xss_score += 0.3
        if len([v for v in analysis.input_vectors if v.location in ['query', 'body']]) > 0:
            xss_score += 0.2
        analysis.potential_xss = min(xss_score, 1.0)
        
        # SQLi score
        sqli_score = 0.0
        if analysis.has_database_content:
            sqli_score += 0.3
        if any(v.suspected_type == 'id' for v in analysis.input_vectors):
            sqli_score += 0.4
        if any(t in [TechnologyType.PHP, TechnologyType.ASP_NET] for t in analysis.technologies):
            sqli_score += 0.2
        if any(v.suspected_type == 'filter' for v in analysis.input_vectors):
            sqli_score += 0.2
        analysis.potential_sqli = min(sqli_score, 1.0)
        
        # CSRF score
        csrf_score = 0.0
        post_forms = [f for f in analysis.forms if f.method.upper() == 'POST']
        if post_forms:
            unprotected = [f for f in post_forms if not f.has_csrf_token]
            if unprotected:
                csrf_score += 0.5 * (len(unprotected) / len(post_forms))
        if not analysis.has_csrf_protection:
            csrf_score += 0.3
        analysis.potential_csrf = min(csrf_score, 1.0)
        
        # Auth issues score
        auth_score = 0.0
        if not analysis.has_secure_cookies:
            auth_score += 0.3
        if analysis.has_authentication:
            auth_score += 0.2
            if not analysis.uses_https:
                auth_score += 0.4
        analysis.potential_auth_issues = min(auth_score, 1.0)
