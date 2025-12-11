"""
AI Analysis Functions for PennyWise.
Provides AI-powered analysis capabilities with stub implementations.

These functions are designed to be replaced with actual AI model calls.
Currently return intelligent mock responses based on heuristics.
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Types of vulnerabilities."""
    XSS = "xss"
    SQLI = "sqli"
    CSRF = "csrf"
    IDOR = "idor"
    AUTH = "auth"
    SSRF = "ssrf"
    RCE = "rce"
    LFI = "lfi"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"


@dataclass
class AttackRecommendation:
    """Recommendation for a specific attack type."""
    attack_type: VulnerabilityType
    probability: float  # 0.0 to 1.0
    confidence: float   # 0.0 to 1.0
    reasons: List[str] = field(default_factory=list)
    priority: int = 1   # 1 = highest


@dataclass
class SeverityClassification:
    """Classification of vulnerability severity."""
    severity: str  # Critical, High, Medium, Low, Info
    cvss_score: float
    impact: str
    exploitability: str
    remediation_priority: int


@dataclass
class RemediationSuggestion:
    """Suggested remediation for a vulnerability."""
    title: str
    description: str
    code_example: Optional[str] = None
    references: List[str] = field(default_factory=list)
    effort: str = "Medium"  # Low, Medium, High


class AIAnalyzer:
    """
    AI-powered analysis engine for vulnerability detection.
    
    This class provides intelligent analysis using heuristics and patterns.
    Methods are designed to be replaced with actual AI model calls.
    
    TODO: Replace stub implementations with actual Qwen model calls.
    """
    
    def __init__(self):
        """Initialize the AI analyzer."""
        self._technology_patterns = self._load_technology_patterns()
        self._vulnerability_indicators = self._load_vulnerability_indicators()
        logger.info("AI Analyzer initialized")
    
    def _load_technology_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for technology detection."""
        return {
            'php': [
                r'\.php[\?$]',
                r'PHPSESSID',
                r'X-Powered-By:\s*PHP',
                r'<\?php',
            ],
            'asp.net': [
                r'\.aspx?[\?$]',
                r'ASP\.NET',
                r'__VIEWSTATE',
                r'__EVENTVALIDATION',
            ],
            'java': [
                r'\.jsp[\?$]',
                r'JSESSIONID',
                r'\.do[\?$]',
                r'\.action[\?$]',
            ],
            'python': [
                r'\.py[\?$]',
                r'csrfmiddlewaretoken',  # Django
                r'Flask',
            ],
            'nodejs': [
                r'express',
                r'X-Powered-By:\s*Express',
                r'connect\.sid',
            ],
            'wordpress': [
                r'/wp-content/',
                r'/wp-admin/',
                r'/wp-includes/',
                r'WordPress',
            ],
            'react': [
                r'react',
                r'__NEXT_DATA__',
                r'_next/',
            ],
            'angular': [
                r'ng-',
                r'angular',
                r'\[ngModel\]',
            ],
        }
    
    def _load_vulnerability_indicators(self) -> Dict[str, Dict[str, Any]]:
        """Load indicators for vulnerability detection."""
        return {
            'xss': {
                'patterns': [
                    r'<input[^>]*>',
                    r'<textarea',
                    r'<form[^>]*>',
                    r'search',
                    r'query',
                    r'q=',
                    r'name=',
                    r'message=',
                ],
                'risky_params': ['q', 'search', 'query', 'name', 'message', 'text', 'input', 'keyword'],
                'weight': 0.8
            },
            'sqli': {
                'patterns': [
                    r'id=\d+',
                    r'user=',
                    r'SELECT',
                    r'category=',
                    r'sort=',
                    r'order=',
                    r'\.php\?.*id=',
                ],
                'risky_params': ['id', 'user_id', 'product_id', 'cat', 'category', 'sort', 'order', 'page'],
                'weight': 0.9
            },
            'csrf': {
                'patterns': [
                    r'<form[^>]*method=["\']?post',
                    r'action=',
                    r'transfer',
                    r'delete',
                    r'update',
                ],
                'negative_patterns': ['csrf', 'token', '_token', 'authenticity'],
                'weight': 0.6
            },
            'idor': {
                'patterns': [
                    r'id=\d+',
                    r'user_id=',
                    r'account=',
                    r'profile=',
                    r'doc_id=',
                    r'/users/\d+',
                    r'/api/.*\d+',
                ],
                'weight': 0.7
            },
            'auth': {
                'patterns': [
                    r'login',
                    r'signin',
                    r'password',
                    r'auth',
                    r'session',
                ],
                'weight': 0.5
            },
            'rce': {
                'patterns': [
                    r'cmd=',
                    r'exec=',
                    r'command=',
                    r'ping',
                    r'host=',
                    r'file=',
                ],
                'weight': 0.95
            },
        }
    
    def analyze_target(self, 
                       url: str, 
                       html: str, 
                       headers: Dict[str, str] = None) -> List[AttackRecommendation]:
        """
        Analyze a target and recommend attacks based on detected patterns.
        
        TODO: Replace with actual AI model call.
        
        Args:
            url: Target URL
            html: HTML content of the page
            headers: Response headers
            
        Returns:
            List of AttackRecommendation sorted by priority
        """
        recommendations = []
        headers = headers or {}
        
        # Detect technologies
        technologies = self._detect_technologies(url, html, headers)
        
        # Analyze for each vulnerability type
        for vuln_type, indicators in self._vulnerability_indicators.items():
            probability = self._calculate_vulnerability_probability(
                vuln_type, url, html, headers, indicators
            )
            
            if probability > 0.3:  # Threshold for recommendation
                reasons = self._generate_reasons(vuln_type, url, html, indicators)
                
                recommendations.append(AttackRecommendation(
                    attack_type=VulnerabilityType(vuln_type),
                    probability=probability,
                    confidence=min(probability + 0.1, 1.0),
                    reasons=reasons,
                    priority=self._calculate_priority(probability)
                ))
        
        # Sort by probability (descending)
        recommendations.sort(key=lambda r: r.probability, reverse=True)
        
        logger.info(f"AI Analysis: Recommended {len(recommendations)} attack types for {url}")
        return recommendations
    
    def _detect_technologies(self, 
                            url: str, 
                            html: str, 
                            headers: Dict[str, str]) -> List[str]:
        """Detect technologies used by the target."""
        detected = []
        combined = url + html + str(headers)
        
        for tech, patterns in self._technology_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.append(tech)
                    break
        
        return detected
    
    def _calculate_vulnerability_probability(self,
                                            vuln_type: str,
                                            url: str,
                                            html: str,
                                            headers: Dict[str, str],
                                            indicators: Dict[str, Any]) -> float:
        """Calculate probability of a vulnerability type existing."""
        combined = url.lower() + html.lower()
        score = 0.0
        matches = 0
        
        # Check positive patterns
        for pattern in indicators.get('patterns', []):
            if re.search(pattern, combined, re.IGNORECASE):
                score += 0.15
                matches += 1
        
        # Check risky parameters in URL
        parsed_url = urlparse(url)
        query = parsed_url.query.lower()
        for param in indicators.get('risky_params', []):
            if param in query:
                score += 0.2
                matches += 1
        
        # Check negative patterns (reduce score if security measures found)
        for pattern in indicators.get('negative_patterns', []):
            if re.search(pattern, combined, re.IGNORECASE):
                score -= 0.3
        
        # Apply weight
        score *= indicators.get('weight', 0.5)
        
        # Normalize to 0-1 range
        return min(max(score, 0.0), 1.0)
    
    def _generate_reasons(self,
                         vuln_type: str,
                         url: str,
                         html: str,
                         indicators: Dict[str, Any]) -> List[str]:
        """Generate reasons for the vulnerability recommendation."""
        reasons = []
        combined = url.lower() + html.lower()
        
        reason_templates = {
            'xss': [
                "User input fields detected without visible sanitization",
                "Search/query parameters found in URL",
                "Form inputs that may reflect user data",
            ],
            'sqli': [
                "Numeric ID parameters detected in URL",
                "Database-driven content patterns found",
                "Dynamic query parameters present",
            ],
            'csrf': [
                "POST forms detected without CSRF tokens",
                "State-changing operations without protection",
                "Missing anti-CSRF mechanisms",
            ],
            'idor': [
                "Object IDs exposed in URL parameters",
                "User-specific resource access patterns",
                "Direct object references in API endpoints",
            ],
            'auth': [
                "Login/authentication forms detected",
                "Session management endpoints found",
                "Password-related functionality present",
            ],
            'rce': [
                "Command execution parameters detected",
                "System utility endpoints found",
                "Potential shell command injection points",
            ],
        }
        
        templates = reason_templates.get(vuln_type, ["Potential vulnerability indicators found"])
        
        # Add relevant reasons based on what was actually found
        for pattern in indicators.get('patterns', [])[:2]:
            if re.search(pattern, combined, re.IGNORECASE):
                if templates:
                    reasons.append(templates.pop(0))
        
        if not reasons:
            reasons = templates[:2]
        
        return reasons
    
    def _calculate_priority(self, probability: float) -> int:
        """Calculate priority based on probability."""
        if probability >= 0.8:
            return 1
        elif probability >= 0.6:
            return 2
        elif probability >= 0.4:
            return 3
        else:
            return 4
    
    def classify_severity(self, finding: Dict[str, Any]) -> SeverityClassification:
        """
        Classify the severity of a vulnerability finding.
        
        TODO: Replace with actual AI model call.
        
        Args:
            finding: Vulnerability finding data
            
        Returns:
            SeverityClassification with severity details
        """
        vuln_type = finding.get('attack_type', '').lower()
        payload = finding.get('payload', '')
        evidence = finding.get('evidence', '')
        
        # Severity mapping based on vulnerability type and context
        severity_map = {
            'sqli': ('Critical', 9.8, 'Complete database compromise possible'),
            'rce': ('Critical', 10.0, 'Remote code execution possible'),
            'xss': ('High', 7.5, 'Client-side code execution and session hijacking'),
            'idor': ('High', 7.0, 'Unauthorized access to sensitive data'),
            'csrf': ('Medium', 6.0, 'Unauthorized actions on behalf of users'),
            'auth': ('Medium', 6.5, 'Authentication bypass possible'),
            'ssrf': ('High', 8.0, 'Server-side request forgery'),
            'lfi': ('High', 7.5, 'Local file inclusion'),
        }
        
        default = ('Medium', 5.0, 'Security vulnerability detected')
        severity_info = severity_map.get(vuln_type, default)
        
        # Adjust based on evidence
        cvss_adjustment = 0.0
        if 'admin' in evidence.lower() or 'password' in evidence.lower():
            cvss_adjustment += 0.5
        if 'error' in evidence.lower() or 'exception' in evidence.lower():
            cvss_adjustment += 0.3
        
        return SeverityClassification(
            severity=severity_info[0],
            cvss_score=min(severity_info[1] + cvss_adjustment, 10.0),
            impact=severity_info[2],
            exploitability="Easy" if severity_info[1] >= 8.0 else "Moderate",
            remediation_priority=1 if severity_info[1] >= 8.0 else 2
        )
    
    def suggest_remediation(self, finding: Dict[str, Any]) -> List[RemediationSuggestion]:
        """
        Suggest remediation steps for a vulnerability.
        
        TODO: Replace with actual AI model call.
        
        Args:
            finding: Vulnerability finding data
            
        Returns:
            List of RemediationSuggestion with fix recommendations
        """
        vuln_type = finding.get('attack_type', '').lower()
        
        remediation_db = {
            'xss': [
                RemediationSuggestion(
                    title="Implement Output Encoding",
                    description="Encode all user-supplied data before rendering in HTML context.",
                    code_example='''# Python/Flask example
from markupsafe import escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"Results for: {escape(query)}"''',
                    references=[
                        "https://owasp.org/www-community/xss-filter-evasion-cheatsheet",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                    ],
                    effort="Low"
                ),
                RemediationSuggestion(
                    title="Implement Content Security Policy",
                    description="Add CSP headers to prevent inline script execution.",
                    code_example='''Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';''',
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    effort="Medium"
                ),
            ],
            'sqli': [
                RemediationSuggestion(
                    title="Use Parameterized Queries",
                    description="Never concatenate user input directly into SQL queries. Use parameterized queries or prepared statements.",
                    code_example='''# Python example - VULNERABLE
query = f"SELECT * FROM users WHERE id = {user_id}"

# SECURE - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))''',
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                    ],
                    effort="Medium"
                ),
                RemediationSuggestion(
                    title="Use an ORM",
                    description="Use an Object-Relational Mapper (ORM) like SQLAlchemy or Django ORM to abstract database queries.",
                    code_example='''# SQLAlchemy example
user = session.query(User).filter(User.id == user_id).first()''',
                    references=["https://docs.sqlalchemy.org/"],
                    effort="High"
                ),
            ],
            'csrf': [
                RemediationSuggestion(
                    title="Implement CSRF Tokens",
                    description="Add CSRF tokens to all state-changing forms and validate them on the server.",
                    code_example='''# Flask-WTF example
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# In template:
<form method="post">
    {{ csrf_token() }}
    ...
</form>''',
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
                    effort="Low"
                ),
            ],
            'idor': [
                RemediationSuggestion(
                    title="Implement Access Control Checks",
                    description="Verify that the authenticated user has permission to access the requested resource.",
                    code_example='''# Check ownership before returning data
def get_document(doc_id, current_user):
    doc = Document.query.get(doc_id)
    if doc.owner_id != current_user.id:
        raise Forbidden("Access denied")
    return doc''',
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"],
                    effort="Medium"
                ),
            ],
            'auth': [
                RemediationSuggestion(
                    title="Use Strong Password Hashing",
                    description="Hash passwords using bcrypt, Argon2, or PBKDF2 with appropriate work factors.",
                    code_example='''# Using bcrypt
import bcrypt

# Hashing
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Verifying
if bcrypt.checkpw(password.encode(), hashed):
    print("Password matches!")''',
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"],
                    effort="Low"
                ),
                RemediationSuggestion(
                    title="Implement Secure Session Management",
                    description="Use secure, HttpOnly, SameSite cookies for session management.",
                    code_example='''response.set_cookie(
    'session',
    value=session_token,
    httponly=True,
    secure=True,
    samesite='Strict'
)''',
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
                    effort="Low"
                ),
            ],
            'rce': [
                RemediationSuggestion(
                    title="Avoid System Commands",
                    description="Never execute system commands with user input. Use native libraries instead.",
                    code_example='''# VULNERABLE
os.system(f"ping {user_input}")

# SECURE - Use Python library
import socket
socket.gethostbyname(hostname)''',
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
                    effort="Medium"
                ),
            ],
        }
        
        default_remediation = [
            RemediationSuggestion(
                title="Review Security Best Practices",
                description="Review and implement OWASP security guidelines for your application.",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                effort="Medium"
            )
        ]
        
        return remediation_db.get(vuln_type, default_remediation)
    
    def generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary analysis of all findings.
        
        TODO: Replace with actual AI model call.
        
        Args:
            findings: List of all vulnerability findings
            
        Returns:
            Summary dictionary with analysis
        """
        if not findings:
            return {
                'overall_risk': 'Low',
                'summary': 'No vulnerabilities detected.',
                'recommendations': ['Continue regular security testing.'],
            }
        
        # Count by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        vuln_types = set()
        
        for finding in findings:
            severity = finding.get('severity', 'Medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            vuln_types.add(finding.get('attack_type', 'unknown'))
        
        # Determine overall risk
        if severity_counts['Critical'] > 0:
            overall_risk = 'Critical'
        elif severity_counts['High'] > 0:
            overall_risk = 'High'
        elif severity_counts['Medium'] > 0:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'
        
        # Generate summary text
        total = len(findings)
        summary_parts = [
            f"Detected {total} security {'vulnerability' if total == 1 else 'vulnerabilities'}.",
        ]
        
        if severity_counts['Critical'] > 0:
            summary_parts.append(f"{severity_counts['Critical']} critical issues require immediate attention.")
        
        summary_parts.append(f"Affected vulnerability types: {', '.join(vuln_types).upper()}")
        
        # Generate recommendations
        recommendations = []
        if 'sqli' in vuln_types:
            recommendations.append("URGENT: Implement parameterized queries to prevent SQL injection.")
        if 'xss' in vuln_types:
            recommendations.append("Implement output encoding and Content Security Policy headers.")
        if 'csrf' in vuln_types:
            recommendations.append("Add CSRF token protection to all state-changing forms.")
        if 'rce' in vuln_types:
            recommendations.append("CRITICAL: Remove or sanitize all command execution functionality.")
        
        recommendations.append("Conduct a comprehensive security audit of the application.")
        recommendations.append("Implement a Web Application Firewall (WAF) as an additional layer of protection.")
        
        return {
            'overall_risk': overall_risk,
            'summary': ' '.join(summary_parts),
            'total_findings': total,
            'severity_breakdown': severity_counts,
            'vulnerability_types': list(vuln_types),
            'recommendations': recommendations,
        }


# Global instance
_ai_analyzer: Optional[AIAnalyzer] = None


def get_ai_analyzer() -> AIAnalyzer:
    """Get the global AI analyzer instance."""
    global _ai_analyzer
    if _ai_analyzer is None:
        _ai_analyzer = AIAnalyzer()
    return _ai_analyzer
