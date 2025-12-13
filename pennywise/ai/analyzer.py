"""
AI Analysis Functions for PennyWise.
Provides AI-powered analysis capabilities using the Qwen model.
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

from ..config import AttackType
from .ai_logger import get_ai_logger
from .model_interface import AIModelInterface

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
    attack_type: AttackType
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
    
    This class provides intelligent analysis using the Qwen AI model
    combined with pattern-based heuristics for enhanced accuracy.
    """
    
    def __init__(self):
        """Initialize the AI analyzer."""
        self._technology_patterns = self._load_technology_patterns()
        self._vulnerability_indicators = self._load_vulnerability_indicators()
        self.ai_logger = get_ai_logger()
        self.ai_model = AIModelInterface()  # Initialize AI model
        logger.info("AI Analyzer initialized with Qwen model")
    
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
                    r'email=',
                    r'username=',
                    r'password=',
                    r'comment',
                    r'feedback',
                    r'contact',
                    r'login',
                    r'auth',
                    r'/api/',
                    r'/rest/',
                    r'json',
                    r'application/json',
                ],
                'risky_params': ['q', 'search', 'query', 'name', 'message', 'text', 'input', 'keyword', 'email', 'username', 'password', 'id', 'user_id'],
                'weight': 0.9  # Increased weight
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
        Analyze a target and recommend attacks using AI-powered analysis.
        
        Uses the Qwen AI model to analyze the target and recommend attack types
        based on detected patterns and AI reasoning.
        
        Args:
            url: Target URL
            html: HTML content of the page
            headers: Response headers
            
        Returns:
            List of AttackRecommendation sorted by priority
        """
        import time
        start_time = time.time()
        
        recommendations = []
        headers = headers or {}
        
        # Detect technologies using pattern matching
        technologies = self._detect_technologies(url, html, headers)
        
        # Use AI model to analyze the target and get recommendations
        try:
            ai_analysis_prompt = f"""Analyze this web target for potential security vulnerabilities:

URL: {url}
Technologies Detected: {', '.join(technologies) if technologies else 'Unknown'}
HTML Content (first 2000 chars): {html[:2000]}...
Response Headers: {headers}

Based on the URL, HTML content, and headers, recommend which types of attacks should be tested.
Consider the technologies used and common vulnerabilities for those technologies.

Respond with a JSON object containing:
- recommended_attacks: array of attack types (xss, sqli, csrf, idor, auth, rce, ssrf, lfi, xxe, open_redirect)
- reasoning: brief explanation for each recommendation
- confidence_levels: object mapping attack types to confidence scores (0.0-1.0)

Example response:
{{
  "recommended_attacks": ["xss", "sqli", "csrf"],
  "reasoning": "The target has user input forms and database-driven content",
  "confidence_levels": {{"xss": 0.8, "sqli": 0.7, "csrf": 0.6}}
}}"""

            ai_response = self.ai_model._generate_response(ai_analysis_prompt)
            
            # Parse AI response
            try:
                # Extract JSON from response
                json_start = ai_response.find('{')
                json_end = ai_response.rfind('}') + 1
                if json_start != -1 and json_end > json_start:
                    json_str = ai_response[json_start:json_end]
                    ai_data = json.loads(json_str)
                    
                    # Process AI recommendations
                    recommended_attacks = ai_data.get('recommended_attacks', [])
                    confidence_levels = ai_data.get('confidence_levels', {})
                    reasoning = ai_data.get('reasoning', 'AI analysis completed')
                    
                    for attack_type in recommended_attacks:
                        if attack_type in self._vulnerability_indicators:
                            confidence = confidence_levels.get(attack_type, 0.7)
                            recommendations.append(AttackRecommendation(
                                attack_type=AttackType(attack_type),
                                probability=min(confidence + 0.1, 1.0),
                                confidence=min(confidence + 0.2, 1.0),
                                reasons=[reasoning, f"AI confidence: {confidence:.1f}"],
                                priority=self._calculate_priority(confidence)
                            ))
                else:
                    # Fallback to heuristic analysis if AI parsing fails
                    logger.warning("AI response parsing failed, falling back to heuristics")
                    recommendations = self._heuristic_analysis(url, html, headers, technologies)
                    
            except Exception as e:
                logger.error(f"AI analysis failed: {e}, falling back to heuristics")
                recommendations = self._heuristic_analysis(url, html, headers, technologies)
                
        except Exception as e:
            logger.error(f"AI model call failed: {e}, falling back to heuristics")
            recommendations = self._heuristic_analysis(url, html, headers, technologies)
        
        # If no recommendations found, provide default web app attacks
        if not recommendations:
            default_attacks = ['xss', 'sqli', 'csrf']
            for attack in default_attacks:
                if attack in self._vulnerability_indicators:
                    recommendations.append(AttackRecommendation(
                        attack_type=AttackType(attack),
                        probability=0.6,
                        confidence=0.7,
                        reasons=["Default recommendation for web applications"],
                        priority=2
                    ))
        
        # Sort by probability (descending)
        recommendations.sort(key=lambda r: r.probability, reverse=True)
        
        # Calculate analysis confidence
        avg_probability = sum(r.probability for r in recommendations) / len(recommendations) if recommendations else 0
        
        # Log the analysis
        recommended_attacks = [
            {
                "attack_type": r.attack_type.value,
                "probability": r.probability,
                "confidence": r.confidence,
                "priority": r.priority,
                "reasons": r.reasons
            } for r in recommendations
        ]
        
        analysis_time = (time.time() - start_time) * 1000
        self.ai_logger.log_pattern_analysis(
            target_url=url,
            patterns_found={"ai_recommendations": len(recommendations), "technologies": technologies},
            vulnerability_scores={r.attack_type.value: r.probability for r in recommendations},
            analysis_time_ms=analysis_time
        )
        
        self.ai_logger.log_attack_recommendation(
            target_url=url,
            recommended_attacks=recommended_attacks,
            analysis_confidence=avg_probability,
            detected_technologies=technologies,
            pattern_matches={"ai_based": len(recommendations)},
            reasoning=f"AI-powered analysis completed in {analysis_time:.1f}ms, recommended {len(recommendations)} attacks"
        )
        
        logger.info(f"AI Analysis: Recommended {len(recommendations)} attack types for {url}")
        return recommendations
    
    def _heuristic_analysis(self, url: str, html: str, headers: Dict[str, str], technologies: List[str]) -> List[AttackRecommendation]:
        """
        Fallback heuristic analysis when AI model fails.
        
        Args:
            url: Target URL
            html: HTML content
            headers: Response headers
            technologies: Detected technologies
            
        Returns:
            List of attack recommendations based on heuristics
        """
        recommendations = []
        
        # Analyze for each vulnerability type using pattern matching
        for vuln_type, indicators in self._vulnerability_indicators.items():
            probability = self._calculate_vulnerability_probability(
                vuln_type, url, html, headers, indicators
            )
            
            if probability > 0.2:  # Higher threshold for fallback
                reasons = self._generate_reasons(vuln_type, url, html, indicators)
                
                recommendations.append(AttackRecommendation(
                    attack_type=AttackType(vuln_type),
                    probability=min(probability + 0.1, 1.0),
                    confidence=min(probability + 0.2, 1.0),
                    reasons=reasons + ["(Heuristic analysis - AI unavailable)"],
                    priority=self._calculate_priority(probability)
                ))
        
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
        Classify the severity of a vulnerability finding using AI analysis.
        
        Uses the Qwen AI model to analyze the finding and determine severity.
        
        Args:
            finding: Vulnerability finding data
            
        Returns:
            SeverityClassification with severity details
        """
        import time
        start_time = time.time()
        
        vuln_type = finding.get('attack_type', '').lower()
        payload = finding.get('payload', '')
        evidence = finding.get('evidence', '')
        finding_id = finding.get('id', 'unknown')
        
        # Try AI-powered severity classification first
        try:
            ai_prompt = f"""Analyze this security vulnerability and classify its severity:

Vulnerability Type: {vuln_type}
Title: {finding.get('title', 'N/A')}
Description: {finding.get('description', 'N/A')}
URL: {finding.get('url', 'N/A')}
Payload Used: {payload}
Evidence: {evidence}

Classify the severity using CVSS v3.1 guidelines. Consider:
- Attack Vector (Network, Adjacent, Local, Physical)
- Attack Complexity (Low, High)
- Privileges Required (None, Low, High)
- User Interaction (None, Required)
- Scope (Unchanged, Changed)
- Confidentiality Impact (None, Low, High)
- Integrity Impact (None, Low, High)
- Availability Impact (None, Low, High)

Respond with a JSON object containing:
- severity: "Critical", "High", "Medium", "Low", or "Info"
- cvss_score: numerical score (0.0-10.0)
- impact: description of potential impact
- exploitability: "Easy", "Moderate", or "Difficult"
- reasoning: brief explanation for the classification

Example response:
{{
  "severity": "High",
  "cvss_score": 7.5,
  "impact": "Potential data breach and session hijacking",
  "exploitability": "Easy",
  "reasoning": "XSS allows code execution in victim's browser"
}}"""

            ai_response = self.ai_model._generate_response(ai_prompt)
            
            # Parse AI response
            try:
                json_start = ai_response.find('{')
                json_end = ai_response.rfind('}') + 1
                if json_start != -1 and json_end > json_start:
                    json_str = ai_response[json_start:json_end]
                    ai_data = json.loads(json_str)
                    
                    classification = SeverityClassification(
                        severity=ai_data.get('severity', 'Medium'),
                        cvss_score=float(ai_data.get('cvss_score', 5.0)),
                        impact=ai_data.get('impact', 'Security vulnerability detected'),
                        exploitability=ai_data.get('exploitability', 'Moderate'),
                        remediation_priority=1 if ai_data.get('cvss_score', 5.0) >= 7.0 else 2
                    )
                    
                    # Log the AI-based classification
                    classification_time = (time.time() - start_time) * 1000
                    self.ai_logger.log_severity_classification(
                        finding_id=finding_id,
                        attack_type=vuln_type,
                        original_severity=finding.get('severity', 'unknown'),
                        ai_classified_severity=classification.severity,
                        confidence_score=0.9,
                        ai_reasoning=ai_data.get('reasoning', 'AI-powered severity classification'),
                        model_response=f"Severity: {classification.severity}, CVSS: {classification.cvss_score}",
                        classification_time_ms=classification_time
                    )
                    
                    return classification
                    
            except Exception as e:
                logger.warning(f"AI severity classification parsing failed: {e}, falling back to heuristics")
                
        except Exception as e:
            logger.warning(f"AI severity classification failed: {e}, falling back to heuristics")
        
        # Fallback to heuristic classification
        return self._heuristic_severity_classification(finding)
    
    def batch_classify_severity(self, findings: List[Dict[str, Any]]) -> List[SeverityClassification]:
        """
        Batch classify severity for multiple findings using AI analysis.
        
        This is much more efficient than calling classify_severity individually
        for each finding, as it reduces the number of AI model calls.
        
        Args:
            findings: List of vulnerability finding data
            
        Returns:
            List of SeverityClassification objects in same order as input
        """
        if not findings:
            return []
        
        classifications = []
        
        # Process findings in batches to avoid overwhelming the AI model
        batch_size = 5  # Process 5 findings at a time
        
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            
            # Create a single AI prompt for the entire batch
            batch_prompt = f"""Analyze the severity of these {len(batch)} security vulnerabilities and provide CVSS scores:

"""
            
            for j, finding in enumerate(batch):
                vuln_type = finding.get('attack_type', '').lower()
                title = finding.get('title', 'N/A')
                description = finding.get('description', 'N/A')
                payload = finding.get('payload', 'N/A')[:100]  # Limit payload length
                
                batch_prompt += f"""
Finding {j+1}:
- Type: {vuln_type}
- Title: {title}
- Description: {description}
- Payload: {payload}

"""
            
            batch_prompt += """
For each finding, provide a JSON object with:
- severity: Critical/High/Medium/Low/Info
- cvss_score: numeric score 0.0-10.0
- impact: brief impact description
- reasoning: why this severity level

Respond with a JSON array of severity classifications in the same order as the findings above.
Example: [{"severity": "High", "cvss_score": 7.5, "impact": "Data exposure", "reasoning": "SQL injection allows data extraction"}]
"""
            
            try:
                ai_response = self.ai_model._generate_response(batch_prompt)
                
                # Parse batch response
                try:
                    # Extract JSON array from response
                    json_start = ai_response.find('[')
                    json_end = ai_response.rfind(']') + 1
                    if json_start != -1 and json_end > json_start:
                        json_str = ai_response[json_start:json_end]
                        batch_classifications = json.loads(json_str)
                        
                        # Process each classification in the batch
                        for j, classification_data in enumerate(batch_classifications):
                            if isinstance(classification_data, dict):
                                severity = classification_data.get('severity', 'Medium')
                                cvss_score = classification_data.get('cvss_score', 5.0)
                                impact = classification_data.get('impact', 'Security vulnerability detected')
                                reasoning = classification_data.get('reasoning', 'AI analysis')
                                
                                classification = SeverityClassification(
                                    severity=severity,
                                    cvss_score=float(cvss_score),
                                    impact=impact,
                                    exploitability="Easy" if cvss_score >= 8.0 else "Moderate",
                                    remediation_priority=1 if cvss_score >= 8.0 else 2
                                )
                                
                                classifications.append(classification)
                                
                                # Log the classification
                                self.ai_logger.log_severity_classification(
                                    finding_id=batch[j].get('id', f'batch_{i+j}'),
                                    attack_type=batch[j].get('attack_type', 'unknown'),
                                    original_severity=batch[j].get('severity', 'unknown'),
                                    ai_classified_severity=classification.severity,
                                    confidence_score=0.8,  # Higher confidence for batch processing
                                    ai_reasoning=reasoning,
                                    model_response=f"Batch classification: {classification.severity} ({classification.cvss_score})",
                                    classification_time_ms=0  # We'll track this differently for batches
                                )
                            else:
                                # Fallback for malformed classification
                                classifications.append(self._heuristic_severity_classification(batch[j]))
                    else:
                        # Fallback to heuristic for entire batch
                        logger.warning("AI batch severity classification parsing failed, falling back to heuristics")
                        for finding in batch:
                            classifications.append(self._heuristic_severity_classification(finding))
                            
                except Exception as e:
                    logger.warning(f"AI batch severity classification parsing failed: {e}, falling back to heuristics")
                    for finding in batch:
                        classifications.append(self._heuristic_severity_classification(finding))
                        
            except Exception as e:
                logger.warning(f"AI batch severity classification failed: {e}, falling back to heuristics")
                for finding in batch:
                    classifications.append(self._heuristic_severity_classification(finding))
        
        return classifications
    
    def batch_suggest_remediation(self, findings: List[Dict[str, Any]]) -> List[List[RemediationSuggestion]]:
        """
        Batch generate remediation suggestions for multiple findings using AI analysis.
        
        This is much more efficient than calling suggest_remediation individually
        for each finding, as it reduces the number of AI model calls.
        
        Args:
            findings: List of vulnerability finding data
            
        Returns:
            List of lists of RemediationSuggestion objects, one list per finding
        """
        if not findings:
            return []
        
        all_suggestions = []
        
        # Process findings in batches to avoid overwhelming the AI model
        batch_size = 3  # Process 3 findings at a time for remediation (more complex)
        
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i + batch_size]
            
            # Create a single AI prompt for the entire batch
            batch_prompt = f"""Provide remediation steps for these {len(batch)} security vulnerabilities:

"""
            
            for j, finding in enumerate(batch):
                vuln_type = finding.get('attack_type', '').lower()
                title = finding.get('title', 'N/A')
                description = finding.get('description', 'N/A')[:200]  # Limit description
                
                batch_prompt += f"""
Finding {j+1} ({vuln_type}):
- Title: {title}
- Description: {description}

"""
            
            batch_prompt += """
For each finding, provide 2-3 specific remediation steps. Each step should include:
- title: clear action title
- description: detailed implementation guidance
- code_example: relevant code snippet (if applicable, use generic examples)
- effort: Low/Medium/High
- references: relevant security resources

Respond with a JSON array where each element corresponds to one finding and contains an array of remediation steps.
Example structure: [[{"title": "Fix 1", "description": "...", "code_example": "...", "effort": "Low", "references": ["OWASP"]}], [...]]
"""
            
            try:
                ai_response = self.ai_model._generate_response(batch_prompt)
                
                # Parse batch response
                try:
                    # Extract JSON array from response
                    json_start = ai_response.find('[')
                    json_end = ai_response.rfind(']') + 1
                    if json_start != -1 and json_end > json_start:
                        json_str = ai_response[json_start:json_end]
                        batch_suggestions = json.loads(json_str)
                        
                        # Process each finding's suggestions
                        for j, finding_suggestions in enumerate(batch_suggestions):
                            if isinstance(finding_suggestions, list):
                                suggestions = []
                                for suggestion_data in finding_suggestions[:3]:  # Max 3 per finding
                                    if isinstance(suggestion_data, dict):
                                        suggestion = RemediationSuggestion(
                                            title=suggestion_data.get('title', 'Implement security fix'),
                                            description=suggestion_data.get('description', 'Follow security best practices'),
                                            code_example=suggestion_data.get('code_example', ''),
                                            effort=suggestion_data.get('effort', 'Medium'),
                                            references=suggestion_data.get('references', [])
                                        )
                                        suggestions.append(suggestion)
                                
                                if suggestions:
                                    all_suggestions.append(suggestions)
                                else:
                                    # Fallback to templates
                                    all_suggestions.append(self._get_remediation_templates(batch[j]))
                            else:
                                # Fallback for malformed suggestions
                                all_suggestions.append(self._get_remediation_templates(batch[j]))
                    else:
                        # Fallback to templates for entire batch
                        logger.warning("AI batch remediation parsing failed, falling back to templates")
                        for finding in batch:
                            all_suggestions.append(self._get_remediation_templates(finding))
                            
                except Exception as e:
                    logger.warning(f"AI batch remediation parsing failed: {e}, falling back to templates")
                    for finding in batch:
                        all_suggestions.append(self._get_remediation_templates(finding))
                        
            except Exception as e:
                logger.warning(f"AI batch remediation failed: {e}, falling back to templates")
                for finding in batch:
                    all_suggestions.append(self._get_remediation_templates(finding))
        
        return all_suggestions
    
    def _get_remediation_templates(self, finding: Dict[str, Any]) -> List[RemediationSuggestion]:
        """Get template remediation suggestions when AI fails."""
        vuln_type = finding.get('attack_type', '').lower()
        
        templates = {
            'xss': [
                RemediationSuggestion(
                    title="Implement Input Sanitization",
                    description="Sanitize all user input before rendering in HTML using appropriate encoding functions.",
                    code_example="# Python with html.escape\nimport html\nsafe_output = html.escape(user_input)",
                    effort="Low",
                    references=["OWASP XSS Prevention Cheat Sheet"]
                ),
                RemediationSuggestion(
                    title="Use Content Security Policy",
                    description="Implement CSP headers to restrict script execution sources.",
                    code_example="Content-Security-Policy: default-src 'self'; script-src 'self'",
                    effort="Medium",
                    references=["MDN CSP Documentation"]
                )
            ],
            'sqli': [
                RemediationSuggestion(
                    title="Use Parameterized Queries",
                    description="Replace string concatenation with parameterized queries or prepared statements.",
                    code_example="# Python with sqlite3\ncursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                    effort="Medium",
                    references=["OWASP SQL Injection Prevention"]
                ),
                RemediationSuggestion(
                    title="Implement Input Validation",
                    description="Validate and sanitize all user inputs using whitelisting approaches.",
                    code_example="import re\nif not re.match(r'^\\d+$', user_id): raise ValueError('Invalid ID')",
                    effort="Low",
                    references=["OWASP Input Validation Cheat Sheet"]
                )
            ],
            'csrf': [
                RemediationSuggestion(
                    title="Implement CSRF Tokens",
                    description="Add unique tokens to all state-changing forms and validate them server-side.",
                    code_example="<input type='hidden' name='csrf_token' value='{{ csrf_token() }}'>",
                    effort="Medium",
                    references=["OWASP CSRF Prevention"]
                )
            ]
        }
        
        return templates.get(vuln_type, [
            RemediationSuggestion(
                title="Review Security Practices",
                description="Consult security documentation and implement appropriate protections for this vulnerability type.",
                code_example="",
                effort="Medium",
                references=["OWASP Cheat Sheets"]
            )
        ])
    
    def _heuristic_severity_classification(self, finding: Dict[str, Any]) -> SeverityClassification:
        import time
        start_time = time.time()
        
        vuln_type = finding.get('attack_type', '').lower()
        payload = finding.get('payload', '')
        evidence = finding.get('evidence', '')
        finding_id = finding.get('id', 'unknown')
        
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
        
        classification = SeverityClassification(
            severity=severity_info[0],
            cvss_score=min(severity_info[1] + cvss_adjustment, 10.0),
            impact=severity_info[2],
            exploitability="Easy" if severity_info[1] >= 8.0 else "Moderate",
            remediation_priority=1 if severity_info[1] >= 8.0 else 2
        )
        
        # Log the heuristic classification
        classification_time = (time.time() - start_time) * 1000
        self.ai_logger.log_severity_classification(
            finding_id=finding_id,
            attack_type=vuln_type,
            original_severity=finding.get('severity', 'unknown'),
            ai_classified_severity=classification.severity,
            confidence_score=0.7,  # Lower confidence for heuristics
            ai_reasoning=f"Heuristic classification based on {vuln_type} vulnerability type",
            model_response=f"Severity: {classification.severity}, CVSS: {classification.cvss_score} (heuristic)",
            classification_time_ms=classification_time
        )
        
        return classification
    
    def suggest_remediation(self, finding: Dict[str, Any]) -> List[RemediationSuggestion]:
        """
        Suggest remediation steps for a vulnerability using AI analysis.
        
        Uses the Qwen AI model to generate tailored remediation suggestions.
        
        Args:
            finding: Vulnerability finding data
            
        Returns:
            List of RemediationSuggestion with fix recommendations
        """
        vuln_type = finding.get('attack_type', '').lower()
        
        # Try AI-powered remediation suggestions first
        try:
            ai_prompt = f"""Provide specific remediation steps for this security vulnerability:

Vulnerability Type: {vuln_type}
Title: {finding.get('title', 'N/A')}
Description: {finding.get('description', 'N/A')}
URL: {finding.get('url', 'N/A')}
Payload Used: {finding.get('payload', 'N/A')}
Evidence: {finding.get('evidence', 'N/A')}

Provide 2-3 specific, actionable remediation steps. For each step, include:
- A clear title
- Detailed description of what to do
- Code example (if applicable)
- Implementation effort (Low/Medium/High)
- Security references

Respond with a JSON array of remediation suggestions.

Example response:
[
  {{
    "title": "Implement Input Validation",
    "description": "Validate and sanitize all user inputs before processing",
    "code_example": "sanitized_input = sanitize(user_input)",
    "effort": "Medium",
    "references": ["https://owasp.org/www-community/xss-filter-evasion-cheatsheet"]
  }}
]"""

            ai_response = self.ai_model._generate_response(ai_prompt)
            
            # Parse AI response
            try:
                json_start = ai_response.find('[')
                json_end = ai_response.rfind(']') + 1
                if json_start != -1 and json_end > json_start:
                    json_str = ai_response[json_start:json_end]
                    ai_suggestions = json.loads(json_str)
                    
                    # Convert to RemediationSuggestion objects
                    suggestions = []
                    for suggestion in ai_suggestions:
                        if isinstance(suggestion, dict):
                            suggestions.append(RemediationSuggestion(
                                title=suggestion.get('title', 'Remediation Step'),
                                description=suggestion.get('description', 'Fix the identified vulnerability'),
                                code_example=suggestion.get('code_example'),
                                references=suggestion.get('references', []),
                                effort=suggestion.get('effort', 'Medium')
                            ))
                    
                    if suggestions:
                        return suggestions
                        
            except Exception as e:
                logger.warning(f"AI remediation parsing failed: {e}, falling back to templates")
                
        except Exception as e:
            logger.warning(f"AI remediation generation failed: {e}, falling back to templates")
        
        # Fallback to template-based remediation
        return self._template_remediation_suggestions(vuln_type)
    
    def _template_remediation_suggestions(self, vuln_type: str) -> List[RemediationSuggestion]:
        """
        Fallback template-based remediation suggestions when AI fails.
        
        Args:
            vuln_type: Type of vulnerability
            
        Returns:
            List of remediation suggestions from templates
        """
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
