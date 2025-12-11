"""
AI Model Interface for PennyWise.
Provides a unified interface for AI-powered analysis using the local Qwen model.
"""

import subprocess
import json
import tempfile
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class AIResponse:
    """Structured AI model response."""
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    raw_response: Optional[str] = None


class AIModelInterface:
    """
    Interface for the local Qwen vulnerability detection model.
    
    This class wraps the local model binary and provides methods for:
    - Vulnerability analysis
    - Site auditing
    - Severity classification
    - Attack recommendation
    """
    
    def __init__(self, model_path: str = "./qwen-vuln-detector/localmodel"):
        """
        Initialize the AI model interface.
        
        Args:
            model_path: Path to the local model binary
        """
        self.model_path = self._resolve_model_path(model_path)
        self._validate_model()
        logger.info(f"AI Model Interface initialized with model: {self.model_path}")
    
    def _resolve_model_path(self, model_path: str) -> Path:
        """Resolve the model binary path, adding .exe on Windows if needed."""
        import platform
        import os
        
        path = Path(model_path)
        
        # Make path absolute if relative
        if not path.is_absolute():
            path = Path(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))) / model_path
        
        # On Windows, try adding .exe if the file doesn't exist
        if platform.system() == 'Windows':
            if not path.exists() and not path.suffix:
                exe_path = path.with_suffix('.exe')
                if exe_path.exists():
                    return exe_path
        
        return path
    
    def _validate_model(self):
        """Validate that the model binary exists and is executable."""
        if not self.model_path.exists():
            logger.warning(f"Model binary not found at {self.model_path}")
    
    def _call_model(self, mode: str, data: Dict[str, Any]) -> AIResponse:
        """
        Call the local model binary with specified mode and data.
        
        Args:
            mode: Operation mode (vuln-info, site-audit, classify-severity)
            data: Input data dictionary
            
        Returns:
            AIResponse with parsed results
        """
        try:
            # Write data to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                json.dump(data, tmp)
                tmp_path = tmp.name
            
            # Call model binary
            cmd = [str(self.model_path), mode, tmp_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Clean up temp file
            Path(tmp_path).unlink(missing_ok=True)
            
            # Parse response
            raw_output = result.stdout.strip()
            
            # Handle markdown code blocks in response
            cleaned = raw_output.replace('```json\n', '').replace('\n```', '').strip()
            
            try:
                parsed = json.loads(cleaned)
                
                # Check for error codes
                if 'error' in parsed:
                    error_code = parsed.get('error')
                    if error_code == 'E001':
                        return AIResponse(False, {}, "API quota exceeded", raw_output)
                    elif error_code == 'E002':
                        return AIResponse(False, {}, "Content blocked by safety filter", raw_output)
                    elif error_code == 'E003':
                        return AIResponse(False, {}, "No response generated", raw_output)
                
                return AIResponse(True, parsed, raw_response=raw_output)
                
            except json.JSONDecodeError:
                return AIResponse(False, {}, "Failed to parse model response", raw_output)
                
        except subprocess.TimeoutExpired:
            return AIResponse(False, {}, "Model inference timeout")
        except Exception as e:
            logger.error(f"Model call failed: {e}")
            return AIResponse(False, {}, str(e))
    
    def analyze_vulnerability(self, vuln_data: Dict[str, Any]) -> AIResponse:
        """
        Analyze a detected vulnerability and provide detailed insights.
        
        Args:
            vuln_data: Dictionary containing:
                - type: Vulnerability type (XSS, SQLi, etc.)
                - subtype: Specific variant (reflected, stored, etc.)
                - url: Affected URL
                - match: Matched pattern or payload
                - findings: Optional list of related findings
                
        Returns:
            AIResponse with:
                - summary: One-line description
                - severity: Low/Medium/High/Critical
                - risks: List of potential risks
                - recommendations: List of remediation steps
        """
        return self._call_model("vuln-info", vuln_data)
    
    def audit_site(self, url: str, html: str, title: str = "") -> AIResponse:
        """
        Perform AI-powered site audit to identify potential vulnerabilities.
        
        Args:
            url: Target URL
            html: HTML content (first 4000 chars recommended)
            title: Page title
            
        Returns:
            AIResponse with:
                - site_summary: Brief overview
                - recommended_tests: List of recommended security tests
                - next_steps: Attack type indicators [0=SQLi, 1=XSS, 2=Auth]
                - vulnerability_type: Primary detected vulnerability type
                - confidence: Confidence score (0-1)
        """
        # Truncate HTML to prevent token overflow
        html_sample = html[:4000] if len(html) > 4000 else html
        
        data = {
            "url": url,
            "html": html_sample,
            "title": title
        }
        return self._call_model("site-audit", data)
    
    def classify_severity(self, findings: List[Dict[str, Any]]) -> AIResponse:
        """
        Classify vulnerabilities by severity and provide quick fixes.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            AIResponse with:
                - severity: Overall severity level
                - impact: Description of potential impact
                - quick_fixes: List of remediation steps
        """
        data = {"vulnerabilities": findings}
        return self._call_model("classify-severity", data)
    
    def recommend_attacks(self, target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Recommend attack types based on target analysis.
        
        Args:
            target_info: Dictionary containing site analysis results
            
        Returns:
            List of recommended attacks with priority and reasoning
        """
        if not target_info.get('success', True):
            return []
        
        recommendations = []
        
        # Extract next_steps indicators if available
        next_steps = target_info.get('data', {}).get('next_steps', [])
        recommended_tests = target_info.get('data', {}).get('recommended_tests', [])
        
        # Map indicators to attack types
        attack_map = {
            0: ("SQLi", "SQL Injection vectors detected"),
            1: ("XSS", "Cross-Site Scripting potential identified"),
            2: ("AUTH", "Authentication/Authorization issues suspected"),
            3: ("CSRF", "Cross-Site Request Forgery risk"),
            4: ("SSRF", "Server-Side Request Forgery possible"),
            5: ("IDOR", "Insecure Direct Object References detected")
        }
        
        for step in next_steps:
            if step in attack_map:
                attack_type, reason = attack_map[step]
                recommendations.append({
                    "attack_type": attack_type,
                    "priority": "high" if step in [0, 1] else "medium",
                    "reason": reason,
                    "from_ai": True
                })
        
        # Add tests from AI recommendations
        for test in recommended_tests:
            if isinstance(test, dict):
                recommendations.append({
                    "attack_type": test.get('test', 'UNKNOWN'),
                    "priority": test.get('priority', 'medium').lower(),
                    "reason": test.get('reason', ''),
                    "from_ai": True
                })
        
        return recommendations


class MockAIModel(AIModelInterface):
    """
    Mock AI model for testing without the actual model binary.
    Returns reasonable default responses.
    """
    
    def __init__(self):
        self.model_path = Path("mock")
        logger.info("Using Mock AI Model for testing")
    
    def _call_model(self, mode: str, data: Dict[str, Any]) -> AIResponse:
        """Return mock responses based on mode."""
        
        if mode == "vuln-info":
            return AIResponse(True, {
                "summary": f"Potential {data.get('type', 'security')} vulnerability detected",
                "severity": "Medium",
                "risks": [
                    "Data exposure risk",
                    "Potential unauthorized access"
                ],
                "recommendations": [
                    "Implement input validation",
                    "Use parameterized queries",
                    "Enable security headers"
                ]
            })
        
        elif mode == "site-audit":
            return AIResponse(True, {
                "site_summary": "Web application with user input forms",
                "recommended_tests": [
                    {"test": "XSS", "priority": "High", "reason": "Forms without sanitization"},
                    {"test": "SQLi", "priority": "Medium", "reason": "Database-backed content"}
                ],
                "next_steps": [1, 0],  # XSS, SQLi
                "vulnerability_type": "XSS",
                "confidence": 0.75
            })
        
        elif mode == "classify-severity":
            return AIResponse(True, {
                "severity": "Medium",
                "impact": "Potential data exposure and session hijacking",
                "quick_fixes": [
                    "Sanitize all user inputs",
                    "Implement CSP headers",
                    "Use HTTPOnly cookies"
                ]
            })
        
        return AIResponse(False, {}, "Unknown mode")
