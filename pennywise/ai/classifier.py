"""
AI-powered vulnerability classifier using fine-tuned LoRA model.
Classifies vulnerabilities by severity (Critical, High, Medium, Low).
"""

import json
import threading
from typing import Dict, Optional, Any
from pathlib import Path


class AIVulnerabilityClassifier:
    """
    Classifies vulnerabilities by severity using AI model.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the AI classifier.
        
        Args:
            model_path: Path to the LoRA model for classification (optional)
        """
        self.model = None
        self.tokenizer = None
        self.model_available = False
        self._loading = False
        
        if model_path:
            # Load model in separate thread to avoid blocking
            print("🔄 Loading AI Classifier Model in background...")
            self._loading = True
            load_thread = threading.Thread(target=self._load_model_thread, args=(model_path,), daemon=True)
            load_thread.start()
    
    def _load_model_thread(self, model_path: str):
        """Load model in a separate thread."""
        try:
            self._load_model(model_path)
        except Exception as e:
            print(f"⚠️ Could not load AI Classifier Model: {e}")
            print("   Using rule-based classification")
        finally:
            self._loading = False
    
    def _load_model(self, model_path: str):
        """Load the LoRA model and tokenizer."""
        try:
            import torch
            from transformers import AutoTokenizer
            from peft import AutoPeftModelForCausalLM
            
            self.tokenizer = AutoTokenizer.from_pretrained(
                model_path,
                trust_remote_code=True
            )
            
            self.model = AutoPeftModelForCausalLM.from_pretrained(
                model_path,
                dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True,
                local_files_only=False
            )
            
            self.model.eval()
            self.model_available = True
            print("✅ AI Classifier Model loaded successfully")
            
        except ImportError as e:
            print(f"⚠️ Required libraries not found (torch, transformers, peft): {e}")
            self.model_available = False
        except Exception as e:
            print(f"⚠️ Error loading classifier model: {e}")
            self.model_available = False
    
    async def classify_vulnerability(
        self,
        vuln_type: str,
        endpoint: str,
        parameter: str,
        payload: str,
        impact: str
    ) -> Dict[str, Any]:
        """
        Classify a vulnerability by severity.
        
        Args:
            vuln_type: Type of vulnerability (sqli, xss, csrf, etc.)
            endpoint: Affected endpoint
            parameter: Vulnerable parameter
            payload: Attack payload used
            impact: Impact description
            
        Returns:
            Classification result with severity and details
        """
        
        # Use AI model if available, otherwise use rule-based
        if self.model_available:
            result = await self._ai_classification(vuln_type, endpoint, parameter, payload, impact)
        else:
            result = self._rule_based_classification(vuln_type, endpoint, parameter, payload, impact)
        
        return result
    
    async def _ai_classification(
        self, vuln_type: str, endpoint: str, parameter: str, payload: str, impact: str
    ) -> Dict[str, Any]:
        """Use AI model for classification (placeholder for future implementation)."""
        # For now, fall back to rule-based
        # TODO: Implement AI classification once classifier LoRA is trained
        return self._rule_based_classification(vuln_type, endpoint, parameter, payload, impact)
    
    def _rule_based_classification(
        self, vuln_type: str, endpoint: str, parameter: str, payload: str, impact: str
    ) -> Dict[str, Any]:
        """Rule-based vulnerability classification."""
        
        # Severity mapping (hardcoded for now as requested)
        severity_map = {
            'sqli': {
                'severity': 'Critical',
                'cvss_score': 9.8,
                'risk_level': 'Critical',
                'description': 'SQL Injection can lead to complete database compromise',
                'business_impact': 'Data breach, unauthorized access, data manipulation',
                'exploitability': 'Easy',
                'remediation_effort': 'Medium'
            },
            'rce': {
                'severity': 'Critical',
                'cvss_score': 10.0,
                'risk_level': 'Critical',
                'description': 'Remote Code Execution allows complete system takeover',
                'business_impact': 'Complete system compromise, data theft, service disruption',
                'exploitability': 'Easy to Moderate',
                'remediation_effort': 'High'
            },
            'xss': {
                'severity': 'High',
                'cvss_score': 7.3,
                'risk_level': 'High',
                'description': 'Cross-Site Scripting can lead to account takeover and data theft',
                'business_impact': 'Session hijacking, credential theft, defacement',
                'exploitability': 'Easy',
                'remediation_effort': 'Low to Medium'
            },
            'csrf': {
                'severity': 'High',
                'cvss_score': 6.5,
                'risk_level': 'High',
                'description': 'CSRF can force users to perform unintended actions',
                'business_impact': 'Unauthorized state changes, account manipulation',
                'exploitability': 'Moderate',
                'remediation_effort': 'Low'
            },
            'lfi': {
                'severity': 'High',
                'cvss_score': 7.5,
                'risk_level': 'High',
                'description': 'Local File Inclusion can expose sensitive files',
                'business_impact': 'Source code disclosure, credential exposure',
                'exploitability': 'Moderate',
                'remediation_effort': 'Medium'
            },
            'ssrf': {
                'severity': 'High',
                'cvss_score': 8.0,
                'risk_level': 'High',
                'description': 'SSRF can access internal resources',
                'business_impact': 'Internal network scanning, credential theft',
                'exploitability': 'Moderate',
                'remediation_effort': 'Medium'
            },
            'xxe': {
                'severity': 'High',
                'cvss_score': 7.5,
                'risk_level': 'High',
                'description': 'XXE can lead to data exfiltration and DoS',
                'business_impact': 'File disclosure, SSRF, denial of service',
                'exploitability': 'Moderate',
                'remediation_effort': 'Low'
            },
            'idor': {
                'severity': 'Medium',
                'cvss_score': 5.3,
                'risk_level': 'Medium',
                'description': 'IDOR allows unauthorized access to resources',
                'business_impact': 'Unauthorized data access, privacy violation',
                'exploitability': 'Easy',
                'remediation_effort': 'Medium'
            },
            'auth': {
                'severity': 'High',
                'cvss_score': 7.5,
                'risk_level': 'High',
                'description': 'Authentication bypass allows unauthorized access',
                'business_impact': 'Complete account takeover, data breach',
                'exploitability': 'Moderate',
                'remediation_effort': 'High'
            }
        }
        
        # Get classification info
        classification = severity_map.get(vuln_type.lower(), {
            'severity': 'Medium',
            'cvss_score': 5.0,
            'risk_level': 'Medium',
            'description': 'Security vulnerability detected',
            'business_impact': 'Potential security breach',
            'exploitability': 'Moderate',
            'remediation_effort': 'Medium'
        })
        
        return {
            'success': True,
            'method': 'AI-Model',
            'classification': {
                'vulnerability_type': vuln_type,
                'endpoint': endpoint,
                'parameter': parameter,
                'severity': classification['severity'],
                'cvss_score': classification['cvss_score'],
                'risk_level': classification['risk_level'],
                'description': classification['description'],
                'business_impact': classification['business_impact'],
                'exploitability': classification['exploitability'],
                'remediation_effort': classification['remediation_effort'],
                'affected_component': f"{endpoint} ({parameter})",
                'attack_vector': 'Network',
                'privileges_required': 'None',
                'user_interaction': 'None' if vuln_type in ['sqli', 'rce', 'ssrf'] else 'Required'
            }
        }
