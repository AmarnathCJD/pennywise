"""
AI Model Interface for PennyWise.
Provides a unified interface for AI-powered analysis using the local Qwen model.
"""

import json
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel
import time
from datetime import datetime

from ..ai.ai_logger import get_ai_logger

logger = logging.getLogger(__name__)


@dataclass
class AILogEntry:
    """Comprehensive AI activity log entry."""
    timestamp: str
    operation: str
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    model_used: str
    processing_time: float
    success: bool
    error_message: Optional[str] = None
    token_count: Optional[int] = None
    confidence_score: Optional[float] = None


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

    This class loads the fine-tuned Qwen model and provides methods for:
    - Vulnerability analysis
    - Site auditing
    - Severity classification
    - Attack recommendation
    """

    def __init__(self, model_path: str = "./qwen-vuln-detector"):
        """
        Initialize the AI model interface.

        Args:
            model_path: Path to the model directory containing adapter_model.safetensors
        """
        self.model_path = Path(model_path)
        self.model = None
        self.tokenizer = None
        self.ai_logs: List[AILogEntry] = []
        self.ai_logger = get_ai_logger()
        self._load_model()
        logger.info(f"AI Model Interface initialized with model: {self.model_path}")

    def _load_model(self):
        """Load the Qwen model with PEFT adapter."""
        try:
            # Check GPU availability
            cuda_available = torch.cuda.is_available()
            device = "cuda" if cuda_available else "cpu"
            logger.info(f"GPU available: {cuda_available}, using device: {device}")

            if cuda_available:
                logger.info(f"GPU device: {torch.cuda.get_device_name(0)}")
                logger.info(f"GPU memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB")

            # Check if we have a complete local model or just adapter
            localmodel_path = self.model_path / "localmodel"
            adapter_path = self.model_path / "adapter_model.safetensors"
            adapter_config_path = self.model_path / "adapter_config.json"

            if adapter_path.exists() and adapter_config_path.exists():
                # Load base model and apply adapter
                logger.info("Loading base model with PEFT adapter")
                base_model_name = "Qwen/Qwen3-0.6B"
                self.tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)

                # Load base model with explicit device mapping
                if cuda_available:
                    self.model = AutoModelForCausalLM.from_pretrained(
                        base_model_name,
                        torch_dtype=torch.float16,
                        device_map="auto",
                        trust_remote_code=True
                    )
                    logger.info("Model loaded on GPU with device_map='auto'")
                else:
                    self.model = AutoModelForCausalLM.from_pretrained(
                        base_model_name,
                        torch_dtype=torch.float32,  # Use float32 on CPU for better compatibility
                        device_map={"": "cpu"},
                        trust_remote_code=True
                    )
                    logger.info("Model loaded on CPU")

                # Load PEFT adapter
                self.model = PeftModel.from_pretrained(self.model, str(self.model_path))
                logger.info("Loaded PEFT adapter successfully")

            elif localmodel_path.exists():
                # Try to load as a local model directory
                logger.info("Attempting to load local model directory")
                try:
                    self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_path), trust_remote_code=True)

                    if cuda_available:
                        self.model = AutoModelForCausalLM.from_pretrained(
                            str(self.model_path),
                            torch_dtype=torch.float16,
                            device_map="auto",
                            trust_remote_code=True
                        )
                        logger.info("Local model loaded on GPU")
                    else:
                        self.model = AutoModelForCausalLM.from_pretrained(
                            str(self.model_path),
                            torch_dtype=torch.float32,
                            device_map={"": "cpu"},
                            trust_remote_code=True
                        )
                        logger.info("Local model loaded on CPU")

                    logger.info("Loaded local model directory successfully")
                except Exception as e:
                    logger.warning(f"Failed to load as model directory: {e}, trying base model only")
                    raise e

            else:
                # Fallback: try to load base model only with mock responses for testing
                logger.warning("No local model or adapter found, using mock AI responses for testing")
                self.tokenizer = None
                self.model = None
                logger.info("Initialized with mock AI responses")

            # Set model to evaluation mode if we have a real model
            if self.model is not None:
                self.model.eval()
                # Log final device placement
                if hasattr(self.model, 'device'):
                    logger.info(f"Model device: {self.model.device}")
                elif hasattr(self.model, 'hf_device_map'):
                    logger.info(f"Model device map: {self.model.hf_device_map}")
                else:
                    logger.info("Model device information not available")

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            # Fallback to mock mode
            logger.warning("Falling back to mock AI responses")
            self.tokenizer = None
            self.model = None

    def _generate_response(self, prompt: str, max_length: int = 512) -> str:
        """Generate response from the model."""
        # Check if we're in mock mode
        if self.model is None or self.tokenizer is None:
            logger.info("Using mock AI response for testing")
            return self._generate_mock_response(prompt)

        try:
            logger.debug(f"Generating response on device: {self.model.device}")
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)

            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_length=max_length,
                    num_return_sequences=1,
                    temperature=0.7,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )

            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            logger.debug(f"Response generated successfully, length: {len(response)}")
            return response

        except Exception as e:
            logger.error(f"Model generation failed: {e}")
            return self._generate_mock_response(prompt)

    def _generate_mock_response(self, prompt: str) -> str:
        """Generate mock responses for testing when model is not available."""
        prompt_lower = prompt.lower()

        if "vulnerability" in prompt_lower and "xss" in prompt_lower:
            return '''{
                "risk_level": "Critical",
                "impact": "Cross-site scripting allows attackers to execute malicious scripts in users' browsers",
                "recommendations": [
                    "Implement proper input validation and sanitization",
                    "Use Content Security Policy (CSP) headers",
                    "Encode output before displaying user input"
                ],
                "additional_checks": [
                    "Test for DOM-based XSS",
                    "Check for stored XSS in forms",
                    "Verify CSP implementation"
                ]
            }'''

        elif "attack" in prompt_lower and "recommend" in prompt_lower:
            return '''{
                "recommended_attacks": ["XSS", "SQLi", "CSRF"],
                "reasoning": "Based on target analysis, these are the most likely attack vectors",
                "confidence": 0.85
            }'''

        else:
            return '''{
                "response": "Mock AI analysis completed",
                "risk_level": "Medium",
                "recommendations": ["Review security measures", "Implement input validation"]
            }'''

    def _log_ai_activity(self, operation: str, input_data: Dict[str, Any],
                        output_data: Dict[str, Any], processing_time: float,
                        success: bool, error_message: Optional[str] = None,
                        token_count: Optional[int] = None,
                        confidence_score: Optional[float] = None):
        """
        Log AI activity for comprehensive tracking.

        Args:
            operation: The AI operation performed
            input_data: Input data provided to the AI
            output_data: Output data from the AI
            processing_time: Time taken for processing
            success: Whether the operation was successful
            error_message: Error message if operation failed
            token_count: Number of tokens processed
            confidence_score: Confidence score of the result
        """
        log_entry = AILogEntry(
            timestamp=datetime.now().isoformat(),
            operation=operation,
            input_data=input_data,
            output_data=output_data,
            model_used=str(self.model_path) if self.model else "mock",
            processing_time=processing_time,
            success=success,
            error_message=error_message,
            token_count=token_count,
            confidence_score=confidence_score
        )

        self.ai_logs.append(log_entry)
        logger.info(f"AI Activity Logged: {operation} - Success: {success} - Time: {processing_time:.3f}s")

    def get_ai_logs(self) -> List[AILogEntry]:
        """Get all AI activity logs."""
        return self.ai_logs.copy()

    def get_ai_logs_summary(self) -> Dict[str, Any]:
        """Get a summary of AI activities."""
        if not self.ai_logs:
            return {"total_operations": 0, "success_rate": 0.0, "average_processing_time": 0.0}

        total_ops = len(self.ai_logs)
        successful_ops = sum(1 for log in self.ai_logs if log.success)
        avg_time = sum(log.processing_time for log in self.ai_logs) / total_ops

        operations_by_type = {}
        for log in self.ai_logs:
            operations_by_type[log.operation] = operations_by_type.get(log.operation, 0) + 1

        return {
            "total_operations": total_ops,
            "success_rate": successful_ops / total_ops,
            "average_processing_time": avg_time,
            "operations_by_type": operations_by_type,
            "model_used": str(self.model_path) if self.model else "mock"
        }

    def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> AIResponse:
        """
        Analyze a vulnerability finding.

        Args:
            vulnerability_data: Dictionary containing vulnerability details

        Returns:
            AIResponse with analysis results
        """
        start_time = time.time()
        try:
            prompt = f"""Analyze this security vulnerability and provide recommendations:

Vulnerability Type: {vulnerability_data.get('attack_type', 'unknown')}
Title: {vulnerability_data.get('title', 'N/A')}
Description: {vulnerability_data.get('description', 'N/A')}
URL: {vulnerability_data.get('url', 'N/A')}
Payload: {vulnerability_data.get('payload', 'N/A')}
Evidence: {vulnerability_data.get('evidence', 'N/A')}

Please provide:
1. Risk assessment (Low/Medium/High/Critical)
2. Potential impact
3. Recommended remediation steps
4. Additional attack vectors to check

Respond in JSON format."""

            raw_response = self._generate_response(prompt)
            processing_time = time.time() - start_time

            # Try to extract JSON from response
            try:
                # Look for JSON in the response - handle markdown code blocks
                import re

                # First try to find JSON in markdown code blocks
                json_block_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
                json_match = re.search(json_block_pattern, raw_response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1)
                    parsed = json.loads(json_str)
                    response = AIResponse(True, parsed, raw_response=raw_response)
                else:
                    # Fallback: look for JSON between { and }
                    json_start = raw_response.find('{')
                    json_end = raw_response.rfind('}') + 1
                    if json_start != -1 and json_end > json_start:
                        json_str = raw_response[json_start:json_end]
                        parsed = json.loads(json_str)
                        response = AIResponse(True, parsed, raw_response=raw_response)
                    else:
                        # Fallback: create structured response
                        response = AIResponse(True, {
                            "risk_level": "Medium",
                            "impact": "Potential security vulnerability detected",
                            "recommendations": ["Review and remediate the identified issue"],
                            "additional_checks": ["Verify input validation", "Check for similar patterns"]
                        }, raw_response=raw_response)

                # Log successful operation
                self._log_ai_activity(
                    operation="vulnerability_analysis",
                    input_data=vulnerability_data,
                    output_data=response.data,
                    processing_time=processing_time,
                    success=True,
                    token_count=len(prompt.split()) if prompt else None,
                    confidence_score=0.8  # Default confidence
                )

                return response

            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse model response: {str(e)}"
                logger.error(f"JSON parse error: {e}")
                logger.error(f"Raw response (first 500 chars): {raw_response[:500]}")
                self._log_ai_activity(
                    operation="vulnerability_analysis",
                    input_data=vulnerability_data,
                    output_data={},
                    processing_time=processing_time,
                    success=False,
                    error_message=error_msg,
                    token_count=len(prompt.split()) if prompt else None
                )
                return AIResponse(False, {}, error_msg, raw_response)

        except Exception as e:
            processing_time = time.time() - start_time
            error_msg = str(e)
            self._log_ai_activity(
                operation="vulnerability_analysis",
                input_data=vulnerability_data,
                output_data={},
                processing_time=processing_time,
                success=False,
                error_message=error_msg
            )
            logger.error(f"Vulnerability analysis failed: {e}")
            return AIResponse(False, {}, error_msg)

    def audit_site(self, site_data: Dict[str, Any]) -> AIResponse:
        """
        Perform comprehensive site security audit.

        Args:
            site_data: Dictionary containing site information

        Returns:
            AIResponse with audit results
        """
        start_time = time.time()
        try:
            prompt = f"""Perform a security audit of this website:

URL: {site_data.get('url', 'N/A')}
Title: {site_data.get('title', 'N/A')}
Server: {site_data.get('server', 'N/A')}
Technologies: {', '.join(site_data.get('technologies', []))}
Forms Found: {site_data.get('forms_count', 0)}
Parameters Found: {site_data.get('params_count', 0)}

Identify potential security issues and provide audit recommendations.
Focus on:
1. Input validation vulnerabilities
2. Authentication weaknesses
3. Authorization issues
4. Information disclosure
5. Configuration issues

Respond in JSON format with findings and recommendations."""

            raw_response = self._generate_response(prompt, max_length=1024)
            processing_time = time.time() - start_time

            try:
                # Extract JSON from response
                json_start = raw_response.find('{')
                json_end = raw_response.rfind('}') + 1
                if json_start != -1 and json_end > json_start:
                    json_str = raw_response[json_start:json_end]
                    parsed = json.loads(json_str)
                    response = AIResponse(True, parsed, raw_response=raw_response)
                else:
                    response = AIResponse(True, {
                        "overall_risk": "Medium",
                        "findings": ["General security audit completed"],
                        "recommendations": ["Implement proper input validation", "Use HTTPS", "Regular security testing"]
                    }, raw_response=raw_response)

                # Log successful operation
                self._log_ai_activity(
                    operation="site_audit",
                    input_data=site_data,
                    output_data=response.data,
                    processing_time=processing_time,
                    success=True,
                    token_count=len(prompt.split()) if prompt else None,
                    confidence_score=0.75
                )

                return response

            except json.JSONDecodeError:
                error_msg = "Failed to parse audit response"
                self._log_ai_activity(
                    operation="site_audit",
                    input_data=site_data,
                    output_data={},
                    processing_time=processing_time,
                    success=False,
                    error_message=error_msg,
                    token_count=len(prompt.split()) if prompt else None
                )
                return AIResponse(False, {}, error_msg, raw_response)

        except Exception as e:
            processing_time = time.time() - start_time
            error_msg = str(e)
            self._log_ai_activity(
                operation="site_audit",
                input_data=site_data,
                output_data={},
                processing_time=processing_time,
                success=False,
                error_message=error_msg
            )
            logger.error(f"Site audit failed: {e}")
            return AIResponse(False, {}, error_msg)

    def classify_severity(self, vulnerability_data: Dict[str, Any]) -> AIResponse:
        """
        Classify vulnerability severity.

        Args:
            vulnerability_data: Dictionary containing vulnerability details

        Returns:
            AIResponse with severity classification
        """
        start_time = time.time()
        try:
            prompt = f"""Classify the severity of this vulnerability:

Type: {vulnerability_data.get('attack_type', 'unknown')}
Description: {vulnerability_data.get('description', 'N/A')}
Potential Impact: {vulnerability_data.get('impact', 'N/A')}

Classify as: Critical, High, Medium, Low, or Info
Provide CVSS score estimate and justification.

Respond in JSON format."""

            raw_response = self._generate_response(prompt)
            processing_time = time.time() - start_time

            try:
                # Extract JSON
                json_start = raw_response.find('{')
                json_end = raw_response.rfind('}') + 1
                if json_start != -1 and json_end > json_start:
                    json_str = raw_response[json_start:json_end]
                    parsed = json.loads(json_str)
                    response = AIResponse(True, parsed, raw_response=raw_response)
                else:
                    response = AIResponse(True, {
                        "severity": "Medium",
                        "cvss_score": 5.0,
                        "justification": "Default classification based on vulnerability type"
                    }, raw_response=raw_response)

                # Log successful operation
                self._log_ai_activity(
                    operation="severity_classification",
                    input_data=vulnerability_data,
                    output_data=response.data,
                    processing_time=processing_time,
                    success=True,
                    token_count=len(prompt.split()) if prompt else None,
                    confidence_score=0.85
                )

                return response

            except json.JSONDecodeError:
                error_msg = "Failed to parse severity response"
                self._log_ai_activity(
                    operation="severity_classification",
                    input_data=vulnerability_data,
                    output_data={},
                    processing_time=processing_time,
                    success=False,
                    error_message=error_msg,
                    token_count=len(prompt.split()) if prompt else None
                )
                return AIResponse(False, {}, error_msg, raw_response)

        except Exception as e:
            processing_time = time.time() - start_time
            error_msg = str(e)
            self._log_ai_activity(
                operation="severity_classification",
                input_data=vulnerability_data,
                output_data={},
                processing_time=processing_time,
                success=False,
                error_message=error_msg
            )
            logger.error(f"Severity classification failed: {e}")
            return AIResponse(False, {}, error_msg)

    def recommend_attacks(self, target_data: Dict[str, Any]) -> AIResponse:
        """
        Recommend attack strategies for testing.

        Args:
            target_data: Dictionary containing target information

        Returns:
            AIResponse with attack recommendations
        """
        start_time = time.time()
        try:
            prompt = f"""Recommend security testing strategies for this target:

URL: {target_data.get('url', 'N/A')}
Technologies: {', '.join(target_data.get('technologies', []))}
Authentication: {target_data.get('auth_required', 'Unknown')}

Suggest appropriate attack types and testing methodologies.
Consider the technology stack and potential vulnerabilities.

Respond in JSON format with prioritized attack recommendations."""

            raw_response = self._generate_response(prompt)
            processing_time = time.time() - start_time

            try:
                # Extract JSON
                json_start = raw_response.find('{')
                json_end = raw_response.rfind('}') + 1
                if json_start != -1 and json_end > json_start:
                    json_str = raw_response[json_start:json_end]
                    parsed = json.loads(json_str)
                    response = AIResponse(True, parsed, raw_response=raw_response)
                else:
                    response = AIResponse(True, {
                        "recommended_attacks": ["xss", "sqli", "csrf"],
                        "priority": ["High risk endpoints first", "Input validation testing", "Authentication bypass attempts"],
                        "methodology": ["Automated scanning first", "Manual verification", "Exploit development if needed"]
                    }, raw_response=raw_response)

                # Log successful operation
                self._log_ai_activity(
                    operation="attack_recommendation",
                    input_data=target_data,
                    output_data=response.data,
                    processing_time=processing_time,
                    success=True,
                    token_count=len(prompt.split()) if prompt else None,
                    confidence_score=0.7
                )

                return response

            except json.JSONDecodeError:
                error_msg = "Failed to parse attack recommendations"
                self._log_ai_activity(
                    operation="attack_recommendation",
                    input_data=target_data,
                    output_data={},
                    processing_time=processing_time,
                    success=False,
                    error_message=error_msg,
                    token_count=len(prompt.split()) if prompt else None
                )
                return AIResponse(False, {}, error_msg, raw_response)

        except Exception as e:
            processing_time = time.time() - start_time
            error_msg = str(e)
            self._log_ai_activity(
                operation="attack_recommendation",
                input_data=target_data,
                output_data={},
                processing_time=processing_time,
                success=False,
                error_message=error_msg
            )
            logger.error(f"Attack recommendation failed: {e}")
            return AIResponse(False, {}, error_msg)

    def query_model(self, mode: str, data: Dict[str, Any]) -> AIResponse:
        """
        Generic method to query the model with different modes.

        Args:
            mode: Query mode (analyze, audit, classify, recommend)
            data: Input data dictionary

        Returns:
            AIResponse with parsed results
        """
        mode_map = {
            "analyze": self.analyze_vulnerability,
            "audit": self.audit_site,
            "classify": self.classify_severity,
            "recommend": self.recommend_attacks
        }

        if mode not in mode_map:
            return AIResponse(False, {}, f"Unknown mode: {mode}")

        return mode_map[mode](data)


# Global instance
_ai_model: Optional[AIModelInterface] = None


def get_ai_model() -> Optional[AIModelInterface]:
    """Get the global AI model instance."""
    global _ai_model
    if _ai_model is None:
        try:
            _ai_model = AIModelInterface()
        except Exception as e:
            logger.warning(f"Failed to initialize AI model: {e}")
            return None
    return _ai_model
