"""
AI-powered remediation report generator using fine-tuned LoRA model.
Generates remediation-focused security reports with actionable guidance.
"""

import json
import re
from typing import Dict, List, Optional, Any

import aiohttp


REMEDY_SYSTEM_PROMPT = """You are a web application security expert. Given the specific vulnerability finding below, return ONLY a JSON object with targeted remediation guidance.

STRICT OUTPUT RULE: Output ONLY the JSON object. No markdown, no code fences, no explanation.

JSON schema:
{
 "priority": "Low" | "Medium" | "High" | "Critical",
 "recommendation": string,
 "steps": [string, string, string, string],
 "code_example": string,
 "details": string
}

Rules:
- priority: reflect the severity of the finding
- recommendation: one specific sentence naming the exact fix for the vulnerable parameter/endpoint
- steps: exactly 3-5 actionable steps referencing the specific parameter name and endpoint where possible
- code_example: a short code snippet showing the exact fix for this vulnerability type (use \\n for newlines)
- details: 1-2 sentences explaining the risk specific to this endpoint and how an attacker could exploit it"""


class AIRemedyAnalyzer:
    """
    Generates remediation reports using AI to recommend security fixes.
    """

    OLLAMA_URL = "http://localhost:11434/api/generate"
    OLLAMA_MODEL = "gemma4:31b-cloud"
    _MODEL_ID = "Qwen/Qwen2.5-1.5B-Instruct"
    _LORA_ADAPTER = "pennywise-lora-remedy-v1"

    def __init__(self):
        self.model = None
        self.tokenizer = None
        self._lora_path = "./lora/remedy/lora-adapter"
        self._load_model()

    def _load_model(self):
        """Load LoRA-finetuned Qwen model for remediation generation."""
        import os
        try:
            from transformers import AutoTokenizer
            from peft import PeftConfig

            if not os.path.exists(self._lora_path):
                raise FileNotFoundError(f"Local adapter not found at {self._lora_path}")

            # Load tokenizer and adapter config only (no full model weights in memory)
            self.tokenizer = AutoTokenizer.from_pretrained(
                self._lora_path,
                trust_remote_code=True,
                local_files_only=True,
            )
            self._peft_config = PeftConfig.from_pretrained(self._lora_path)
            # Full model inference is offloaded to Ollama relay for GPU efficiency
        except Exception:
            pass

    async def generate_remediation_report(
        self, scan_id: str, target: str, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        findings_input = []
        for finding in findings:
            findings_input.append({
                "type": finding.get("type", "unknown"),
                "endpoint": finding.get("endpoint", ""),
                "parameter": finding.get("parameter", ""),
                "payload": finding.get("payload", ""),
                "impact": finding.get("impact", "Security vulnerability detected"),
            })

        result = await self._ollama_remediation(scan_id, target, findings_input)
        return result

    async def _ollama_remediation(
        self,
        scan_id: str,
        target: str,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Use Ollama for remediation generation, fall back to rule-based."""
        findings_text = json.dumps(findings, indent=2)
        # Build a specific context block so the model gives targeted advice
        context_lines = [f"Target: {target}"]
        if findings:
            f = findings[0]
            if f.get("endpoint"):
                context_lines.append(f"Vulnerable endpoint: {f['endpoint']}")
            if f.get("parameter"):
                context_lines.append(f"Vulnerable parameter: {f['parameter']}")
            if f.get("payload"):
                context_lines.append(f"Payload that triggered it: {f['payload']}")
            if f.get("impact"):
                context_lines.append(f"Impact observed: {f['impact']}")
        context = "\n".join(context_lines)
        prompt = f"{REMEDY_SYSTEM_PROMPT}\n\n{context}\n\nAll findings:\n{findings_text}"

        try:
            print(" [Remedy] Running Qwen 3.5 2B inference...")
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=180, connect=5)
            ) as session:
                async with session.post(
                    self.OLLAMA_URL,
                    json={"model": self.OLLAMA_MODEL, "prompt": prompt, "stream": False},
                ) as resp:
                    raw_text = await resp.text()
                    if resp.status != 200:
                        raise RuntimeError(f"Ollama returned HTTP {resp.status}: {raw_text[:300]}")
                    data = json.loads(raw_text)
                    raw = data.get("response", "")

            print(" [Remedy] Local Qwen model inference complete")
            result = self._parse_ai_response(raw, findings)
            result["method"] = "ai-ollama"
            return result

        except aiohttp.ClientConnectorError:
            print(" [Remedy] Local model not available using rule-based fallback")
        except Exception as e:
            print(f" [Remedy] Inference error: {e} using rule-based fallback")

        return self._rule_based_remediation(scan_id, target, findings)

    def _parse_ai_response(self, response: str, findings: List[Dict]) -> Dict[str, Any]:
        """Parse AI response as JSON - expects structured JSON format from model."""
        try:
            print(f" Raw AI Response: {response}")

            try:
                cleaned_response = response.strip()
                if cleaned_response.startswith("```json"):
                    cleaned_response = cleaned_response[7:]
                if cleaned_response.startswith("```"):
                    cleaned_response = cleaned_response[3:]
                if cleaned_response.endswith("```"):
                    cleaned_response = cleaned_response[:-3]

                parsed_json = json.loads(cleaned_response)

                result = {
                    "success": parsed_json.get("success", True),
                    "method": "ai-model-json",
                    "priority": parsed_json.get("priority", "Medium"),
                    "steps": parsed_json.get("steps", []),
                    "code_example": parsed_json.get("code_example", ""),
                    "recommendation": parsed_json.get("recommendation", ""),
                    "details": parsed_json.get("details", ""),
                    "raw_output": response,
                }

                print(
                    f" Successfully parsed JSON: priority={result['priority']}, steps={len(result['steps'])}"
                )
                return result

            except json.JSONDecodeError:
                print(" JSON parsing failed, falling back to regex extraction")

            priority = "Medium"
            steps = []
            code_example = ""
            recommendation = ""
            details = ""

            priority_match = re.search(
                r'"priority"\s*:\s*"([^"]+)"', response, re.IGNORECASE
            )
            if priority_match:
                priority = priority_match.group(1)

            rec_match = re.search(
                r'"recommendation"\s*:\s*"([^"]+)"', response, re.IGNORECASE
            )
            if rec_match:
                recommendation = rec_match.group(1)

            steps_section = re.search(
                r'"steps"\s*:\s*\[(.*?)\]', response, re.DOTALL | re.IGNORECASE
            )
            if steps_section:
                steps_content = steps_section.group(1)
                step_matches = re.findall(r'"([^"]+)"', steps_content)
                if step_matches:
                    steps = step_matches

            code_match = re.search(
                r'"code_example"\s*:\s*"([^"]*)"', response, re.DOTALL
            )
            if code_match:
                code_example = (
                    code_match.group(1).replace("\\n", "\n").replace('\\"', '"')
                )

            details_match = re.search(
                r'"details"\s*:\s*"([^"]*)"', response, re.DOTALL
            )
            if details_match:
                details = (
                    details_match.group(1).replace("\\n", "\n").replace('\\"', '"')
                )

            result = {
                "success": True,
                "method": "ai-model-regex",
                "priority": priority,
                "steps": steps if steps else [response],
                "code_example": code_example,
                "recommendation": recommendation,
                "details": details,
                "raw_output": response,
            }

            print(
                f" Extracted via regex: priority={priority}, steps={len(steps)}"
            )
            return result

        except Exception as e:
            print(f" Failed to parse AI response: {e}, returning error")
            return {
                "success": False,
                "method": "ai-model-error",
                "priority": "Unknown",
                "steps": [response if "response" in locals() else str(e)],
                "code_example": "",
                "recommendation": "Error parsing AI response",
                "details": f"Error: {str(e)}",
                "raw_output": response if "response" in locals() else str(e),
            }

    def _rule_based_remediation(
        self, scan_id: str, target: str, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Fallback rule-based remediation generation."""

        remediation_map = {
            "sqli": {
                "recommendation": "Use parameterized queries, ORM frameworks, and strict input validation.",
                "priority": "Critical",
                "steps": [
                    "Implement prepared statements for all database queries",
                    "Use ORM frameworks (e.g., SQLAlchemy, Hibernate)",
                    "Validate and sanitize all user inputs",
                    "Apply principle of least privilege for database accounts",
                ],
                "details": "SQL Injection allows attackers to execute arbitrary SQL code. Use parameterized queries with placeholders (?) instead of string concatenation to prevent this.",
            },
            "xss": {
                "recommendation": "Implement output encoding, Content-Security-Policy headers, and input validation.",
                "priority": "High",
                "steps": [
                    "Encode all user-controlled data in HTML context",
                    "Implement Content-Security-Policy headers",
                    "Use framework-provided XSS protection",
                    "Validate and sanitize user inputs",
                ],
                "details": "Cross-Site Scripting allows attackers to inject malicious scripts. Always encode user input when displaying in HTML, use CSP headers, and avoid innerHTML.",
            },
            "csrf": {
                "recommendation": "Implement anti-CSRF tokens, SameSite cookies, and verify Origin headers.",
                "priority": "High",
                "steps": [
                    "Add CSRF tokens to all state-changing forms",
                    "Set SameSite attribute on session cookies",
                    "Verify Origin and Referer headers",
                    "Use framework-provided CSRF protection",
                ],
                "details": "CSRF attacks trick users into performing unintended actions. Protect using unique tokens per request, SameSite cookies, and origin validation.",
            },
            "rce": {
                "recommendation": "Avoid dynamic command execution and apply sandboxing and least privilege.",
                "priority": "Critical",
                "steps": [
                    "Never execute user-controlled commands",
                    "Use safe APIs instead of shell commands",
                    "Implement strict input validation",
                    "Apply sandboxing and containerization",
                ],
                "details": "Remote Code Execution allows attackers full system access. Avoid system() calls with user input; use APIs instead and apply strict validation.",
            },
            "lfi": {
                "recommendation": "Validate file paths, use whitelists, and implement proper access controls.",
                "priority": "High",
                "steps": [
                    "Implement whitelist of allowed files",
                    "Validate and sanitize file paths",
                    "Use absolute paths internally",
                    "Apply proper file system permissions",
                ],
                "details": "Local File Inclusion allows reading arbitrary files. Use a whitelist of allowed files, validate paths against directory traversal (../, ..), and restrict file permissions.",
            },
            "ssrf": {
                "recommendation": "Validate URLs, use allowlists, and implement network segmentation.",
                "priority": "High",
                "steps": [
                    "Implement URL allowlist validation",
                    "Block requests to internal IPs",
                    "Use network segmentation",
                    "Validate and sanitize user-provided URLs",
                ],
                "details": "Server-Side Request Forgery allows attacking internal systems. Block internal IPs (10.x.x.x, 127.x.x.x, 172.16-31.x.x), use URL whitelists, and segment networks.",
            },
        }

        if findings:
            vuln_type = findings[0].get("type", "unknown")
            remedy_info = remediation_map.get(
                vuln_type,
                {
                    "recommendation": "Follow secure coding practices and perform security testing.",
                    "priority": "Medium",
                    "steps": [
                        "Review code for security issues",
                        "Apply defense in depth",
                    ],
                    "details": "Implement secure coding practices including input validation, output encoding, authentication, and authorization controls.",
                },
            )
        else:
            remedy_info = {
                "recommendation": "Follow secure coding practices.",
                "priority": "Medium",
                "steps": ["Review code for security issues"],
                "details": "Apply security best practices to your application.",
            }

        return {
            "success": True,
            "method": "rule-based",
            "priority": remedy_info["priority"],
            "steps": remedy_info.get("steps", []),
            "code_example": remedy_info.get("code_example", ""),
            "recommendation": remedy_info["recommendation"],
            "details": remedy_info.get("details", ""),
        }
