"""
AI-powered remediation report generator using fine-tuned LoRA model.
Generates remediation-focused security reports with actionable guidance.
"""

import json
import re
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path

import aiohttp


class AIRemedyAnalyzer:
    """
    Generates remediation reports using AI to recommend security fixes.
    """

    def __init__(self, model=None, tokenizer=None):
        """
        Initialize the AI remedy analyzer.

        Args:
            model: Shared LoRA model object (from target_analyzer or elsewhere)
            tokenizer: Shared tokenizer object (from target_analyzer or elsewhere)
        """
        self.model = model
        self.tokenizer = tokenizer
        self.model_available = model is not None and tokenizer is not None

    async def generate_remediation_report(
        self, scan_id: str, target: str, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate a remediation report for the scan findings.

        Args:
            scan_id: Unique scan identifier
            target: Target URL/application
            findings: List of vulnerability findings

        Returns:
            Remediation report with recommendations
        """

        # Prepare findings for AI model
        findings_input = []
        for finding in findings:
            findings_input.append(
                {
                    "type": finding.get("type", "unknown"),
                    "endpoint": finding.get("endpoint", ""),
                    "parameter": finding.get("parameter", ""),
                    "payload": finding.get("payload", ""),
                    "impact": finding.get("impact", "Security vulnerability detected"),
                }
            )

        # Use AI model if available, otherwise use rule-based
        if self.model_available:
            result = await self._ai_remediation(scan_id, target, findings_input)
        else:
            result = self._rule_based_remediation(scan_id, target, findings_input)

        return result

    async def _ai_remediation(
        self,
        scan_id: str,
        target: str,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Use AI backend for remediation generation."""

        input_data = {
            "scan_id": scan_id,
            "target": target,
            "findings": findings,
        }

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=90)
            ) as session:
                async with session.post(
                    "http://127.0.0.1:8090/report",
                    json=input_data,
                    headers={"Content-Type": "application/json"},
                ) as resp:

                    raw = await resp.text()

                    if resp.status != 200:
                        raise RuntimeError(
                            f"AI remediation backend error {resp.status}: {raw[:200]}"
                        )

                    result = json.loads(raw)

                    # ===== basic validation =====
                    if not isinstance(result, dict):
                        raise ValueError("Invalid remediation JSON structure")

                    # Ensure required keys exist (defensive)
                    result.setdefault("success", True)
                    result.setdefault("priority", "Medium")
                    result.setdefault("recommendation", "")
                    result.setdefault("steps", [])
                    result.setdefault("code_example", "")
                    result.setdefault("details", "")

                    result["method"] = "ai-backend"

                    print("✅ AI remediation generated successfully (backend)")
                    return result

        except Exception as e:
            print(f"⚠️ AI remediation failed: {e}")

            return {
                "success": True,
                "method": "ai-backend-failed",
                "priority": "Low",
                "recommendation": "Manual remediation required due to AI backend failure",
                "steps": [
                    "Review the identified findings manually",
                    "Apply standard security best practices",
                    "Re-run the scan after fixes are applied",
                ],
                "code_example": "",
                "details": f"AI remediation backend failed: {str(e)}",
            }

    def _parse_ai_response(self, response: str, findings: List[Dict]) -> Dict[str, Any]:
        """Parse AI response as JSON - now expects structured JSON format from model."""
        try:
            print(f"🔍 Raw AI Response: {response}")

            # Try to parse as JSON first (since we now prompt for JSON output)
            try:
                # Clean up response - remove any leading/trailing whitespace or markdown
                cleaned_response = response.strip()
                if cleaned_response.startswith("```json"):
                    cleaned_response = cleaned_response[7:]
                if cleaned_response.startswith("```"):
                    cleaned_response = cleaned_response[3:]
                if cleaned_response.endswith("```"):
                    cleaned_response = cleaned_response[:-3]

                parsed_json = json.loads(cleaned_response)

                # Validate required fields
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
                    f"✅ Successfully parsed JSON: priority={result['priority']}, steps={len(result['steps'])}"
                )
                return result

            except json.JSONDecodeError:
                # Fallback to regex parsing if JSON parsing fails
                print("⚠️ JSON parsing failed, falling back to regex extraction")

                priority = "Medium"
                steps = []
                code_example = ""
                recommendation = ""
                details = ""

                # Try to find priority
                priority_match = re.search(
                    r'"priority"\s*:\s*"([^"]+)"', response, re.IGNORECASE
                )
                if priority_match:
                    priority = priority_match.group(1)

                # Try to find recommendation
                rec_match = re.search(
                    r'"recommendation"\s*:\s*"([^"]+)"', response, re.IGNORECASE
                )
                if rec_match:
                    recommendation = rec_match.group(1)

                # Try to find steps array
                steps_section = re.search(
                    r'"steps"\s*:\s*\[(.*?)\]', response, re.DOTALL | re.IGNORECASE
                )
                if steps_section:
                    steps_content = steps_section.group(1)
                    step_matches = re.findall(r'"([^"]+)"', steps_content)
                    if step_matches:
                        steps = step_matches

                # Try to find code example
                code_match = re.search(
                    r'"code_example"\s*:\s*"([^"]*)"', response, re.DOTALL
                )
                if code_match:
                    code_example = (
                        code_match.group(1).replace("\\n", "\n").replace('\\"', '"')
                    )

                # Try to find details
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
                    f"✅ Extracted via regex: priority={priority}, steps={len(steps)}"
                )
                return result

        except Exception as e:
            print(f"⚠️ Failed to parse AI response: {e}, returning error")
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

        # Get remedy info for the first finding (since frontend shows one at a time)
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

        # Return format that frontend expects
        return {
            "success": True,
            "method": "rule-based",
            "priority": remedy_info["priority"],
            "steps": remedy_info.get("steps", []),
            "code_example": remedy_info.get("code_example", ""),
            "recommendation": remedy_info["recommendation"],
            "details": remedy_info.get("details", ""),
        }
