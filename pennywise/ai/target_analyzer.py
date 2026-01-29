"""
AI-powered target analysis using fine-tuned LoRA model.
Analyzes website structure and recommends security scans.
"""

import json
import re
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path

SYSTEM_PROMPT = """You are a web application security vulnerability classifier.
Your ONLY allowed output is valid JSON matching this EXACT schema. Nothing else is permitted.

{
  "overall_risk": "low" | "medium" | "high",
  "scan_suggestions": [string],
  "vulnerabilities": [
    {
      "type": string,
      "severity": "low" | "medium" | "high",
      "description": string,
      "evidence": string
    }
  ]
}

STRICT RULES — YOU MUST OBEY ALL OF THEM:
- Output ONLY the JSON object above. NO other text before, after, or inside.
- NO explanations, NO reasoning, NO markdown, NO code blocks, NO ```json, NO apologies.
- NO natural language sentences at all — only the JSON structure.
- "scan_suggestions" MUST contain ONLY values from this list (lowercase, no others): ["xss", "sqli", "csrf", "idor", "open_redirect", "auth", "cors", "file_upload", "directory_listing", "insecure_headers"]
- "vulnerabilities[].type" MUST be one of the same allowed values above.
- "scan_suggestions" entries MUST be unique (no duplicates).
- Use ONLY these severity levels: "low", "medium", "high"
- If no vulnerabilities are found → "vulnerabilities": [], "overall_risk": "low"
- Even if evidence is weak or indirect, infer likely issues when controls are missing.
- Missing headers / CSP / tokens / protections → infer corresponding issues.
- Do NOT add any extra fields, comments, or trailing commas.
- The JSON must be valid and parseable — no syntax errors.

You will now receive website data. Respond with JSON only."""


class AITargetAnalyzer:
    """
    Analyzes target websites using AI to recommend attack types.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the AI analyzer.

        Args:
            model_path: Path to the LoRA model (optional, will try to load if available)
        """
        self.model = None
        self.tokenizer = None
        self.model_available = False
        self._loading = False

        if model_path:
            # Load model in separate thread to avoid blocking
            print("🔄 Loading AI model in background...")
            self._loading = True
            load_thread = threading.Thread(
                target=self._load_model_thread, args=(model_path,), daemon=True
            )
            load_thread.start()

    def _load_model_thread(self, model_path: str):
        try:
            self._load_model(model_path)
        except Exception as e:
            print(f"⚠️ Could not load AI model: {e}")
            print("   Falling back to rule-based analysis")
        finally:
            self._loading = False

    def _load_model(self, model_path: str):
        try:
            import torch
            from transformers import (
                AutoTokenizer,
                AutoModelForCausalLM,
                BitsAndBytesConfig,
            )

            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",
            )
            model_id = "Qwen/Qwen3-1.7B"

            tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                device_map="auto",
                trust_remote_code=True,
                quantization_config=quantization_config,
            )
            model.config.use_cache = False
            self.tokenizer = tokenizer
            self.model = model

            self.model.eval()
            self.model_available = True
            print("✅ AI model loaded successfully")

        except ImportError:
            print("⚠️ Required libraries not found (torch, transformers, peft)")
            self.model_available = False
        except Exception as e:
            print(f"⚠️ Error loading model: {e}")
            self.model_available = False

    async def analyze_target(
        self,
        url: str,
        html_content: str,
        headers: Dict[str, str],
        forms: List[Dict[str, Any]],
        tech_stack: List[str],
    ) -> Dict[str, Any]:
        """
        Analyze a target website and recommend security scans.

        Args:
            url: Target URL
            html_content: HTML content of the page
            headers: HTTP response headers
            forms: List of detected forms
            tech_stack: Detected technologies

        Returns:
            Analysis result with recommended attack types and reasoning
        """
        # Extract relevant information
        html_snippet = self._extract_html_snippet(html_content)
        forms_summary = self._summarize_forms(forms)
        headers_summary = self._summarize_headers(headers)
        tech_summary = ", ".join(tech_stack) if tech_stack else "Unknown"

        # Use AI model if available, otherwise use rule-based analysis
        if self.model_available:
            result = await self._ai_analysis(
                html_snippet, forms_summary, headers_summary, tech_summary
            )
        else:
            result = self._rule_based_analysis(
                html_snippet, forms_summary, headers_summary, tech_summary
            )

        return result

    def _extract_html_snippet(self, html_content: str, max_length: int = 50000) -> str:
        """Extract relevant HTML snippet for analysis."""
        if not html_content:
            return ""

        # Focus on forms, inputs, and scripts
        patterns = [
            r"<form[^>]*>.*?</form>",
            r"<input[^>]*>",
            r"<script[^>]*>.*?</script>",
            r"<a[^>]*href[^>]*>",
        ]

        snippets = []
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
            snippets.extend(matches[:3])  # Take first 3 of each type

        snippet = "\n".join(snippets)
        if len(snippet) > max_length:
            snippet = snippet[:max_length] + "..."

        return snippet or html_content[:max_length]

    def _summarize_forms(self, forms: List[Dict[str, Any]]) -> str:
        """Create a text summary of detected forms."""
        if not forms:
            return "No forms detected"

        summary = []
        for form in forms[:5]:  # Limit to 5 forms
            method = form.get("method", "GET").upper()
            action = form.get("action", "/")
            inputs = form.get("inputs", [])
            input_names = [inp.get("name", "") for inp in inputs if inp.get("name")]

            has_csrf = any(
                "csrf" in inp.get("name", "").lower()
                or "token" in inp.get("name", "").lower()
                for inp in inputs
            )

            summary.append(f"- {method} {action}")
            if input_names:
                summary.append(f"  Inputs: {', '.join(input_names)}")
            summary.append(
                f"  CSRF token: {'detected' if has_csrf else 'not detected'}"
            )

        return "\n".join(summary)

    def _summarize_headers(self, headers: Dict[str, str]) -> str:
        """Create a text summary of security-relevant headers."""
        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
        ]

        summary = []
        for header in security_headers:
            if header.lower() in [h.lower() for h in headers.keys()]:
                summary.append(f"- {header}: present")
            else:
                summary.append(f"- {header}: missing")

        return "\n".join(summary)

    async def _ai_analysis(
        self,
        html_snippet: str,
        forms_summary: str,
        headers_summary: str,
        tech_summary: str,
    ) -> Dict[str, Any]:

        try:
            import torch

            # Assuming self.tokenizer and self.model are already loaded
            # e.g. from transformers import AutoTokenizer, AutoModelForCausalLM
            # with quantization if needed for RTX 3050 (4-bit / 8-bit)

            # Build the full prompt using chat template (recommended for instruct models)
            # This handles system + user formatting automatically
            messages = [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": f"""Analyze the following website structure.

HTML_SNIPPET:
{html_snippet}

FORMS_SUMMARY:
{forms_summary}

HEADERS_SUMMARY:
{headers_summary}

TECH_STACK:
{tech_summary}
""",
                },
            ]

            prompt = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,  # Adds the assistant prefix
                enable_thinking=False,
            )

            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)

            if self.tokenizer.pad_token_id is None:
                self.tokenizer.pad_token_id = self.tokenizer.eos_token_id

            with torch.no_grad():
                out = self.model.generate(
                    **inputs,
                    max_new_tokens=1024,
                    repetition_penalty=1.05,
                    do_sample=False,
                    eos_token_id=self.tokenizer.eos_token_id,
                    pad_token_id=self.tokenizer.pad_token_id,
                    use_cache=True,
                )

            full_response = self.tokenizer.decode(out[0], skip_special_tokens=True)

            if "<|assistant|>" in full_response:
                response = full_response.split("<|assistant|>", 1)[-1].strip()
            elif "assistant" in full_response.lower():  # fallback heuristic
                # Try to cut after last "assistant" marker (case insensitive)
                idx = full_response.lower().rfind("assistant")
                if idx != -1:
                    response = full_response[idx + len("assistant") :].strip()
                else:
                    response = full_response.strip()
            else:
                response = full_response.strip()

            response = response.replace("<|endoftext|>", "").strip()
            result = self._parse_ai_response(response)
            return result

        except Exception as e:
            print(f"⚠️ AI analysis failed: {e}")
            return self._rule_based_analysis(
                html_snippet, forms_summary, headers_summary, tech_summary
            )

    def _parse_ai_response(self, response: str) -> Dict[str, Any]:
        try:
            response = response.replace("</think>", "").replace("<think>", "").strip()
            result = json.loads(response)

            # Extract overall risk
            overall_risk = result.get("overall_risk", "low")
            
            # Extract scan suggestions (list of attack types)
            scan_suggestions = result.get("scan_suggestions", [])
            
            # Extract vulnerabilities array with type, severity, description, evidence
            vulnerabilities_list = result.get("vulnerabilities", [])
            
            # If using old format, fall back to legacy parsing
            if not vulnerabilities_list and ("scan_result" in result or "variant" in result):
                return self._parse_legacy_response(result)
            
            # Format vulnerabilities for compatibility
            formatted_vulnerabilities = []
            for vuln in vulnerabilities_list:
                if isinstance(vuln, dict):
                    formatted_vulnerabilities.append({
                        "type": vuln.get("type", "unknown"),
                        "severity": vuln.get("severity", "low"),
                        "description": vuln.get("description", ""),
                        "evidence": vuln.get("evidence", "")
                    })
                else:
                    # String format fallback
                    formatted_vulnerabilities.append({
                        "type": str(vuln),
                        "severity": "low",
                        "description": f"{str(vuln)} vulnerability detected",
                        "evidence": ""
                    })
            
            # Map vulnerability types to attack types
            attack_types = scan_suggestions if scan_suggestions else self._extract_attack_types(formatted_vulnerabilities)
            
            # Build final response
            response_data = {
                "success": True,
                "overall_risk": overall_risk,
                "attack_types": attack_types,
                "scan_suggestions": scan_suggestions,
                "vulnerabilities": formatted_vulnerabilities,
                "reasoning": f"Risk level: {overall_risk}. Detected {len(formatted_vulnerabilities)} vulnerabilities.",
                "method": "ai",
                "raw_response": response,
            }

            return response_data

        except Exception as e:
            print(f"⚠️ Failed to parse AI response: {e}")
            print(f"   Raw response: {response[:200]}...")

            # Return the raw response for UI display
            return {
                "success": False,
                "error": f"JSON Parse Error: {str(e)}",
                "raw_response": response,
                "attack_types": ["xss", "sqli", "csrf"],  # Default fallback
                "method": "parse-error",
                "reasoning": f"Unable to parse AI model output. Error: {str(e)}",
                "vulnerabilities": [],
                "recommendation": {},
            }
    
    def _parse_legacy_response(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse responses in the old format for backward compatibility."""
        vulnerabilities = []
        if "scan_result" in result and "vulnerabilities" in result["scan_result"]:
            vulnerabilities = result["scan_result"]["vulnerabilities"]
        elif "vulnerabilities" in result:
            vulnerabilities = result["vulnerabilities"]
        elif "variant" in result and "name" in result["variant"]:
            vulnerabilities = [result["variant"]["name"]]
        elif "status" in result and result["status"] == "VULN":
            if "variant" in result:
                vulnerabilities = [result["variant"].get("name", "Unknown")]

            reasoning = ""
            if "reasoning" in result:
                reasoning = result["reasoning"]
            elif "scan_result" in result and "reasoning" in result["scan_result"]:
                reasoning = result["scan_result"]["reasoning"]
            elif "variant" in result and "details" in result["variant"]:
                # Format reasoning from variant details
                vuln_name = result["variant"].get("name", "Unknown")
                details = result["variant"].get("details", [])
                if details:
                    reasoning = f"{vuln_name} detected: {', '.join(details)}"
                else:
                    reasoning = f"{vuln_name} vulnerability detected"

                # Add impact info if present
                if "impact" in result["variant"]:
                    impact = result["variant"]["impact"]
                    impact_str = ", ".join([k for k, v in impact.items() if v])
                    if impact_str:
                        reasoning += f" (Impact: {impact_str})"

            recommendation = result.get("recommendation", {})

            # Normalize recommendation format
            if "scan" in recommendation and isinstance(recommendation["scan"], list):
                # Convert scan URLs to action format
                recommendation["action"] = [
                    f"Scan endpoint: {url}" for url in recommendation["scan"][:3]
                ]

            # Map vulnerability names to attack types
            attack_types = self._map_vulnerabilities_to_attacks(vulnerabilities)

            # Build final response
            response_data = {
                "success": True,
                "attack_types": attack_types,
                "vulnerabilities": vulnerabilities,
                "reasoning": reasoning,
                "recommendation": recommendation,
                "method": "ai",
                "raw_response": result,
            }

            # Add status if present
            if "status" in result:
                response_data["status"] = result["status"]

            return response_data
    
    def _extract_attack_types(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Extract unique attack types from vulnerabilities list."""
        attack_types = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "").lower()
            if vuln_type and vuln_type not in attack_types:
                attack_types.append(vuln_type)
        return attack_types

    def _repair_json(self, json_text: str) -> str:
        """Attempt to repair common JSON formatting issues."""
        # Remove any trailing commas before closing braces/brackets
        json_text = re.sub(r",(\s*[}\]])", r"\1", json_text)

        # Track bracket/brace stack to properly close/remove them
        stack = []
        result = []
        i = 0
        in_string = False
        escape_next = False

        while i < len(json_text):
            char = json_text[i]

            # Handle string escaping
            if escape_next:
                escape_next = False
                result.append(char)
                i += 1
                continue

            if char == "\\":
                escape_next = True
                result.append(char)
                i += 1
                continue

            # Toggle string state
            if char == '"':
                in_string = not in_string
                result.append(char)
                i += 1
                continue

            # If we're in a string, just copy
            if in_string:
                result.append(char)
                i += 1
                continue

            # Track brackets/braces
            if char == "{":
                stack.append("{")
                result.append(char)
            elif char == "[":
                stack.append("[")
                result.append(char)
            elif char == "}":
                if stack and stack[-1] == "{":
                    stack.pop()
                    result.append(char)
                elif stack and stack[-1] == "[":
                    # Wrong closer - fix it
                    stack.pop()
                    result.append("]")
                else:
                    # Extra closing brace - skip it
                    pass
            elif char == "]":
                if stack and stack[-1] == "[":
                    stack.pop()
                    result.append(char)
                elif stack and stack[-1] == "{":
                    # Wrong closer - fix it
                    stack.pop()
                    result.append("}")
                else:
                    # Extra closing bracket - skip it
                    pass
            else:
                result.append(char)

            i += 1

        # Close any remaining open brackets/braces
        while stack:
            opener = stack.pop()
            if opener == "{":
                result.append("}")
            elif opener == "[":
                result.append("]")

        return "".join(result)

    def _map_vulnerabilities_to_attacks(self, vulnerabilities: List[str]) -> List[str]:
        """Map vulnerability names to PennyWise attack types."""
        mapping = {
            "xss": [
                "xss",
                "cross-site scripting",
                "reflected xss",
                "stored xss",
                "dom xss",
            ],
            "sqli": ["sqli", "sql injection", "sql", "database injection"],
            "csrf": ["csrf", "xsrf", "cross-site request forgery"],
            "lfi": ["lfi", "local file inclusion", "file inclusion", "path traversal"],
            "rce": [
                "rce",
                "remote code execution",
                "command injection",
                "code injection",
            ],
            "xxe": ["xxe", "xml external entity"],
            "ssrf": ["ssrf", "server-side request forgery"],
        }

        attack_types = []
        for vuln in vulnerabilities:
            vuln_lower = vuln.lower()
            for attack_type, keywords in mapping.items():
                if any(keyword in vuln_lower for keyword in keywords):
                    if attack_type not in attack_types:
                        attack_types.append(attack_type)

        # If no matches, return common types
        if not attack_types:
            attack_types = ["xss", "sqli", "csrf"]

        return attack_types

    def _rule_based_analysis(
        self,
        html_snippet: str,
        forms_summary: str,
        headers_summary: str,
        tech_summary: str,
    ) -> Dict[str, Any]:
        """Fallback rule-based analysis when AI is not available."""
        vulnerabilities = []
        attack_types = []
        reasoning_parts = []

        # Check for forms without CSRF protection
        if "csrf token: not detected" in forms_summary.lower():
            vulnerabilities.append("CSRF")
            attack_types.append("csrf")
            reasoning_parts.append(
                "Forms detected without CSRF tokens - vulnerable to Cross-Site Request Forgery."
            )

        # Check for input fields (potential XSS/SQLi)
        if "input" in html_snippet.lower() or "form" in forms_summary.lower():
            vulnerabilities.append("XSS")
            attack_types.append("xss")
            reasoning_parts.append(
                "Input fields detected - potential Cross-Site Scripting vulnerability."
            )

            if any(
                db in tech_summary.lower()
                for db in ["mysql", "postgres", "sql", "database"]
            ):
                vulnerabilities.append("SQL Injection")
                attack_types.append("sqli")
                reasoning_parts.append(
                    "Database technology detected with input fields - potential SQL Injection."
                )

        # Check for missing security headers
        if "content-security-policy: missing" in headers_summary.lower():
            if "XSS" not in vulnerabilities:
                vulnerabilities.append("XSS")
                attack_types.append("xss")
            reasoning_parts.append(
                "Missing Content-Security-Policy header increases XSS risk."
            )

        # Check for file-related vulnerabilities
        if any(
            keyword in html_snippet.lower()
            for keyword in ["file", "upload", "download", "include"]
        ):
            vulnerabilities.append("LFI")
            attack_types.append("lfi")
            reasoning_parts.append(
                "File operations detected - potential Local File Inclusion vulnerability."
            )

        # Default scans if nothing detected
        if not attack_types:
            attack_types = ["xss", "sqli", "csrf"]
            reasoning_parts.append(
                "Performing standard security scans (XSS, SQLi, CSRF)."
            )

        return {
            "success": True,
            "attack_types": list(set(attack_types)),  # Remove duplicates
            "vulnerabilities": vulnerabilities,
            "reasoning": " ".join(reasoning_parts),
            "recommendation": {
                "scan_details": forms_summary.split("\n"),
                "action": [f"Test for {v}" for v in vulnerabilities],
            },
            "method": "rule-based",
        }
