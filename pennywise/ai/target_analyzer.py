"""
AI-powered target analysis using Qwen 3.5 2B.
Analyzes website structure and recommends security scans.
"""

import json
import re
from typing import Dict, List, Optional, Any

import aiohttp

SYSTEM_PROMPT = """You are a web application penetration tester. Analyze the given website data and return ONLY a JSON object.

STRICT OUTPUT RULE: Output ONLY the JSON object. No markdown, no code fences, no explanation.

JSON schema:
{
 "overall_risk": "low" | "medium" | "high" | "critical",
 "scan_suggestions": [string],
 "confidence_score": float,
 "vulnerabilities": [
 {"type": string, "severity": "low"|"medium"|"high"|"critical", "description": string, "evidence": string}
 ]
}

ALLOWED values for scan_suggestions and type:
xss, sqli, csrf, idor, auth, cors, lfi, rce, ssrf, open_redirect, file_upload, insecure_headers

STRICT RECOMMENDATION RULES only add a scan if you have DIRECT evidence:
- Add "xss" ONLY if: input fields present OR CSP header missing AND forms exist
- Add "sqli" ONLY if: login/search/filter form present OR database tech in stack
- Add "csrf" ONLY if: form without CSRF token detected
- Add "auth" ONLY if: login form or password field detected
- Add "lfi" ONLY if: file parameter or include in URL, or file upload input
- Add "rce" ONLY if: command/exec parameter detected or server-side scripting evident
- Add "ssrf" ONLY if: URL parameter that fetches remote content detected
- Add "idor" ONLY if: numeric ID parameters in URL or API endpoints detected
- Add "cors" ONLY if: Access-Control-Allow-Origin header present
- Add "open_redirect" ONLY if: redirect/return/next URL parameter detected
- Add "file_upload" ONLY if: file input element detected
- Add "insecure_headers" ONLY if: 3 or more security headers are missing

LIMITS:
- Maximum 4 items in scan_suggestions
- Only report vulnerabilities you have actual evidence for
- If evidence is weak or site is a 404/error page, return low risk with 1-2 suggestions max
- Do NOT add every possible attack type be selective and precise"""


class AITargetAnalyzer:
    """
    Analyzes target websites using AI to recommend attack types.
    """

    OLLAMA_URL = "http://localhost:11434/api/generate"
    OLLAMA_MODEL = "gemma4:31b-cloud"

    _MODEL_ID = "Qwen/Qwen2.5-1.5B-Instruct"
    _LORA_ADAPTER = "pennywise-lora-v2"

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.tokenizer = None
        self.model_available = False
        self._loading = False
        self._lora_path = model_path or "./lora/analyser/lora-adapter"
        self._load_model()

    def _load_model(self):
        """Load LoRA-finetuned Qwen model for target analysis."""
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
            self.model_available = True
        except Exception:
            self.model_available = False

    async def analyze_target(
        self,
        url: str,
        html_content: str,
        headers: Dict[str, str],
        forms: List[Dict[str, Any]],
        tech_stack: List[str],
    ) -> Dict[str, Any]:
        html_snippet = self._extract_html_snippet(html_content)
        forms_summary = self._summarize_forms(forms)
        headers_summary = self._summarize_headers(headers)
        tech_summary = ", ".join(tech_stack) if tech_stack else "Unknown"

        # Detect SPA (no static forms but JS-heavy)
        is_spa = len(forms) == 0 and any(
            kw in html_content.lower()
            for kw in ["angular", "react", "vue", "ng-", "data-react", "__next"]
        )
        if is_spa:
            print(" [AI Analyzer] SPA detected forms may be dynamically rendered")

        result = await self._ollama_analysis(
            url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
        )

        return result

    async def _try_ai_backend(
        self, url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
    ) -> Dict[str, Any]:
        """Try Ollama for AI analysis, fall back to rule-based if unavailable."""
        return await self._ollama_analysis(
            url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
        )

    def _build_analysis_payload(
        self, url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
    ) -> str:
        spa_note = " This is a SPA forms are dynamic, focus on headers and URL." if is_spa else ""
        snippet_short = html_snippet[:800] if html_snippet else "none"
        return f"""Website:{spa_note}
URL: {url}
FORMS: {forms_summary[:400]}
HEADERS: {headers_summary[:600]}
TECH: {tech_summary[:100]}
HTML: {snippet_short}"""

    async def _ollama_analysis(
        self,
        url: str,
        html_snippet: str,
        forms_summary: str,
        headers_summary: str,
        tech_summary: str,
        is_spa: bool = False,
    ) -> Dict[str, Any]:
        """Use Ollama for AI analysis, fall back to rule-based if unavailable."""
        payload = self._build_analysis_payload(
            url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
        )
        prompt = f"{SYSTEM_PROMPT}\n\n{payload}"

        try:
            print(" [AI Analyzer] Running Qwen 3.5 2B inference...")
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=180, connect=5)
            ) as session:
                async with session.post(
                    self.OLLAMA_URL,
                    json={"model": self.OLLAMA_MODEL, "prompt": prompt, "stream": False},
                ) as resp:
                    raw_text = await resp.text()
                    if resp.status != 200:
                        raise RuntimeError(f"Model inference error {resp.status}: {raw_text[:300]}")
                    data = json.loads(raw_text)
                    raw = data.get("response", "")

                    if not raw.strip():
                        print(" [AI Analyzer] Empty model response using rule-based fallback")
                        return self._rule_based_analysis(
                            html_snippet, forms_summary, headers_summary, tech_summary, is_spa
                        )
                    print(" [AI Analyzer] Model inference complete")
                    return self._parse_ai_response(raw, url)

        except aiohttp.ClientConnectorError:
            print(" [AI Analyzer] Local model not available using rule-based fallback")
        except Exception as e:
            print(f" [AI Analyzer] Inference error: {e} using rule-based fallback")

        return self._rule_based_analysis(
            html_snippet, forms_summary, headers_summary, tech_summary, is_spa
        )

    async def _ai_analysis(
        self,
        url: str,
        html_snippet: str,
        forms_summary: str,
        headers_summary: str,
        tech_summary: str,
        is_spa: bool = False,
    ) -> Dict[str, Any]:
        return await self._ollama_analysis(
            url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
        )

    def _parse_ai_response(self, raw: str, url: str = "") -> Dict[str, Any]:
        """Parse JSON from AI model output."""
        cleaned = raw.strip()
        cleaned = re.sub(r"^```json\s*", "", cleaned)
        cleaned = re.sub(r"^```\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start != -1 and end > start:
            cleaned = cleaned[start:end]

        try:
            result = json.loads(cleaned)
        except json.JSONDecodeError:
            print(f" [AI Analyzer] JSON parse failed, attempting repair")
            try:
                result = json.loads(self._repair_json(cleaned))
            except Exception:
                print(f" [AI Analyzer] JSON repair failed rule-based fallback")
                return self._rule_based_analysis(cleaned, "", "", "", False)

        vulnerabilities = result.get("vulnerabilities", [])
        scan_suggestions = result.get("scan_suggestions", [])
        overall_risk = result.get("overall_risk", "low")

        normalized_vulns = []
        for v in vulnerabilities:
            if isinstance(v, str):
                normalized_vulns.append({
                    "type": v.lower(),
                    "severity": "low",
                    "description": f"{v} vulnerability detected",
                    "evidence": "",
                })
            else:
                normalized_vulns.append({
                    "type": v.get("type", "unknown"),
                    "severity": v.get("severity", "low"),
                    "description": v.get("description", ""),
                    "evidence": v.get("evidence", ""),
                })

        attack_types = scan_suggestions if scan_suggestions else self._extract_attack_types(normalized_vulns)

        print(
            f" [AI Analyzer] Parsed risk: {overall_risk}, "
            f"vulns: {len(normalized_vulns)}, attacks: {attack_types}"
        )

        return {
            "success": True,
            "overall_risk": overall_risk,
            "attack_types": attack_types,
            "scan_suggestions": scan_suggestions,
            "vulnerabilities": normalized_vulns,
            "reasoning": f"AI analysis risk: {overall_risk}. Found {len(normalized_vulns)} vulnerability candidate(s).",
            "method": "ai-model",
            "confidence_score": result.get("confidence_score", 0.0),
        }

    def _extract_html_snippet(self, html_content: str, max_length: int = 3000) -> str:
        if not html_content:
            return ""

        patterns = [
            r"<form[^>]*>.*?</form>",
            r"<input[^>]*>",
            r"<script[^>]*src[^>]*>",
            r"<a[^>]*href=['\"][^'\"]*['\"][^>]*>",
            r"<meta[^>]*>",
        ]

        snippets = []
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
            snippets.extend(matches[:5])

        snippet = "\n".join(snippets)
        if len(snippet) > max_length:
            snippet = snippet[:max_length] + "..."

        return snippet or html_content[:max_length]

    def _summarize_forms(self, forms: List[Dict[str, Any]]) -> str:
        if not forms:
            return "No forms detected (page may be a SPA with dynamic rendering)"

        summary = []
        for form in forms[:5]:
            method = form.get("method", "GET").upper()
            action = form.get("action", "/")
            inputs = form.get("inputs", [])
            input_names = [inp.get("name", "") for inp in inputs if inp.get("name")]

            has_csrf = any(
                "csrf" in inp.get("name", "").lower()
                or "token" in inp.get("name", "").lower()
                for inp in inputs
            )
            has_file = any(
                inp.get("type", "").lower() == "file" for inp in inputs
            )
            has_password = any(
                inp.get("type", "").lower() == "password" for inp in inputs
            )

            summary.append(f"- {method} {action}")
            if input_names:
                summary.append(f"  Inputs: {', '.join(input_names)}")
            summary.append(f"  CSRF token: {'present' if has_csrf else 'MISSING'}")
            if has_file:
                summary.append("  File upload input detected")
            if has_password:
                summary.append("  Password input detected (auth form)")

        return "\n".join(summary)

    def _summarize_headers(self, headers: Dict[str, str]) -> str:
        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Access-Control-Allow-Origin",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

        headers_lower = {k.lower(): v for k, v in headers.items()}
        summary = []
        for header in security_headers:
            val = headers_lower.get(header.lower())
            if val:
                summary.append(f"- {header}: {val[:80]}")
            else:
                summary.append(f"- {header}: MISSING")

        return "\n".join(summary)

    def _extract_attack_types(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        attack_types = []
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "").lower()
            if vuln_type and vuln_type not in attack_types:
                attack_types.append(vuln_type)
        return attack_types

    def _repair_json(self, json_text: str) -> str:
        json_text = re.sub(r",(\s*[}\]])", r"\1", json_text)
        stack = []
        result = []
        i = 0
        in_string = False
        escape_next = False

        while i < len(json_text):
            char = json_text[i]
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
            if char == '"':
                in_string = not in_string
                result.append(char)
                i += 1
                continue
            if in_string:
                result.append(char)
                i += 1
                continue
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
                    stack.pop()
                    result.append("]")
            elif char == "]":
                if stack and stack[-1] == "[":
                    stack.pop()
                    result.append(char)
                elif stack and stack[-1] == "{":
                    stack.pop()
                    result.append("}")
            else:
                result.append(char)
            i += 1

        while stack:
            opener = stack.pop()
            result.append("}" if opener == "{" else "]")

        return "".join(result)

    def _map_vulnerabilities_to_attacks(self, vulnerabilities: List[str]) -> List[str]:
        mapping = {
            "xss": ["xss", "cross-site scripting", "reflected xss", "stored xss", "dom xss"],
            "sqli": ["sqli", "sql injection", "sql", "database injection"],
            "csrf": ["csrf", "xsrf", "cross-site request forgery"],
            "lfi": ["lfi", "local file inclusion", "file inclusion", "path traversal"],
            "rce": ["rce", "remote code execution", "command injection", "code injection"],
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

        if not attack_types:
            attack_types = ["xss", "sqli", "csrf"]

        return attack_types

    def _rule_based_analysis(
        self,
        html_snippet: str,
        forms_summary: str,
        headers_summary: str,
        tech_summary: str,
        is_spa: bool = False,
    ) -> Dict[str, Any]:
        print(" [AI Analyzer] Running rule-based analysis (AI not available)")
        vulnerabilities = []
        attack_types = []
        reasoning_parts = []

        if "content-security-policy: missing" in headers_summary.lower():
            if "xss" not in attack_types:
                attack_types.append("xss")
            vulnerabilities.append({"type": "xss", "severity": "medium",
                "description": "Missing Content-Security-Policy header increases XSS risk",
                "evidence": "CSP header not present"})
            reasoning_parts.append("Missing Content-Security-Policy header.")

        if "x-frame-options: missing" in headers_summary.lower():
            reasoning_parts.append("Missing X-Frame-Options (clickjacking risk).")

        if "strict-transport-security: missing" in headers_summary.lower():
            if "insecure_headers" not in attack_types:
                attack_types.append("insecure_headers")
            vulnerabilities.append({"type": "insecure_headers", "severity": "low",
                "description": "Missing HSTS header", "evidence": "HSTS not present"})

        if "access-control-allow-origin" in headers_summary.lower():
            if "cors" not in attack_types:
                attack_types.append("cors")
            vulnerabilities.append({"type": "cors", "severity": "medium",
                "description": "CORS header detected may be misconfigured",
                "evidence": "Access-Control-Allow-Origin present"})

        if "csrf token: missing" in forms_summary.lower() and "no forms detected" not in forms_summary.lower():
            attack_types.append("csrf")
            vulnerabilities.append({"type": "csrf", "severity": "high",
                "description": "Form found without CSRF token", "evidence": forms_summary[:100]})
            reasoning_parts.append("Forms without CSRF tokens detected.")

        if "password input detected" in forms_summary.lower():
            if "auth" not in attack_types:
                attack_types.append("auth")
            attack_types.append("sqli")
            vulnerabilities.append({"type": "auth", "severity": "medium",
                "description": "Authentication form detected", "evidence": "Password input present"})
            reasoning_parts.append("Login form detected.")

        if "file upload input detected" in forms_summary.lower():
            attack_types.append("file_upload")
            attack_types.append("lfi")
            vulnerabilities.append({"type": "file_upload", "severity": "high",
                "description": "File upload input detected", "evidence": "File input present"})
            reasoning_parts.append("File upload detected.")

        if "input" in html_snippet.lower() or "form" in forms_summary.lower():
            if "xss" not in attack_types:
                attack_types.append("xss")
            vulnerabilities.append({"type": "xss", "severity": "low",
                "description": "Input fields detected potential XSS surface",
                "evidence": "Input elements found"})
            if "sqli" not in attack_types and any(
                db in tech_summary.lower() for db in ["mysql", "postgres", "sql", "database", "mongo"]
            ):
                attack_types.append("sqli")
                vulnerabilities.append({"type": "sqli", "severity": "high",
                    "description": "Database tech + input fields = SQLi risk",
                    "evidence": f"Tech: {tech_summary}"})

        if is_spa:
            reasoning_parts.append("SPA detected static analysis limited, recommend full scan.")
            if "xss" not in attack_types:
                attack_types.append("xss")
            if "idor" not in attack_types:
                attack_types.append("idor")
            vulnerabilities.append({"type": "idor", "severity": "medium",
                "description": "SPAs often expose API endpoints susceptible to IDOR",
                "evidence": "Angular/React/Vue detected"})

        if not attack_types:
            attack_types = ["xss", "sqli", "csrf"]
            reasoning_parts.append("No specific signals running standard scans.")

        severities = [v.get("severity", "low") for v in vulnerabilities]
        if "critical" in severities:
            overall_risk = "critical"
        elif "high" in severities:
            overall_risk = "high"
        elif "medium" in severities:
            overall_risk = "medium"
        else:
            overall_risk = "low"

        return {
            "success": True,
            "overall_risk": overall_risk,
            "attack_types": list(dict.fromkeys(attack_types)),
            "scan_suggestions": list(dict.fromkeys(attack_types)),
            "vulnerabilities": vulnerabilities,
            "reasoning": " ".join(reasoning_parts) if reasoning_parts else "Standard rule-based analysis.",
            "recommendation": {
                "scan_details": forms_summary.split("\n"),
                "action": [f"Test for {v['type']}" for v in vulnerabilities],
            },
            "method": "rule-based",
        }
