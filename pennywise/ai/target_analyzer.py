"""
AI-powered target analysis using fine-tuned LoRA model.
Analyzes website structure and recommends security scans.
"""

import json
import re
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path

import aiohttp

SYSTEM_PROMPT = """You are an expert web application penetration tester and security analyst.

Your task is to analyze website data (HTML, forms, headers, tech stack) and identify likely attack surfaces.

Output ONLY a valid JSON object. No markdown, no code blocks, no explanation text.

JSON schema:
{
  "overall_risk": "low" | "medium" | "high" | "critical",
  "scan_suggestions": [string],
  "confidence_score": float (0.0 to 1.0),
  "vulnerabilities": [
    {
      "type": string,
      "severity": "low" | "medium" | "high" | "critical",
      "description": string,
      "evidence": string
    }
  ]
}

Rules:
- "scan_suggestions" values MUST be from: ["xss", "sqli", "csrf", "idor", "open_redirect", "auth", "cors", "file_upload", "directory_listing", "insecure_headers", "lfi", "rce", "ssrf"]
- "vulnerabilities[].type" must be from the same list above
- No duplicate entries in "scan_suggestions"
- Missing CSP header → add "xss" and "insecure_headers"
- Missing X-Frame-Options → add "xss" (clickjacking risk)
- Missing HSTS → add "insecure_headers"
- Forms without CSRF tokens → add "csrf"
- Login/auth forms → add "auth", "sqli"
- File upload inputs → add "file_upload", "lfi"
- URL/redirect params → add "open_redirect", "ssrf"
- API endpoints detected → add "idor", "cors"
- Angular/React SPA → still analyze headers and URL patterns, do not skip
- Respond with JSON only. No extra text."""


class AITargetAnalyzer:
    """
    Analyzes target websites using AI to recommend attack types.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.tokenizer = None
        self.model_available = False
        self._loading = False

        if model_path:
            print("🔄 Loading AI model in background...")
            self._loading = True
            load_thread = threading.Thread(
                target=self._load_model_thread, args=(model_path,), daemon=True
            )
            load_thread.start()
        else:
            print("ℹ️  [AI Analyzer] No model path provided — using rule-based fallback")

    def _load_model_thread(self, model_path: str):
        try:
            self._load_model(model_path)
        except Exception as e:
            print(f"⚠️  [AI Analyzer] Could not load AI model: {e}")
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

            use_cuda = torch.cuda.is_available()
            print(f"ℹ️  [AI Analyzer] CUDA available: {use_cuda}")

            if use_cuda:
                torch.backends.cuda.matmul.allow_tf32 = True
                torch.backends.cudnn.allow_tf32 = True
                quantization_config = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_use_double_quant=True,
                    bnb_4bit_quant_type="nf4",
                )
                load_kwargs = {
                    "device_map": {"": 0},
                    "quantization_config": quantization_config,
                    "low_cpu_mem_usage": True,
                }
            else:
                load_kwargs = {
                    "device_map": "cpu",
                    "torch_dtype": torch.float32,
                    "low_cpu_mem_usage": True,
                }

            model_id = "Qwen/Qwen3.5-0.8B"

            print(f"📥 [AI Analyzer] Loading model: {model_id}")
            tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                trust_remote_code=True,
                **load_kwargs,
            )
            model.config.use_cache = False
            self.tokenizer = tokenizer
            self.model = model

            self.model.eval()
            torch.set_grad_enabled(False)
            self.model_available = True
            print("✅ [AI Analyzer] AI model loaded successfully")

        except ImportError as e:
            print(f"⚠️  [AI Analyzer] Missing library: {e}")
            self.model_available = False
        except Exception as e:
            print(f"⚠️  [AI Analyzer] Error loading model: {e}")
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
            print("ℹ️  [AI Analyzer] SPA detected — forms may be dynamically rendered")

        if self.model_available:
            print("🤖 [AI Analyzer] Using AI model for analysis")
            result = await self._ai_analysis(
                url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
            )
        else:
            # Try AI backend at port 8090 first
            result = await self._try_ai_backend(
                url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
            )

        return result

    async def _try_ai_backend(
        self, url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
    ) -> Dict[str, Any]:
        """Try the AI backend at port 8090, fall back to rule-based if unavailable."""
        payload = self._build_analysis_payload(
            url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
        )
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5, connect=2)
            ) as session:
                async with session.post(
                    "http://127.0.0.1:8090/classify",
                    data=payload,
                    headers={"Content-Type": "text/plain"},
                ) as resp:
                    raw = await resp.text()
                    if resp.status != 200:
                        raise RuntimeError(f"Backend returned HTTP {resp.status}: {raw[:200]}")

                    print("✅ [AI Analyzer] AI backend responded successfully")
                    return self._parse_ai_response(raw, url)

        except aiohttp.ClientConnectorError:
            print("⚠️  [AI Analyzer] AI backend not running at port 8090 — using rule-based fallback")
        except Exception as e:
            print(f"⚠️  [AI Analyzer] AI backend error: {e} — using rule-based fallback")

        return self._rule_based_analysis(
            html_snippet, forms_summary, headers_summary, tech_summary, is_spa
        )

    def _build_analysis_payload(
        self, url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
    ) -> str:
        spa_note = "\nNOTE: This is a Single-Page Application (SPA). Forms are dynamically rendered — analyze headers and URL patterns instead." if is_spa else ""
        return f"""Analyze this website for security vulnerabilities.{spa_note}

TARGET_URL: {url}

HTML_SNIPPET:
{html_snippet}

FORMS_SUMMARY:
{forms_summary}

SECURITY_HEADERS:
{headers_summary}

TECH_STACK: {tech_summary}
"""

    async def _ai_analysis(
        self,
        url: str,
        html_snippet: str,
        forms_summary: str,
        headers_summary: str,
        tech_summary: str,
        is_spa: bool = False,
    ) -> Dict[str, Any]:
        payload = self._build_analysis_payload(
            url, html_snippet, forms_summary, headers_summary, tech_summary, is_spa
        )

        try:
            import torch
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": payload},
            ]

            text = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=False,
            )
            inputs = self.tokenizer([text], return_tensors="pt").to(self.model.device)

            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=512,
                    do_sample=False,
                    pad_token_id=self.tokenizer.eos_token_id,
                )

            output_ids = outputs[0][inputs.input_ids.shape[1]:]
            raw = self.tokenizer.decode(output_ids, skip_special_tokens=True).strip()

            print(f"🤖 [AI Analyzer] Raw model output: {raw[:500]}")
            return self._parse_ai_response(raw, url)

        except Exception as e:
            print(f"⚠️  [AI Analyzer] Model inference failed: {e} — falling back to rule-based")
            return self._rule_based_analysis(
                html_snippet, forms_summary, headers_summary, tech_summary, is_spa
            )

    def _parse_ai_response(self, raw: str, url: str = "") -> Dict[str, Any]:
        """Parse JSON from AI model output."""
        # Strip markdown code blocks if present
        cleaned = raw.strip()
        cleaned = re.sub(r"^```json\s*", "", cleaned)
        cleaned = re.sub(r"^```\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

        # Find JSON object boundaries
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start != -1 and end > start:
            cleaned = cleaned[start:end]

        try:
            result = json.loads(cleaned)
        except json.JSONDecodeError:
            print(f"⚠️  [AI Analyzer] JSON parse failed, attempting repair")
            try:
                result = json.loads(self._repair_json(cleaned))
            except Exception:
                print(f"⚠️  [AI Analyzer] JSON repair failed — rule-based fallback")
                return self._rule_based_analysis(cleaned, "", "", "", False)

        vulnerabilities = result.get("vulnerabilities", [])
        scan_suggestions = result.get("scan_suggestions", [])
        overall_risk = result.get("overall_risk", "low")

        # Normalize vulnerabilities to ensure consistent structure
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
            f"✅ [AI Analyzer] Parsed — risk: {overall_risk}, "
            f"vulns: {len(normalized_vulns)}, attacks: {attack_types}"
        )

        return {
            "success": True,
            "overall_risk": overall_risk,
            "attack_types": attack_types,
            "scan_suggestions": scan_suggestions,
            "vulnerabilities": normalized_vulns,
            "reasoning": f"AI analysis — risk: {overall_risk}. Found {len(normalized_vulns)} vulnerability candidate(s).",
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
                summary.append("  ⚠️  File upload input detected")
            if has_password:
                summary.append("  🔒 Password input detected (auth form)")

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
                summary.append(f"- {header}: ⚠️  MISSING")

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
        print("🔁 [AI Analyzer] Running rule-based analysis (AI not available)")
        vulnerabilities = []
        attack_types = []
        reasoning_parts = []

        # Always check headers regardless of SPA
        if "content-security-policy: ⚠️  missing" in headers_summary.lower() or \
           "content-security-policy: missing" in headers_summary.lower():
            if "xss" not in attack_types:
                attack_types.append("xss")
                vulnerabilities.append({"type": "xss", "severity": "medium",
                    "description": "Missing Content-Security-Policy header increases XSS risk",
                    "evidence": "CSP header not present"})
            reasoning_parts.append("Missing Content-Security-Policy header.")

        if "x-frame-options: ⚠️  missing" in headers_summary.lower() or \
           "x-frame-options: missing" in headers_summary.lower():
            reasoning_parts.append("Missing X-Frame-Options (clickjacking risk).")

        if "strict-transport-security: ⚠️  missing" in headers_summary.lower() or \
           "strict-transport-security: missing" in headers_summary.lower():
            if "insecure_headers" not in attack_types:
                attack_types.append("insecure_headers")
                vulnerabilities.append({"type": "insecure_headers", "severity": "low",
                    "description": "Missing HSTS header", "evidence": "HSTS not present"})

        if "access-control-allow-origin" in headers_summary.lower():
            if "cors" not in attack_types:
                attack_types.append("cors")
                vulnerabilities.append({"type": "cors", "severity": "medium",
                    "description": "CORS header detected — may be misconfigured",
                    "evidence": "Access-Control-Allow-Origin present"})

        # Form-based checks
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
                    "description": "Input fields detected — potential XSS surface",
                    "evidence": "Input elements found"})
            if "sqli" not in attack_types and any(
                db in tech_summary.lower() for db in ["mysql", "postgres", "sql", "database", "mongo"]
            ):
                attack_types.append("sqli")
                vulnerabilities.append({"type": "sqli", "severity": "high",
                    "description": "Database tech + input fields = SQLi risk",
                    "evidence": f"Tech: {tech_summary}"})

        # SPA-specific
        if is_spa:
            reasoning_parts.append("SPA detected — static analysis limited, recommend full scan.")
            if "xss" not in attack_types:
                attack_types.append("xss")
            if "idor" not in attack_types:
                attack_types.append("idor")
                vulnerabilities.append({"type": "idor", "severity": "medium",
                    "description": "SPAs often expose API endpoints susceptible to IDOR",
                    "evidence": "Angular/React/Vue detected"})

        if not attack_types:
            attack_types = ["xss", "sqli", "csrf"]
            reasoning_parts.append("No specific signals — running standard scans.")

        # Determine overall risk
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
            "attack_types": list(dict.fromkeys(attack_types)),  # dedupe preserving order
            "scan_suggestions": list(dict.fromkeys(attack_types)),
            "vulnerabilities": vulnerabilities,
            "reasoning": " ".join(reasoning_parts) if reasoning_parts else "Standard rule-based analysis.",
            "recommendation": {
                "scan_details": forms_summary.split("\n"),
                "action": [f"Test for {v['type']}" for v in vulnerabilities],
            },
            "method": "rule-based",
        }
