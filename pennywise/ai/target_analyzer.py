"""
AI-powered target analysis using fine-tuned LoRA model.
Analyzes website structure and recommends security scans.
"""

import json
import re
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path


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
            load_thread = threading.Thread(target=self._load_model_thread, args=(model_path,), daemon=True)
            load_thread.start()
    
    def _load_model_thread(self, model_path: str):
        """Load model in a separate thread."""
        try:
            self._load_model(model_path)
        except Exception as e:
            print(f"⚠️ Could not load AI model: {e}")
            print("   Falling back to rule-based analysis")
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
                torch_dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True,
                local_files_only=False
            )
            
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
        tech_stack: List[str]
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
    
    def _extract_html_snippet(self, html_content: str, max_length: int = 1000) -> str:
        """Extract relevant HTML snippet for analysis."""
        if not html_content:
            return ""
        
        # Focus on forms, inputs, and scripts
        patterns = [
            r'<form[^>]*>.*?</form>',
            r'<input[^>]*>',
            r'<script[^>]*>.*?</script>',
            r'<a[^>]*href[^>]*>',
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
            method = form.get('method', 'GET').upper()
            action = form.get('action', '/')
            inputs = form.get('inputs', [])
            input_names = [inp.get('name', '') for inp in inputs if inp.get('name')]
            
            has_csrf = any('csrf' in inp.get('name', '').lower() or 
                          'token' in inp.get('name', '').lower() 
                          for inp in inputs)
            
            summary.append(f"- {method} {action}")
            if input_names:
                summary.append(f"  Inputs: {', '.join(input_names)}")
            summary.append(f"  CSRF token: {'detected' if has_csrf else 'not detected'}")
        
        return "\n".join(summary)
    
    def _summarize_headers(self, headers: Dict[str, str]) -> str:
        """Create a text summary of security-relevant headers."""
        security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-XSS-Protection',
            'X-Content-Type-Options',
            'Strict-Transport-Security'
        ]
        
        summary = []
        for header in security_headers:
            if header.lower() in [h.lower() for h in headers.keys()]:
                summary.append(f"- {header}: present")
            else:
                summary.append(f"- {header}: missing")
        
        return "\n".join(summary)
    
    async def _ai_analysis(
        self, html_snippet: str, forms_summary: str, 
        headers_summary: str, tech_summary: str
    ) -> Dict[str, Any]:
        """Use AI model for analysis."""
        import torch
        
        prompt = f"""<|system|>
You are a defensive web security analysis model.

Rules:
- Only classify vulnerabilities
- Do NOT generate exploits or payloads
- Output strictly valid JSON
<|user|>
Analyze the following website structure and recommend relevant security scans.

HTML_SNIPPET:
{html_snippet}

FORMS_SUMMARY:
{forms_summary}

HEADERS_SUMMARY:
{headers_summary}

TECH_STACK:
{tech_summary}
<|assistant|>
"""
        
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
            
            with torch.no_grad():
                out = self.model.generate(
                    **inputs,
                    max_new_tokens=400,
                    temperature=0.1,
                    do_sample=False
                )
            
            response = self.tokenizer.decode(out[0], skip_special_tokens=True)
            
            # Extract the assistant's response
            if "<|assistant|>" in response:
                response = response.split("<|assistant|>")[-1].strip()
            
            # Parse JSON response
            result = self._parse_ai_response(response)
            return result
            
        except Exception as e:
            print(f"⚠️ AI analysis failed: {e}")
            return self._rule_based_analysis(
                html_snippet, forms_summary, headers_summary, tech_summary
            )
    
    def _parse_ai_response(self, response: str) -> Dict[str, Any]:
        """Parse AI model's JSON response with automatic repair."""
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                json_text = json_match.group()
            else:
                json_text = response
            
            # Try to fix common JSON issues
            json_text = self._repair_json(json_text)
            
            # Parse JSON
            result = json.loads(json_text)
            
            # Normalize the structure
            vulnerabilities = []
            if 'scan_result' in result and 'vulnerabilities' in result['scan_result']:
                vulnerabilities = result['scan_result']['vulnerabilities']
            elif 'vulnerabilities' in result:
                vulnerabilities = result['vulnerabilities']
            
            reasoning = ""
            if 'reasoning' in result:
                reasoning = result['reasoning']
            elif 'scan_result' in result and 'reasoning' in result['scan_result']:
                reasoning = result['scan_result']['reasoning']
            
            recommendation = result.get('recommendation', {})
            
            # Map vulnerability names to attack types
            attack_types = self._map_vulnerabilities_to_attacks(vulnerabilities)
            
            return {
                'success': True,
                'attack_types': attack_types,
                'vulnerabilities': vulnerabilities,
                'reasoning': reasoning,
                'recommendation': recommendation,
                'method': 'ai',
                'raw_response': response
            }
            
        except Exception as e:
            print(f"⚠️ Failed to parse AI response: {e}")
            print(f"   Raw response: {response[:200]}...")
            return {
                'success': False,
                'error': str(e),
                'raw_response': response,
                'attack_types': ['xss', 'sqli', 'csrf'],  # Default fallback
                'method': 'ai-fallback',
                'reasoning': 'AI model returned invalid JSON. Using default recommendations.'
            }
    
    def _repair_json(self, json_text: str) -> str:
        """Attempt to repair common JSON formatting issues."""
        # Remove any trailing commas before closing braces/brackets
        json_text = re.sub(r',(\s*[}\]])', r'\1', json_text)
        
        # Fix unmatched brackets - count and balance them
        open_braces = json_text.count('{')
        close_braces = json_text.count('}')
        open_brackets = json_text.count('[')
        close_brackets = json_text.count(']')
        
        # Add missing closing braces
        if open_braces > close_braces:
            json_text += '}' * (open_braces - close_braces)
        
        # Add missing closing brackets
        if open_brackets > close_brackets:
            json_text += ']' * (open_brackets - close_brackets)
        
        # Fix missing quotes around unquoted strings after colons
        json_text = re.sub(r':\s*([a-zA-Z_][a-zA-Z0-9_\-\s]*)\s*([,}\]])', r': "\1"\2', json_text)
        
        return json_text
    
    def _map_vulnerabilities_to_attacks(self, vulnerabilities: List[str]) -> List[str]:
        """Map vulnerability names to PennyWise attack types."""
        mapping = {
            'xss': ['xss', 'cross-site scripting', 'reflected xss', 'stored xss', 'dom xss'],
            'sqli': ['sqli', 'sql injection', 'sql', 'database injection'],
            'csrf': ['csrf', 'xsrf', 'cross-site request forgery'],
            'lfi': ['lfi', 'local file inclusion', 'file inclusion', 'path traversal'],
            'rce': ['rce', 'remote code execution', 'command injection', 'code injection'],
            'xxe': ['xxe', 'xml external entity'],
            'ssrf': ['ssrf', 'server-side request forgery'],
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
            attack_types = ['xss', 'sqli', 'csrf']
        
        return attack_types
    
    def _rule_based_analysis(
        self, html_snippet: str, forms_summary: str,
        headers_summary: str, tech_summary: str
    ) -> Dict[str, Any]:
        """Fallback rule-based analysis when AI is not available."""
        vulnerabilities = []
        attack_types = []
        reasoning_parts = []
        
        # Check for forms without CSRF protection
        if 'csrf token: not detected' in forms_summary.lower():
            vulnerabilities.append('CSRF')
            attack_types.append('csrf')
            reasoning_parts.append('Forms detected without CSRF tokens - vulnerable to Cross-Site Request Forgery.')
        
        # Check for input fields (potential XSS/SQLi)
        if 'input' in html_snippet.lower() or 'form' in forms_summary.lower():
            vulnerabilities.append('XSS')
            attack_types.append('xss')
            reasoning_parts.append('Input fields detected - potential Cross-Site Scripting vulnerability.')
            
            if any(db in tech_summary.lower() for db in ['mysql', 'postgres', 'sql', 'database']):
                vulnerabilities.append('SQL Injection')
                attack_types.append('sqli')
                reasoning_parts.append('Database technology detected with input fields - potential SQL Injection.')
        
        # Check for missing security headers
        if 'content-security-policy: missing' in headers_summary.lower():
            if 'XSS' not in vulnerabilities:
                vulnerabilities.append('XSS')
                attack_types.append('xss')
            reasoning_parts.append('Missing Content-Security-Policy header increases XSS risk.')
        
        # Check for file-related vulnerabilities
        if any(keyword in html_snippet.lower() for keyword in ['file', 'upload', 'download', 'include']):
            vulnerabilities.append('LFI')
            attack_types.append('lfi')
            reasoning_parts.append('File operations detected - potential Local File Inclusion vulnerability.')
        
        # Default scans if nothing detected
        if not attack_types:
            attack_types = ['xss', 'sqli', 'csrf']
            reasoning_parts.append('Performing standard security scans (XSS, SQLi, CSRF).')
        
        return {
            'success': True,
            'attack_types': list(set(attack_types)),  # Remove duplicates
            'vulnerabilities': vulnerabilities,
            'reasoning': ' '.join(reasoning_parts),
            'recommendation': {
                'scan_details': forms_summary.split('\n'),
                'action': [f'Test for {v}' for v in vulnerabilities]
            },
            'method': 'rule-based'
        }
