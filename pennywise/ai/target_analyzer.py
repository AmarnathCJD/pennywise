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
                dtype=torch.float16,
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
            # First, try to repair the JSON
            repaired_response = self._repair_json(response.strip())
            
            # Try to parse the repaired JSON directly
            try:
                result = json.loads(repaired_response)
            except json.JSONDecodeError:
                # If that fails, try line-by-line parsing
                json_objects = []
                for line in repaired_response.split('\n'):
                    line = line.strip()
                    if line.startswith('{') and line.endswith('}'):
                        try:
                            obj = json.loads(line)
                            json_objects.append(obj)
                        except:
                            continue
                
                # If we found multiple objects, merge them
                if len(json_objects) > 1:
                    result = {}
                    for obj in json_objects:
                        result.update(obj)
                elif len(json_objects) == 1:
                    result = json_objects[0]
                else:
                    # Last resort: extract first valid JSON
                    json_match = re.search(r'\{.*\}', repaired_response, re.DOTALL)
                    if json_match:
                        result = json.loads(json_match.group())
                    else:
                        raise ValueError("No valid JSON found in response")
            
            # Normalize the structure
            vulnerabilities = []
            if 'scan_result' in result and 'vulnerabilities' in result['scan_result']:
                vulnerabilities = result['scan_result']['vulnerabilities']
            elif 'vulnerabilities' in result:
                vulnerabilities = result['vulnerabilities']
            elif 'variant' in result and 'name' in result['variant']:
                # Handle format like: {"variant": {"name": "XSS"}}
                vulnerabilities = [result['variant']['name']]
            elif 'status' in result and result['status'] == 'VULN':
                # Handle status-based format
                if 'variant' in result:
                    vulnerabilities = [result['variant'].get('name', 'Unknown')]
            
            reasoning = ""
            if 'reasoning' in result:
                reasoning = result['reasoning']
            elif 'scan_result' in result and 'reasoning' in result['scan_result']:
                reasoning = result['scan_result']['reasoning']
            elif 'variant' in result and 'details' in result['variant']:
                # Format reasoning from variant details
                vuln_name = result['variant'].get('name', 'Unknown')
                details = result['variant'].get('details', [])
                if details:
                    reasoning = f"{vuln_name} detected: {', '.join(details)}"
                else:
                    reasoning = f"{vuln_name} vulnerability detected"
                    
                # Add impact info if present
                if 'impact' in result['variant']:
                    impact = result['variant']['impact']
                    impact_str = ', '.join([k for k, v in impact.items() if v])
                    if impact_str:
                        reasoning += f" (Impact: {impact_str})"
            
            recommendation = result.get('recommendation', {})
            
            # Normalize recommendation format
            if 'scan' in recommendation and isinstance(recommendation['scan'], list):
                # Convert scan URLs to action format
                recommendation['action'] = [f"Scan endpoint: {url}" for url in recommendation['scan'][:3]]
            
            # Map vulnerability names to attack types
            attack_types = self._map_vulnerabilities_to_attacks(vulnerabilities)
            
            # Build final response
            response_data = {
                'success': True,
                'attack_types': attack_types,
                'vulnerabilities': vulnerabilities,
                'reasoning': reasoning,
                'recommendation': recommendation,
                'method': 'ai',
                'raw_response': response
            }
            
            # Add status if present
            if 'status' in result:
                response_data['status'] = result['status']
            
            return response_data
            
        except Exception as e:
            print(f"⚠️ Failed to parse AI response: {e}")
            print(f"   Raw response: {response[:200]}...")
            
            # Return the raw response for UI display
            return {
                'success': False,
                'error': f"JSON Parse Error: {str(e)}",
                'raw_response': response,
                'attack_types': ['xss', 'sqli', 'csrf'],  # Default fallback
                'method': 'parse-error',
                'reasoning': f'Unable to parse AI model output. Error: {str(e)}',
                'vulnerabilities': [],
                'recommendation': {}
            }
    
    def _repair_json(self, json_text: str) -> str:
        """Attempt to repair common JSON formatting issues."""
        # Remove any trailing commas before closing braces/brackets
        json_text = re.sub(r',(\s*[}\]])', r'\1', json_text)
        
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
            
            if char == '\\':
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
            if char == '{':
                stack.append('{')
                result.append(char)
            elif char == '[':
                stack.append('[')
                result.append(char)
            elif char == '}':
                if stack and stack[-1] == '{':
                    stack.pop()
                    result.append(char)
                elif stack and stack[-1] == '[':
                    # Wrong closer - fix it
                    stack.pop()
                    result.append(']')
                else:
                    # Extra closing brace - skip it
                    pass
            elif char == ']':
                if stack and stack[-1] == '[':
                    stack.pop()
                    result.append(char)
                elif stack and stack[-1] == '{':
                    # Wrong closer - fix it
                    stack.pop()
                    result.append('}')
                else:
                    # Extra closing bracket - skip it
                    pass
            else:
                result.append(char)
            
            i += 1
        
        # Close any remaining open brackets/braces
        while stack:
            opener = stack.pop()
            if opener == '{':
                result.append('}')
            elif opener == '[':
                result.append(']')
        
        return ''.join(result)
    
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
