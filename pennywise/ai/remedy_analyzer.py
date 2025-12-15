"""
AI-powered remediation report generator using fine-tuned LoRA model.
Generates remediation-focused security reports with actionable guidance.
"""

import json
import re
import threading
from typing import Dict, List, Optional, Any
from pathlib import Path


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
        self,
        scan_id: str,
        target: str,
        findings: List[Dict[str, Any]]
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
            findings_input.append({
                "type": finding.get('type', 'unknown'),
                "endpoint": finding.get('endpoint', ''),
                "parameter": finding.get('parameter', ''),
                "payload": finding.get('payload', ''),
                "impact": finding.get('impact', 'Security vulnerability detected')
            })
        
        # Use AI model if available, otherwise use rule-based
        if self.model_available:
            result = await self._ai_remediation(scan_id, target, findings_input)
        else:
            result = self._rule_based_remediation(scan_id, target, findings_input)
        
        return result
    
    async def _ai_remediation(
        self, scan_id: str, target: str, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Use AI model for remediation generation."""
        import torch
        
        # Prepare input data
        input_data = {
            "scan_id": scan_id,
            "target": target,
            "findings": findings
        }
        
        prompt = f"""<|system|>
You are PennyWise, a senior application security engineer generating remediation-focused security reports.
<|user|>
Generate a hybrid security assessment report with remediation guidance based on the scan data.

{json.dumps(input_data)}
<|assistant|>
"""
        
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
            
            with torch.no_grad():
                out = self.model.generate(
                    **inputs,
                    max_new_tokens=600,
                    temperature=0.1,
                    do_sample=False
                )
            
            response = self.tokenizer.decode(out[0], skip_special_tokens=True)
            
            # Extract the assistant's response
            if "<|assistant|>" in response:
                response = response.split("<|assistant|>")[-1].strip()
            
            # Parse JSON response
            result = self._parse_ai_response(response, findings)
            print("✅ AI remediation generated successfully: using AI model: ", result)
            return result
            
        except Exception as e:
            print(f"⚠️ AI remediation failed: {e}, returning error info")
            return {
                'success': True,
                'method': 'ai-model-failed',
                'priority': 'Unknown',
                'steps': [f"AI model error: {str(e)}"],
                'code_example': '',
                'recommendation': f"Failed to generate AI remediation: {str(e)}",
                'error': str(e)
            }
    
    def _parse_ai_response(self, response: str, findings: List[Dict]) -> Dict[str, Any]:
        """Parse AI response using regex - ignores malformed JSON and extracts what we can."""
        try:
            print(f"🔍 Raw AI Response: {response}")
            
            # Extract using regex patterns - ignore JSON structure
            priority = 'Medium'
            steps = []
            code_example = ''
            recommendation = ''
            
            # Try to find priority
            priority_match = re.search(r'"priority"\s*:\s*"([^"]+)"', response, re.IGNORECASE)
            if priority_match:
                priority = priority_match.group(1)
            
            # Try to find recommendation/answer
            rec_match = re.search(r'"(?:recommendation|answer)"\s*:\s*"([^"]+)"', response, re.IGNORECASE)
            if rec_match:
                recommendation = rec_match.group(1)
                # If answer field contains the steps, split it
                if not steps and recommendation:
                    # Split by common separators
                    if '.' in recommendation:
                        steps = [s.strip() for s in recommendation.split('.') if s.strip()]
                    elif ',' in recommendation:
                        steps = [s.strip() for s in recommendation.split(',') if s.strip()]
                    else:
                        steps = [recommendation]
            
            # Try to find steps array - extract all items
            steps_section = re.search(r'"(?:steps|remediation_steps)"\s*:\s*\[(.*?)\]', response, re.DOTALL | re.IGNORECASE)
            if steps_section:
                steps_content = steps_section.group(1)
                # Extract each quoted string
                step_matches = re.findall(r'"([^"]+)"', steps_content)
                if step_matches:
                    steps = step_matches
            
            # If no steps found, try to find them as separate lines
            if not steps:
                # Look for numbered or bulleted lists
                step_patterns = [
                    r'^\d+\.\s+(.+)$',  # 1. Step
                    r'^[-*]\s+(.+)$',   # - Step or * Step
                ]
                for pattern in step_patterns:
                    step_matches = re.findall(pattern, response, re.MULTILINE)
                    if step_matches:
                        steps = step_matches
                        break
            
            # Try to find code example
            code_match = re.search(r'"code_example"\s*:\s*"([^"]*)"', response, re.DOTALL)
            if code_match:
                code_example = code_match.group(1).replace('\\n', '\n').replace('\\"', '"')
            
            # If we didn't find anything useful, return raw AI output
            if not steps and not recommendation:
                print("⚠️ Could not extract structured data, returning raw AI output")
                return {
                    'success': True,
                    'method': 'ai-model-raw',
                    'priority': priority,
                    'steps': [response],  # Put entire response as single step
                    'code_example': '',
                    'recommendation': response,
                    'raw_output': response
                }
            
            # Build the response in the format frontend expects
            result = {
                'success': True,
                'method': 'ai-model',
                'priority': priority,
                'steps': steps if steps else ['Apply recommended security fixes', 'Review code for vulnerabilities'],
                'code_example': code_example,
                'recommendation': recommendation,
                'raw_output': response
            }
            
            print(f"✅ Extracted remedy data: priority={priority}, steps={len(steps)}")
            return result
            
        except Exception as e:
            print(f"⚠️ Failed to parse AI response: {e}, returning raw output")
            return {
                'success': True,
                'method': 'ai-model-error',
                'priority': 'Unknown',
                'steps': [response if 'response' in locals() else str(e)],
                'code_example': '',
                'recommendation': response if 'response' in locals() else f"Error: {str(e)}",
                'raw_output': response if 'response' in locals() else str(e)
            }
    
    def _rule_based_remediation(
        self, scan_id: str, target: str, findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Fallback rule-based remediation generation."""
        
        remediation_map = {
            'sqli': {
                'recommendation': 'Use parameterized queries, ORM frameworks, and strict input validation.',
                'priority': 'Critical',
                'steps': [
                    'Implement prepared statements for all database queries',
                    'Use ORM frameworks (e.g., SQLAlchemy, Hibernate)',
                    'Validate and sanitize all user inputs',
                    'Apply principle of least privilege for database accounts'
                ]
            },
            'xss': {
                'recommendation': 'Implement output encoding, Content-Security-Policy headers, and input validation.',
                'priority': 'High',
                'steps': [
                    'Encode all user-controlled data in HTML context',
                    'Implement Content-Security-Policy headers',
                    'Use framework-provided XSS protection',
                    'Validate and sanitize user inputs'
                ]
            },
            'csrf': {
                'recommendation': 'Implement anti-CSRF tokens, SameSite cookies, and verify Origin headers.',
                'priority': 'High',
                'steps': [
                    'Add CSRF tokens to all state-changing forms',
                    'Set SameSite attribute on session cookies',
                    'Verify Origin and Referer headers',
                    'Use framework-provided CSRF protection'
                ]
            },
            'rce': {
                'recommendation': 'Avoid dynamic command execution and apply sandboxing and least privilege.',
                'priority': 'Critical',
                'steps': [
                    'Never execute user-controlled commands',
                    'Use safe APIs instead of shell commands',
                    'Implement strict input validation',
                    'Apply sandboxing and containerization'
                ]
            },
            'lfi': {
                'recommendation': 'Validate file paths, use whitelists, and implement proper access controls.',
                'priority': 'High',
                'steps': [
                    'Implement whitelist of allowed files',
                    'Validate and sanitize file paths',
                    'Use absolute paths internally',
                    'Apply proper file system permissions'
                ]
            },
            'ssrf': {
                'recommendation': 'Validate URLs, use allowlists, and implement network segmentation.',
                'priority': 'High',
                'steps': [
                    'Implement URL allowlist validation',
                    'Block requests to internal IPs',
                    'Use network segmentation',
                    'Validate and sanitize user-provided URLs'
                ]
            }
        }
        
        # Get remedy info for the first finding (since frontend shows one at a time)
        if findings:
            vuln_type = findings[0].get('type', 'unknown')
            remedy_info = remediation_map.get(vuln_type, {
                'recommendation': 'Follow secure coding practices and perform security testing.',
                'priority': 'Medium',
                'steps': ['Review code for security issues', 'Apply defense in depth']
            })
        else:
            remedy_info = {
                'recommendation': 'Follow secure coding practices.',
                'priority': 'Medium',
                'steps': ['Review code for security issues']
            }
        
        # Return format that frontend expects
        return {
            'success': True,
            'method': 'rule-based',
            'priority': remedy_info['priority'],
            'steps': remedy_info.get('steps', []),
            'code_example': remedy_info.get('code_example', ''),
            'recommendation': remedy_info['recommendation']
        }
