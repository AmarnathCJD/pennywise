"""
Generate 500 diverse security vulnerability training examples
Covers: SQLi (SQL Injection), XSS (Cross-Site Scripting), CSRF (Cross-Site Request Forgery)
"""

import json
import random
from typing import List, Dict, Any

def generate_sqli_examples(count: int = 150) -> List[Dict[str, Any]]:
    """Generate SQL Injection vulnerability examples"""
    examples = []
    
    sqli_contexts = [
        ("user search", "/search?user=", "username", "MySQL"),
        ("product lookup", "/product", "id", "PostgreSQL"),
        ("order retrieval", "/api/orders", "order_id", "MySQL"),
        ("employee filter", "/employees", "dept", "Oracle"),
        ("invoice query", "/invoice", "inv_num", "MySQL"),
        ("customer lookup", "/customer", "cid", "SQL Server"),
        ("article search", "/articles", "author", "MySQL"),
        ("report generation", "/report", "month", "PostgreSQL"),
        ("inventory check", "/inventory", "sku", "MySQL"),
        ("transaction history", "/transactions", "ref", "Oracle"),
        ("account lookup", "/account", "acct_num", "MySQL"),
        ("booking search", "/bookings", "hotel_id", "PostgreSQL"),
        ("document retrieval", "/docs", "doc_id", "MySQL"),
        ("profile view", "/profile", "user_id", "MySQL"),
        ("rating filter", "/ratings", "product_id", "MySQL"),
    ]
    
    methods = ["GET", "POST"]
    
    for i in range(count):
        context, endpoint, param, db = random.choice(sqli_contexts)
        method = random.choice(methods)
        
        form_summary = f"- {method} {endpoint}\n- Input: {param}"
        
        html_snippet = f"""<form method="{method}" action="{endpoint}">
  <input type="text" name="{param}">
  <input type="submit" value="Search">
</form>"""
        
        confidence = round(random.uniform(0.78, 0.95), 2)
        
        reasoning = random.choice([
            f"{param} parameter likely used in SQL query without parameterization",
            f"{param} sent to backend using {db}",
            f"User input concatenated directly into {db} query",
            f"{param} processed without prepared statements",
            f"Form input directly used in database query",
            f"Vulnerable {method} endpoint with {db}",
            f"User-controlled {param} in SQL WHERE clause",
        ])
        
        example = {
            "system": "You are a defensive web security analysis model. Your task is to analyze partial HTML code, form structure, HTTP headers, and backend technology stack. You must predict which vulnerability scans are most relevant. Rules: - Only identify vulnerability categories - Do NOT generate exploits or payloads - Output strictly valid JSON - Be conservative if unsure",
            "instruction": "Analyze the following website structure and recommend relevant security scans.",
            "input": f"HTML_SNIPPET:\n{html_snippet}\n\nFORMS_SUMMARY:\n{form_summary}\n\nHEADERS_SUMMARY:\n- Content-Security-Policy: missing\n\nTECH_STACK:\n{db}",
            "output": json.dumps({
                "scan_recommended": ["sqli"],
                "confidence": {"sqli": confidence},
                "reasoning": {"sqli": reasoning}
            })
        }
        examples.append(example)
    
    return examples


def generate_xss_examples(count: int = 150) -> List[Dict[str, Any]]:
    """Generate XSS (Cross-Site Scripting) vulnerability examples"""
    examples = []
    
    xss_contexts = [
        ("search results", "query", "GET /search"),
        ("comment section", "comment", "POST /comment"),
        ("user profile", "bio", "GET /profile"),
        ("product review", "review_text", "POST /review"),
        ("feedback form", "feedback", "POST /feedback"),
        ("message board", "message", "POST /message"),
        ("forum post", "content", "POST /forum/post"),
        ("chat input", "text", "POST /chat"),
        ("blog comment", "comment", "POST /blog/comment"),
        ("status update", "status", "POST /status"),
        ("error messages", "msg", "GET /error"),
        ("notification", "notification", "GET /notify"),
        ("tag input", "tag", "POST /tag"),
        ("username search", "q", "GET /users"),
        ("display name", "name", "POST /profile/update"),
    ]
    
    injection_types = [
        "URL parameter reflected without encoding",
        "User input directly inserted into HTML",
        "Form data rendered without sanitization",
        "Missing Content-Security-Policy header",
        "JavaScript directly evaluates user input",
        "DOM manipulation with untrusted data",
        "No output encoding applied",
    ]
    
    for i in range(count):
        context, param, endpoint = random.choice(xss_contexts)
        
        html_snippet = f"""<form method="POST" action="{endpoint.split()[1]}">
  <input type="text" name="{param}" placeholder="Enter {context}">
  <input type="submit" value="Submit">
</form>"""
        
        confidence = round(random.uniform(0.75, 0.95), 2)
        
        reasoning = random.choice(injection_types)
        
        example = {
            "system": "You are a defensive web security analysis model. Your task is to analyze partial HTML code, form structure, HTTP headers, and backend technology stack. You must predict which vulnerability scans are most relevant. Rules: - Only identify vulnerability categories - Do NOT generate exploits or payloads - Output strictly valid JSON - Be conservative if unsure",
            "instruction": "Analyze the following website structure and recommend relevant security scans.",
            "input": f"HTML_SNIPPET:\n{html_snippet}\n\nFORMS_SUMMARY:\n- {endpoint}\n- Input: {param}\n\nHEADERS_SUMMARY:\n- Content-Security-Policy: missing\n- X-XSS-Protection: missing\n\nTECH_STACK:\nPHP, Apache",
            "output": json.dumps({
                "scan_recommended": ["xss"],
                "confidence": {"xss": confidence},
                "reasoning": {"xss": reasoning}
            })
        }
        examples.append(example)
    
    return examples


def generate_csrf_examples(count: int = 100) -> List[Dict[str, Any]]:
    """Generate CSRF (Cross-Site Request Forgery) vulnerability examples"""
    examples = []
    
    csrf_contexts = [
        ("delete account", "/account/delete", "POST"),
        ("password change", "/account/password", "POST"),
        ("email update", "/account/email", "POST"),
        ("transfer funds", "/bank/transfer", "POST"),
        ("order placement", "/order/create", "POST"),
        ("settings update", "/settings/update", "POST"),
        ("permission grant", "/admin/grant", "POST"),
        ("user delete", "/admin/delete-user", "POST"),
        ("role assignment", "/admin/assign-role", "POST"),
        ("subscription cancel", "/subscription/cancel", "POST"),
        ("profile update", "/profile/update", "POST"),
        ("payment method", "/payment/add", "POST"),
        ("notification settings", "/notify/settings", "POST"),
        ("data export", "/data/export", "POST"),
        ("api key generation", "/api/generate-key", "POST"),
    ]
    
    csrf_reasons = [
        "Form lacks CSRF token - vulnerable to cross-site request forgery",
        "POST request without CSRF protection",
        "No token validation for state-changing operation",
        "Form submitted without anti-CSRF token",
        "Missing SameSite cookie attribute",
        "Sensitive action unprotected against CSRF",
        "State-changing form without token verification",
    ]
    
    for i in range(count):
        action, endpoint, method = random.choice(csrf_contexts)
        
        html_snippet = f"""<form method="{method}" action="{endpoint}">
  <input type="text" name="data">
  <input type="submit" value="Confirm {action}">
</form>"""
        
        confidence = round(random.uniform(0.80, 0.95), 2)
        
        example = {
            "system": "You are a defensive web security analysis model. Your task is to analyze partial HTML code, form structure, HTTP headers, and backend technology stack. You must predict which vulnerability scans are most relevant. Rules: - Only identify vulnerability categories - Do NOT generate exploits or payloads - Output strictly valid JSON - Be conservative if unsure",
            "instruction": "Analyze the following website structure and recommend relevant security scans.",
            "input": f"HTML_SNIPPET:\n{html_snippet}\n\nFORMS_SUMMARY:\n- {method} {endpoint}\n- CSRF token: not detected\n\nHEADERS_SUMMARY:\n- Content-Security-Policy: missing\n- SameSite: missing\n\nTECH_STACK:\nPHP, Apache, MySQL",
            "output": json.dumps({
                "scan_recommended": ["csrf"],
                "confidence": {"csrf": confidence},
                "reasoning": {"csrf": random.choice(csrf_reasons)}
            })
        }
        examples.append(example)
    
    return examples


def generate_hybrid_examples(count: int = 100) -> List[Dict[str, Any]]:
    """Generate examples with multiple vulnerabilities"""
    examples = []
    
    hybrid_contexts = [
        (["sqli", "xss"], 0.85, "User input in form field likely vulnerable to both SQL injection and XSS"),
        (["sqli", "csrf"], 0.82, "Database query without parameterization or CSRF protection"),
        (["xss", "csrf"], 0.88, "Form with reflected user input and missing CSRF token"),
        (["sqli", "xss", "csrf"], 0.80, "Multiple vulnerabilities in same form"),
    ]
    
    for i in range(count):
        vulns, conf, reason = random.choice(hybrid_contexts)
        
        if len(vulns) == 2:
            vuln_str = f"{vulns[0]} and {vulns[1]}"
        else:
            vuln_str = ", ".join(vulns)
        
        example = {
            "system": "You are a defensive web security analysis model. Your task is to analyze partial HTML code, form structure, HTTP headers, and backend technology stack. You must predict which vulnerability scans are most relevant. Rules: - Only identify vulnerability categories - Do NOT generate exploits or payloads - Output strictly valid JSON - Be conservative if unsure",
            "instruction": "Analyze the following website structure and recommend relevant security scans.",
            "input": f"HTML_SNIPPET:\n<form method=\"POST\" action=\"/search\">\n  <input type=\"text\" name=\"query\">\n  <input type=\"submit\" value=\"Search\">\n</form>\n\nFORMS_SUMMARY:\n- POST /search\n- Input: query\n- CSRF token: not detected\n\nHEADERS_SUMMARY:\n- Content-Security-Policy: missing\n\nTECH_STACK:\nPHP, MySQL, Apache",
            "output": json.dumps({
                "scan_recommended": vulns,
                "confidence": {v: round(conf - (0.02 * idx), 2) for idx, v in enumerate(vulns)},
                "reasoning": {v: f"{reason} - {v.upper()} risk" for v in vulns}
            })
        }
        examples.append(example)
    
    return examples


def main():
    print("\n" + "="*70)
    print("🔒 GENERATING 500 SECURITY VULNERABILITY TRAINING EXAMPLES")
    print("="*70)
    
    # Generate examples
    print("\n📝 Generating SQL Injection examples... (150)")
    sqli_examples = generate_sqli_examples(150)
    
    print("📝 Generating XSS examples... (150)")
    xss_examples = generate_xss_examples(150)
    
    print("📝 Generating CSRF examples... (100)")
    csrf_examples = generate_csrf_examples(100)
    
    print("📝 Generating Hybrid vulnerability examples... (100)")
    hybrid_examples = generate_hybrid_examples(100)
    
    # Combine all examples
    all_examples = sqli_examples + xss_examples + csrf_examples + hybrid_examples
    
    print(f"\n✅ Total examples generated: {len(all_examples)}")
    
    # Write to file
    dataset_path = r'c:\Users\Amarnath\Programs\My Projects\pennywise\lora\analyser\step1_dataset.jsonl'
    
    print(f"\n📁 Writing to: {dataset_path}")
    with open(dataset_path, 'a', encoding='utf-8') as f:
        for example in all_examples:
            f.write(json.dumps(example) + '\n')
    
    # Statistics
    print("\n" + "="*70)
    print("📊 DATASET STATISTICS")
    print("="*70)
    print(f"✅ SQL Injection (SQLi):  150 examples")
    print(f"✅ Cross-Site Scripting:  150 examples")
    print(f"✅ CSRF:                 100 examples")
    print(f"✅ Hybrid (Multi-vuln):  100 examples")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"📈 Total Added:          500 examples")
    print(f"📈 Grand Total in File:  {len(all_examples)} examples")
    print("="*70 + "\n")
    
    print("✨ Training dataset enhanced with diverse vulnerability scenarios!")
    print("   Ready for LoRA fine-tuning of the security analysis model\n")


if __name__ == "__main__":
    main()
