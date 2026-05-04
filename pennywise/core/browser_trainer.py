"""
Browser-based training mode.
Opens a Chrome browser via Selenium Wire, intercepts all network requests
in real-time, and streams them to the dashboard as attack surfaces.
"""

import asyncio
import json
import threading
import time
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urlparse, parse_qs


class BrowserTrainer:
    """
    Opens Chrome with request interception. Streams discovered endpoints,
    parameters, forms, and request bodies back to the dashboard in real-time.
    """

    def __init__(self, on_request: Callable, on_log: Callable, on_surface: Callable):
        self.on_request = on_request   # called for every intercepted request
        self.on_log = on_log           # called for log messages
        self.on_surface = on_surface   # called when attack surface is found
        self.driver = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.surfaces = []             # discovered attack surfaces
        self.request_count = 0
        self.session_id = None

    def start(self, url: str = "about:blank") -> bool:
        """Launch Chrome with request interception."""
        try:
            from seleniumwire import webdriver as sw_webdriver
            from selenium.webdriver.chrome.options import Options
            from webdriver_manager.chrome import ChromeDriverManager
            from selenium.webdriver.chrome.service import Service

            options = Options()
            options.add_argument("--start-maximized")
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option("useAutomationExtension", False)

            sw_options = {
                "suppress_connection_errors": True,
                "verify_ssl": False,
            }

            service = Service(ChromeDriverManager().install())
            self.driver = sw_webdriver.Chrome(
                service=service,
                options=options,
                seleniumwire_options=sw_options,
            )
            # Remove automation fingerprint
            self.driver.execute_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
            )

            if url and url != "about:blank":
                self.driver.get(url)

            self._running = True
            self._thread = threading.Thread(target=self._intercept_loop, daemon=True)
            self._thread.start()

            self.on_log("Chrome browser launched — browse the target site", "success")
            self.on_log("All network requests are being intercepted", "info")
            return True

        except Exception as e:
            self.on_log(f"Failed to launch browser: {e}", "error")
            return False

    def stop(self):
        """Stop interception and close the browser."""
        self._running = False
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None
        self.on_log(
            f"Browser session ended — {self.request_count} requests captured, "
            f"{len(self.surfaces)} attack surfaces found",
            "success",
        )

    def _intercept_loop(self):
        """Background thread — polls for new requests from selenium-wire."""
        seen = set()
        while self._running:
            try:
                if not self.driver:
                    break
                requests = self.driver.requests
                for req in requests:
                    rid = id(req)
                    if rid in seen:
                        continue
                    seen.add(rid)
                    self._process_request(req)
            except Exception:
                pass
            time.sleep(0.3)

    def _process_request(self, req):
        """Analyse an intercepted request for attack surfaces."""
        try:
            url = req.url
            method = req.method
            headers = dict(req.headers) if req.headers else {}
            body = req.body.decode("utf-8", errors="ignore") if req.body else ""

            self.request_count += 1

            parsed = urlparse(url)
            host = parsed.netloc
            path = parsed.path

            # Skip noise
            if any(
                ext in path.lower()
                for ext in [".png", ".jpg", ".gif", ".ico", ".woff", ".css", ".svg", ".mp4"]
            ):
                return
            if any(
                domain in host
                for domain in ["google-analytics", "googletagmanager", "facebook", "doubleclick", "cdn"]
            ):
                return

            surfaces_found = []

            # URL query parameters
            query_params = parse_qs(parsed.query)
            if query_params:
                for param, values in query_params.items():
                    surface = {
                        "type": "url_param",
                        "url": url,
                        "parameter": param,
                        "value": values[0] if values else "",
                        "method": method,
                        "attack_hints": self._guess_attack_types(param, values[0] if values else ""),
                    }
                    surfaces_found.append(surface)

            # POST body parameters
            if method == "POST" and body:
                # Try form-encoded
                if "application/x-www-form-urlencoded" in headers.get("Content-Type", ""):
                    post_params = parse_qs(body)
                    for param, values in post_params.items():
                        surface = {
                            "type": "post_param",
                            "url": url,
                            "parameter": param,
                            "value": values[0] if values else "",
                            "method": "POST",
                            "attack_hints": self._guess_attack_types(param, values[0] if values else ""),
                        }
                        surfaces_found.append(surface)
                # Try JSON body
                elif "application/json" in headers.get("Content-Type", ""):
                    try:
                        json_body = json.loads(body)
                        if isinstance(json_body, dict):
                            for param, value in json_body.items():
                                surface = {
                                    "type": "json_param",
                                    "url": url,
                                    "parameter": param,
                                    "value": str(value)[:100],
                                    "method": "POST",
                                    "attack_hints": self._guess_attack_types(param, str(value)),
                                }
                                surfaces_found.append(surface)
                    except Exception:
                        pass

            # Auth headers
            if "Authorization" in headers:
                surfaces_found.append({
                    "type": "auth_header",
                    "url": url,
                    "parameter": "Authorization",
                    "value": headers["Authorization"][:40] + "...",
                    "method": method,
                    "attack_hints": ["auth"],
                })

            # Fire callbacks
            request_info = {
                "url": url,
                "method": method,
                "host": host,
                "path": path,
                "has_params": bool(query_params or (method == "POST" and body)),
                "surfaces": len(surfaces_found),
                "timestamp": datetime.now().isoformat(),
            }
            self.on_request(request_info)

            for surface in surfaces_found:
                self.surfaces.append(surface)
                self.on_surface(surface)

            # Log interesting ones
            if surfaces_found:
                hints = list(set(h for s in surfaces_found for h in s.get("attack_hints", [])))
                self.on_log(
                    f"[{method}] {path} — {len(surfaces_found)} param(s) found, "
                    f"possible: {', '.join(hints).upper() if hints else 'unknown'}",
                    "warning" if hints else "info",
                )
            elif method in ("GET", "POST") and path != "/":
                self.on_log(f"[{method}] {url[:80]}", "url")

        except Exception as e:
            pass  # silently skip malformed requests

    def _guess_attack_types(self, param: str, value: str) -> list:
        """Heuristically guess which attack types a parameter might be vulnerable to."""
        hints = []
        param_l = param.lower()
        value_l = value.lower()

        sqli_params = ["id", "uid", "user_id", "pid", "cat", "category", "search", "q", "query",
                       "filter", "sort", "order", "page", "limit", "offset", "item", "product"]
        xss_params = ["name", "search", "q", "query", "msg", "message", "comment", "text",
                      "title", "content", "description", "input", "data", "value", "email"]
        redirect_params = ["redirect", "return", "url", "next", "goto", "dest", "destination",
                           "continue", "callback", "redir", "forward", "location"]
        file_params = ["file", "path", "page", "include", "load", "template", "view",
                       "doc", "document", "upload", "filename", "attachment"]
        ssrf_params = ["url", "uri", "link", "src", "source", "fetch", "load", "request",
                       "proxy", "target", "host", "endpoint", "api", "webhook"]
        idor_params = ["id", "uid", "user_id", "account", "profile", "order", "invoice",
                       "ticket", "record", "item_id", "post_id", "doc_id"]

        if any(p in param_l for p in sqli_params) or value_l.isdigit():
            hints.append("sqli")
        if any(p in param_l for p in xss_params):
            hints.append("xss")
        if any(p in param_l for p in redirect_params):
            hints.append("open_redirect")
        if any(p in param_l for p in file_params):
            hints.append("lfi")
        if any(p in param_l for p in ssrf_params):
            hints.append("ssrf")
        if any(p in param_l for p in idor_params) and value_l.isdigit():
            hints.append("idor")
        if not hints:
            hints.append("xss")  # default — most params are XSS candidates

        return list(set(hints))

    def get_summary(self) -> dict:
        """Return a summary of discovered attack surfaces."""
        by_type = {}
        for s in self.surfaces:
            for hint in s.get("attack_hints", []):
                by_type[hint] = by_type.get(hint, 0) + 1

        return {
            "request_count": self.request_count,
            "surface_count": len(self.surfaces),
            "attack_surface_breakdown": by_type,
            "top_attack_types": sorted(by_type, key=lambda k: by_type[k], reverse=True)[:4],
            "surfaces": self.surfaces[:50],
        }
