"""
Browser-based training mode.
Opens Chrome via Selenium with CDP network logging, intercepts all network
requests in real-time, and streams them to the dashboard as attack surfaces.
"""

import json
import threading
import time
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urlparse, parse_qs


class BrowserTrainer:
    def __init__(self, on_request: Callable, on_log: Callable, on_surface: Callable):
        self.on_request = on_request
        self.on_log = on_log
        self.on_surface = on_surface
        self.driver = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.surfaces = []
        self.request_count = 0

    def start(self, url: str = "about:blank") -> bool:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            from webdriver_manager.chrome import ChromeDriverManager

            options = Options()
            options.add_argument("--start-maximized")
            options.add_argument("--disable-blink-features=AutomationControlled")
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option("useAutomationExtension", False)
            options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)
            self.driver.execute_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
            )
            self.driver.execute_cdp_cmd("Network.enable", {})

            if url and url != "about:blank":
                self.driver.get(url)

            self._running = True
            self._thread = threading.Thread(target=self._intercept_loop, daemon=True)
            self._thread.start()

            self.on_log("Chrome browser launched — browse the target site", "success")
            self.on_log("All network requests are being intercepted via CDP", "info")
            return True

        except Exception as e:
            self.on_log(f"Failed to launch browser: {e}", "error")
            return False

    def stop(self):
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
        seen_ids = set()
        while self._running:
            try:
                if not self.driver:
                    break
                logs = self.driver.get_log("performance")
                for entry in logs:
                    try:
                        msg = json.loads(entry["message"])["message"]
                        if msg.get("method") != "Network.requestWillBeSent":
                            continue
                        params = msg.get("params", {})
                        req_id = params.get("requestId", "")
                        if req_id in seen_ids:
                            continue
                        seen_ids.add(req_id)
                        self._process_request(params)
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(0.3)

    def _process_request(self, params: dict):
        try:
            req = params.get("request", {})
            url = req.get("url", "")
            method = req.get("method", "GET")
            headers = req.get("headers", {})
            body = req.get("postData", "")

            if not url.startswith("http"):
                return

            parsed = urlparse(url)
            host = parsed.netloc
            path = parsed.path

            if any(ext in path.lower() for ext in [
                ".png", ".jpg", ".gif", ".ico", ".woff", ".css", ".svg", ".mp4", ".webp", ".ttf"
            ]):
                return
            if any(d in host for d in [
                "google-analytics", "googletagmanager", "facebook", "doubleclick", "cdn"
            ]):
                return

            self.request_count += 1
            surfaces_found = []

            query_params = parse_qs(parsed.query)
            for param, values in query_params.items():
                surfaces_found.append({
                    "type": "url_param",
                    "url": url,
                    "parameter": param,
                    "value": values[0] if values else "",
                    "method": method,
                    "attack_hints": self._guess_attack_types(param, values[0] if values else ""),
                })

            if method == "POST" and body:
                content_type = headers.get("Content-Type", headers.get("content-type", ""))
                if "application/x-www-form-urlencoded" in content_type:
                    for param, values in parse_qs(body).items():
                        surfaces_found.append({
                            "type": "post_param",
                            "url": url,
                            "parameter": param,
                            "value": values[0] if values else "",
                            "method": "POST",
                            "attack_hints": self._guess_attack_types(param, values[0] if values else ""),
                        })
                elif "application/json" in content_type:
                    try:
                        json_body = json.loads(body)
                        if isinstance(json_body, dict):
                            for param, value in json_body.items():
                                surfaces_found.append({
                                    "type": "json_param",
                                    "url": url,
                                    "parameter": param,
                                    "value": str(value)[:100],
                                    "method": "POST",
                                    "attack_hints": self._guess_attack_types(param, str(value)),
                                })
                    except Exception:
                        pass

            auth = headers.get("Authorization", headers.get("authorization", ""))
            if auth:
                surfaces_found.append({
                    "type": "auth_header",
                    "url": url,
                    "parameter": "Authorization",
                    "value": auth[:40] + "...",
                    "method": method,
                    "attack_hints": ["auth"],
                })

            self.on_request({
                "url": url,
                "method": method,
                "host": host,
                "path": path,
                "has_params": bool(query_params or (method == "POST" and body)),
                "surfaces": len(surfaces_found),
                "timestamp": datetime.now().isoformat(),
            })

            for surface in surfaces_found:
                self.surfaces.append(surface)
                self.on_surface(surface)

            if surfaces_found:
                hints = list(set(h for s in surfaces_found for h in s.get("attack_hints", [])))
                self.on_log(
                    f"[{method}] {path} — {len(surfaces_found)} param(s), "
                    f"possible: {', '.join(hints).upper() if hints else 'unknown'}",
                    "warning",
                )
            elif method in ("GET", "POST") and path not in ("/", ""):
                self.on_log(f"[{method}] {url[:80]}", "url")

        except Exception:
            pass

    def _guess_attack_types(self, param: str, value: str) -> list:
        hints = []
        p = param.lower()
        v = value.lower()

        if any(x in p for x in ["id", "uid", "user_id", "pid", "cat", "search", "q", "query", "filter", "sort", "order", "page", "item"]) or v.isdigit():
            hints.append("sqli")
        if any(x in p for x in ["name", "search", "q", "query", "msg", "message", "comment", "text", "title", "content", "input", "data", "value", "email"]):
            hints.append("xss")
        if any(x in p for x in ["redirect", "return", "url", "next", "goto", "dest", "continue", "callback", "redir", "forward"]):
            hints.append("open_redirect")
        if any(x in p for x in ["file", "path", "page", "include", "load", "template", "view", "doc", "filename"]):
            hints.append("lfi")
        if any(x in p for x in ["url", "uri", "link", "src", "source", "fetch", "proxy", "target", "host", "endpoint", "webhook"]):
            hints.append("ssrf")
        if any(x in p for x in ["id", "uid", "user_id", "account", "order", "invoice", "ticket", "record"]) and v.isdigit():
            hints.append("idor")
        if not hints:
            hints.append("xss")

        return list(set(hints))

    def get_summary(self) -> dict:
        by_type = {}
        for s in self.surfaces:
            for h in s.get("attack_hints", []):
                by_type[h] = by_type.get(h, 0) + 1
        return {
            "request_count": self.request_count,
            "surface_count": len(self.surfaces),
            "attack_surface_breakdown": by_type,
            "top_attack_types": sorted(by_type, key=lambda k: by_type[k], reverse=True)[:4],
            "surfaces": self.surfaces[:50],
        }
