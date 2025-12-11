"""
Tester Activity Recorder for PennyWise.
Records security tester interactions for reinforcement learning training data.

Features:
- Selenium-based browser session recording
- Captures all HTTP requests/responses
- Records user inputs, clicks, and form submissions
- Tracks payloads tested and their outcomes
- Exports data in JSON format for ML training
"""

import asyncio
import json
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
import threading
import logging

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.common.exceptions import WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from seleniumwire import webdriver as wire_webdriver
    SELENIUM_WIRE_AVAILABLE = True
except ImportError:
    SELENIUM_WIRE_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class UserAction:
    """Records a single user action."""
    timestamp: str
    action_type: str  # click, input, submit, navigate, scroll
    element_selector: Optional[str] = None
    element_tag: Optional[str] = None
    element_id: Optional[str] = None
    element_name: Optional[str] = None
    value: Optional[str] = None
    url: Optional[str] = None
    page_title: Optional[str] = None


@dataclass
class HttpInteraction:
    """Records an HTTP request/response pair."""
    timestamp: str
    method: str
    url: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None
    duration_ms: float = 0


@dataclass
class VulnerabilityAttempt:
    """Records a vulnerability testing attempt."""
    timestamp: str
    attack_type: str  # xss, sqli, csrf, idor, etc.
    target_url: str
    target_parameter: Optional[str] = None
    payload: str = ""
    was_successful: bool = False
    evidence: Optional[str] = None
    tester_notes: Optional[str] = None


@dataclass
class RecordingSession:
    """A complete recording session."""
    session_id: str
    start_time: str
    end_time: Optional[str] = None
    target_url: str = ""
    tester_name: str = "anonymous"
    actions: List[UserAction] = field(default_factory=list)
    http_interactions: List[HttpInteraction] = field(default_factory=list)
    vulnerability_attempts: List[VulnerabilityAttempt] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'target_url': self.target_url,
            'tester_name': self.tester_name,
            'actions': [asdict(a) for a in self.actions],
            'http_interactions': [asdict(h) for h in self.http_interactions],
            'vulnerability_attempts': [asdict(v) for v in self.vulnerability_attempts],
            'findings': self.findings,
            'notes': self.notes,
            'stats': {
                'total_actions': len(self.actions),
                'total_http_requests': len(self.http_interactions),
                'total_vuln_attempts': len(self.vulnerability_attempts),
                'total_findings': len(self.findings),
            }
        }


class TesterRecorder:
    """
    Records security tester activities for ML training data collection.
    
    Usage:
        recorder = TesterRecorder()
        recorder.start_recording("http://target.com", tester_name="alice")
        # ... tester performs manual testing ...
        recorder.mark_vulnerability("xss", "Reflected XSS in search", payload="<script>alert(1)</script>")
        data = recorder.stop_recording()
    """
    
    # Common XSS payloads to detect
    XSS_PATTERNS = [
        '<script', 'javascript:', 'onerror=', 'onload=', 'onclick=',
        'onfocus=', 'onmouseover=', 'alert(', 'prompt(', 'confirm(',
        '<img', '<svg', '<iframe', 'document.cookie', 'eval('
    ]
    
    # Common SQLi patterns to detect
    SQLI_PATTERNS = [
        "' or ", "' and ", "' union ", "' select ", "1=1", "1=2",
        "admin'--", "' --", "';", "or 1=1", "and 1=1", "union select",
        "information_schema", "sqlite_master", "@@version"
    ]
    
    def __init__(self, 
                 recordings_dir: str = None,
                 use_selenium_wire: bool = True,
                 headless: bool = False):
        """
        Initialize the recorder.
        
        Args:
            recordings_dir: Directory to save recordings
            use_selenium_wire: Use selenium-wire for HTTP interception
            headless: Run browser in headless mode
        """
        self.recordings_dir = Path(recordings_dir or 
                                   Path(__file__).parent / "recordings")
        self.recordings_dir.mkdir(exist_ok=True)
        
        self.use_wire = use_selenium_wire and SELENIUM_WIRE_AVAILABLE
        self.headless = headless
        
        self.driver: Optional[webdriver.Chrome] = None
        self.session: Optional[RecordingSession] = None
        self.is_recording = False
        self._action_listener_active = False
        self._last_url = ""
        
        # Validate dependencies
        if not SELENIUM_AVAILABLE:
            logger.warning("Selenium not installed. Install with: pip install selenium")
        if not SELENIUM_WIRE_AVAILABLE:
            logger.warning("Selenium-wire not installed. HTTP interception disabled. "
                          "Install with: pip install selenium-wire")
    
    def start_recording(self, 
                        target_url: str, 
                        tester_name: str = "anonymous") -> bool:
        """
        Start a new recording session.
        
        Args:
            target_url: The URL to test
            tester_name: Name of the tester for tracking
            
        Returns:
            True if recording started successfully
        """
        if not SELENIUM_AVAILABLE:
            print("[ERROR] Selenium is not installed!")
            print("Install it with: pip install selenium selenium-wire")
            return False
        
        try:
            # Initialize Chrome options
            options = Options()
            if self.headless:
                options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--window-size=1920,1080')
            
            # Enable logging
            options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
            
            # Create browser instance
            if self.use_wire:
                self.driver = wire_webdriver.Chrome(options=options)
                print("[*] Using Selenium-Wire for HTTP interception")
            else:
                self.driver = webdriver.Chrome(options=options)
                print("[*] Using standard Selenium (no HTTP interception)")
            
            # Initialize session
            session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.session = RecordingSession(
                session_id=session_id,
                start_time=datetime.now().isoformat(),
                target_url=target_url,
                tester_name=tester_name
            )
            
            # Navigate to target
            self.driver.get(target_url)
            self._last_url = target_url
            
            # Start action listener
            self.is_recording = True
            self._start_action_listener()
            
            print(f"\n{'='*60}")
            print(f"[*] PENNYWISE TESTER RECORDER")
            print(f"{'='*60}")
            print(f"Session ID: {session_id}")
            print(f"Target: {target_url}")
            print(f"Tester: {tester_name}")
            print(f"{'='*60}")
            print("\n[*] Recording started! Perform your security testing.")
            print("[*] Commands:")
            print("    - Press F12 to open DevTools")
            print("    - Type in the console: pennywise.markVuln('xss', 'description', 'payload')")
            print("    - Or call recorder.mark_vulnerability() from Python")
            print("\n[*] The recorder is capturing:")
            print("    - All page navigations")
            print("    - Form submissions")
            print("    - User inputs (auto-classified as attack payloads)")
            print("    - HTTP requests/responses")
            print()
            
            # Inject helper JavaScript
            self._inject_helper_script()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start recording: {e}")
            print(f"[ERROR] Failed to start recording: {e}")
            return False
    
    def _inject_helper_script(self):
        """Inject JavaScript helper for marking vulnerabilities from console."""
        script = """
        window.pennywise = {
            markVuln: function(type, description, payload) {
                window.__pennywise_vuln = {
                    type: type,
                    description: description,
                    payload: payload || '',
                    timestamp: new Date().toISOString()
                };
                console.log('[PennyWise] Vulnerability marked: ' + type);
                return 'Vulnerability recorded!';
            },
            addNote: function(note) {
                window.__pennywise_note = {
                    note: note,
                    timestamp: new Date().toISOString()
                };
                console.log('[PennyWise] Note added');
                return 'Note recorded!';
            },
            getInputs: function() {
                var inputs = [];
                document.querySelectorAll('input, textarea, select').forEach(function(el) {
                    inputs.push({
                        tag: el.tagName,
                        name: el.name,
                        id: el.id,
                        type: el.type,
                        value: el.value
                    });
                });
                return inputs;
            }
        };
        console.log('[PennyWise] Helper loaded. Use pennywise.markVuln(type, desc, payload) to record findings.');
        """
        try:
            self.driver.execute_script(script)
        except Exception as e:
            logger.debug(f"Failed to inject helper script: {e}")
    
    def _start_action_listener(self):
        """Start background thread to monitor user actions."""
        self._action_listener_active = True
        
        def listener_loop():
            while self._action_listener_active and self.is_recording:
                try:
                    self._capture_state()
                    time.sleep(0.5)  # Poll every 500ms
                except Exception as e:
                    logger.debug(f"Listener error: {e}")
        
        thread = threading.Thread(target=listener_loop, daemon=True)
        thread.start()
    
    def _capture_state(self):
        """Capture current browser state and detect actions."""
        if not self.driver or not self.session:
            return
        
        try:
            # Check for URL changes (navigation)
            current_url = self.driver.current_url
            if current_url != self._last_url:
                self.session.actions.append(UserAction(
                    timestamp=datetime.now().isoformat(),
                    action_type='navigate',
                    url=current_url,
                    page_title=self.driver.title
                ))
                self._last_url = current_url
                
                # Re-inject helper script on new pages
                self._inject_helper_script()
            
            # Check for marked vulnerabilities from console
            vuln = self.driver.execute_script("return window.__pennywise_vuln;")
            if vuln:
                self.mark_vulnerability(
                    attack_type=vuln.get('type', 'unknown'),
                    description=vuln.get('description', ''),
                    payload=vuln.get('payload', '')
                )
                self.driver.execute_script("window.__pennywise_vuln = null;")
            
            # Check for notes
            note = self.driver.execute_script("return window.__pennywise_note;")
            if note:
                self.session.notes.append(f"[{note.get('timestamp')}] {note.get('note')}")
                self.driver.execute_script("window.__pennywise_note = null;")
            
            # Capture HTTP interactions (selenium-wire only)
            if self.use_wire and hasattr(self.driver, 'requests'):
                self._capture_http_requests()
            
            # Auto-detect potential attack payloads in inputs
            self._detect_payloads_in_inputs()
            
        except Exception as e:
            logger.debug(f"State capture error: {e}")
    
    def _capture_http_requests(self):
        """Capture HTTP requests from selenium-wire."""
        if not hasattr(self.driver, 'requests'):
            return
        
        for request in self.driver.requests:
            # Skip already processed
            if hasattr(request, '_recorded'):
                continue
            
            try:
                interaction = HttpInteraction(
                    timestamp=datetime.now().isoformat(),
                    method=request.method,
                    url=request.url,
                    request_headers=dict(request.headers) if request.headers else {},
                    request_body=request.body.decode('utf-8', errors='ignore') if request.body else None,
                )
                
                if request.response:
                    interaction.response_status = request.response.status_code
                    interaction.response_headers = dict(request.response.headers) if request.response.headers else {}
                    # Limit response body size
                    body = request.response.body
                    if body:
                        interaction.response_body = body[:5000].decode('utf-8', errors='ignore')
                
                self.session.http_interactions.append(interaction)
                request._recorded = True
                
            except Exception as e:
                logger.debug(f"HTTP capture error: {e}")
    
    def _detect_payloads_in_inputs(self):
        """Auto-detect attack payloads in form inputs."""
        try:
            inputs = self.driver.execute_script("return pennywise.getInputs();")
            if not inputs:
                return
            
            for inp in inputs:
                value = inp.get('value', '')
                if not value or len(value) < 3:
                    continue
                
                value_lower = value.lower()
                
                # Detect XSS payloads
                for pattern in self.XSS_PATTERNS:
                    if pattern in value_lower:
                        self._record_payload_attempt('xss', inp, value)
                        break
                
                # Detect SQLi payloads
                for pattern in self.SQLI_PATTERNS:
                    if pattern in value_lower:
                        self._record_payload_attempt('sqli', inp, value)
                        break
                        
        except Exception as e:
            logger.debug(f"Payload detection error: {e}")
    
    def _record_payload_attempt(self, attack_type: str, input_info: Dict, payload: str):
        """Record an auto-detected payload attempt."""
        # Avoid duplicates
        for attempt in self.session.vulnerability_attempts[-10:]:
            if attempt.payload == payload and attempt.target_parameter == input_info.get('name'):
                return
        
        self.session.vulnerability_attempts.append(VulnerabilityAttempt(
            timestamp=datetime.now().isoformat(),
            attack_type=attack_type,
            target_url=self._last_url,
            target_parameter=input_info.get('name') or input_info.get('id'),
            payload=payload,
            was_successful=False,  # Unknown until marked
            evidence=f"Auto-detected in {input_info.get('tag')} element"
        ))
    
    def mark_vulnerability(self, 
                          attack_type: str, 
                          description: str, 
                          payload: str = "",
                          was_successful: bool = True,
                          evidence: str = "") -> None:
        """
        Mark a vulnerability finding.
        
        Args:
            attack_type: Type of vulnerability (xss, sqli, csrf, idor, etc.)
            description: Description of the finding
            payload: The payload used
            was_successful: Whether the attack was successful
            evidence: Evidence of the vulnerability
        """
        if not self.session:
            print("[ERROR] No active recording session!")
            return
        
        attempt = VulnerabilityAttempt(
            timestamp=datetime.now().isoformat(),
            attack_type=attack_type.lower(),
            target_url=self._last_url,
            payload=payload,
            was_successful=was_successful,
            evidence=evidence,
            tester_notes=description
        )
        
        self.session.vulnerability_attempts.append(attempt)
        
        if was_successful:
            self.session.findings.append({
                'type': attack_type,
                'description': description,
                'payload': payload,
                'url': self._last_url,
                'timestamp': attempt.timestamp
            })
            print(f"[+] VULNERABILITY RECORDED: {attack_type.upper()} - {description[:50]}")
        else:
            print(f"[*] Attempt recorded: {attack_type} - {description[:50]}")
    
    def add_note(self, note: str) -> None:
        """Add a note to the current session."""
        if not self.session:
            return
        self.session.notes.append(f"[{datetime.now().isoformat()}] {note}")
        print(f"[*] Note added: {note[:50]}")
    
    def stop_recording(self, save: bool = True) -> Optional[Dict[str, Any]]:
        """
        Stop recording and optionally save the session.
        
        Args:
            save: Whether to save the recording to disk
            
        Returns:
            The recorded session data
        """
        self.is_recording = False
        self._action_listener_active = False
        
        if not self.session:
            return None
        
        self.session.end_time = datetime.now().isoformat()
        
        # Final HTTP capture
        if self.use_wire:
            self._capture_http_requests()
        
        data = self.session.to_dict()
        
        # Save to file
        if save:
            filename = f"{self.session.session_id}.json"
            filepath = self.recordings_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"\n[*] Recording saved to: {filepath}")
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"[*] RECORDING SUMMARY")
        print(f"{'='*60}")
        print(f"Session: {self.session.session_id}")
        print(f"Duration: {self.session.start_time} -> {self.session.end_time}")
        print(f"Actions recorded: {len(self.session.actions)}")
        print(f"HTTP requests: {len(self.session.http_interactions)}")
        print(f"Attack attempts: {len(self.session.vulnerability_attempts)}")
        print(f"Findings: {len(self.session.findings)}")
        print(f"{'='*60}\n")
        
        # Close browser
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None
        
        return data
    
    def get_session_data(self) -> Optional[Dict[str, Any]]:
        """Get current session data without stopping."""
        if not self.session:
            return None
        return self.session.to_dict()


def convert_recordings_to_training_data(recordings_dir: str = None) -> List[Dict[str, Any]]:
    """
    Convert recorded sessions to ML training data format.
    
    Returns:
        List of training samples with features and labels
    """
    recordings_dir = Path(recordings_dir or Path(__file__).parent / "recordings")
    training_data = []
    
    for json_file in recordings_dir.glob("*.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                session = json.load(f)
            
            # Extract training samples from vulnerability attempts
            for attempt in session.get('vulnerability_attempts', []):
                sample = {
                    'input': {
                        'url': attempt.get('target_url', ''),
                        'parameter': attempt.get('target_parameter', ''),
                        'payload': attempt.get('payload', ''),
                        'attack_type': attempt.get('attack_type', ''),
                    },
                    'output': {
                        'is_vulnerable': attempt.get('was_successful', False),
                        'evidence': attempt.get('evidence', ''),
                    },
                    'context': {
                        'session_id': session.get('session_id', ''),
                        'tester': session.get('tester_name', ''),
                        'timestamp': attempt.get('timestamp', ''),
                    }
                }
                training_data.append(sample)
            
            # Extract successful findings for positive samples
            for finding in session.get('findings', []):
                sample = {
                    'input': {
                        'url': finding.get('url', ''),
                        'payload': finding.get('payload', ''),
                        'attack_type': finding.get('type', ''),
                    },
                    'output': {
                        'is_vulnerable': True,
                        'description': finding.get('description', ''),
                    },
                    'context': {
                        'session_id': session.get('session_id', ''),
                        'tester': session.get('tester_name', ''),
                    }
                }
                training_data.append(sample)
                
        except Exception as e:
            logger.error(f"Error processing {json_file}: {e}")
    
    return training_data


# CLI interface for manual testing
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='PennyWise Tester Recorder')
    parser.add_argument('target', nargs='?', default='http://127.0.0.1:8888/sandbox',
                        help='Target URL to test')
    parser.add_argument('--tester', default='anonymous', help='Tester name')
    parser.add_argument('--headless', action='store_true', help='Run headless')
    parser.add_argument('--convert', action='store_true', 
                        help='Convert recordings to training data')
    
    args = parser.parse_args()
    
    if args.convert:
        print("[*] Converting recordings to training data...")
        data = convert_recordings_to_training_data()
        output_file = Path(__file__).parent / "recordings" / "training_data.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print(f"[*] Saved {len(data)} training samples to {output_file}")
    else:
        recorder = TesterRecorder(headless=args.headless)
        
        if recorder.start_recording(args.target, args.tester):
            print("\n[*] Press Ctrl+C to stop recording...\n")
            try:
                while recorder.is_recording:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Stopping recording...")
            
            recorder.stop_recording()
        else:
            print("[ERROR] Failed to start recording")
