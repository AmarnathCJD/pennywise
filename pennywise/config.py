"""
Configuration module for PennyWise.
Centralized configuration management with environment variable support.
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import json
from pathlib import Path


class AttackType(Enum):
    """Supported attack types for vulnerability scanning."""
    XSS = "xss"
    SQLI = "sqli"
    CSRF = "csrf"
    AUTH = "auth"
    SSRF = "ssrf"
    IDOR = "idor"
    RCE = "rce"
    LFI = "lfi"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanMode(Enum):
    """Scanning operation modes."""
    PASSIVE = "passive"      # Only observe, no active injection
    ACTIVE = "active"        # Active injection testing
    AGGRESSIVE = "aggressive"  # Full testing with all payloads
    STEALTH = "stealth"      # Minimal footprint scanning


@dataclass
class ScanConfig:
    """Configuration for scanning operations."""
    max_pages: int = 100
    max_depth: int = 5
    request_timeout: int = 15
    delay_between_requests: float = 0.1
    concurrent_requests: int = 5
    follow_redirects: bool = True
    scan_mode: ScanMode = ScanMode.ACTIVE
    
    # Target restrictions
    allowed_hosts: List[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    auto_add_hosts: bool = True
    
    # Headers
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    # Authentication
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None
    
    # Output
    screenshot_enabled: bool = True
    save_requests: bool = True
    output_dir: str = "./pennywise_output"


@dataclass
class AIConfig:
    """Configuration for AI model integration."""
    enabled: bool = True  # Enable/disable AI analysis for faster scanning
    model_path: str = "./qwen-vuln-detector"
    use_local_model: bool = True
    
    # Fallback API (when local model fails)
    api_key: Optional[str] = None
    api_endpoint: Optional[str] = None
    
    # Model parameters
    max_tokens: int = 512
    temperature: float = 0.1
    top_p: float = 0.9


@dataclass 
class SandboxConfig:
    """Configuration for sandbox environment."""
    enabled: bool = True
    capture_inputs: bool = True
    capture_behavior: bool = True
    session_timeout: int = 3600  # 1 hour
    max_actions: int = 1000
    storage_path: str = "./pennywise_data/sandbox"


@dataclass
class LearningConfig:
    """Configuration for behavior learning system."""
    enabled: bool = True
    model_path: str = "./pennywise_data/learning_model"
    min_samples: int = 50  # Minimum samples before adaptation
    update_interval: int = 10  # Update model every N sessions
    pattern_memory: int = 100  # Number of patterns to remember


@dataclass
class PennywiseConfig:
    """Main configuration class for PennyWise."""
    scan: ScanConfig = field(default_factory=ScanConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    learning: LearningConfig = field(default_factory=LearningConfig)
    
    # Global settings
    debug: bool = False
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    @classmethod
    def from_file(cls, path: str) -> "PennywiseConfig":
        """Load configuration from JSON file."""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: dict) -> "PennywiseConfig":
        """Create configuration from dictionary."""
        config = cls()
        
        if 'scan' in data:
            for key, value in data['scan'].items():
                if hasattr(config.scan, key):
                    if key == 'scan_mode':
                        value = ScanMode(value)
                    setattr(config.scan, key, value)
        
        if 'ai' in data:
            for key, value in data['ai'].items():
                if hasattr(config.ai, key):
                    setattr(config.ai, key, value)
        
        if 'sandbox' in data:
            for key, value in data['sandbox'].items():
                if hasattr(config.sandbox, key):
                    setattr(config.sandbox, key, value)
        
        if 'learning' in data:
            for key, value in data['learning'].items():
                if hasattr(config.learning, key):
                    setattr(config.learning, key, value)
        
        # Global settings
        config.debug = data.get('debug', False)
        config.log_level = data.get('log_level', 'INFO')
        config.log_file = data.get('log_file')
        
        return config
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary."""
        return {
            'scan': {
                'max_pages': self.scan.max_pages,
                'max_depth': self.scan.max_depth,
                'request_timeout': self.scan.request_timeout,
                'delay_between_requests': self.scan.delay_between_requests,
                'concurrent_requests': self.scan.concurrent_requests,
                'follow_redirects': self.scan.follow_redirects,
                'scan_mode': self.scan.scan_mode.value,
                'allowed_hosts': self.scan.allowed_hosts,
                'auto_add_hosts': self.scan.auto_add_hosts,
                'user_agent': self.scan.user_agent,
                'custom_headers': self.scan.custom_headers,
                'screenshot_enabled': self.scan.screenshot_enabled,
                'save_requests': self.scan.save_requests,
                'output_dir': self.scan.output_dir
            },
            'ai': {
                'model_path': self.ai.model_path,
                'use_local_model': self.ai.use_local_model,
                'max_tokens': self.ai.max_tokens,
                'temperature': self.ai.temperature,
                'top_p': self.ai.top_p
            },
            'sandbox': {
                'enabled': self.sandbox.enabled,
                'capture_inputs': self.sandbox.capture_inputs,
                'capture_behavior': self.sandbox.capture_behavior,
                'session_timeout': self.sandbox.session_timeout,
                'max_actions': self.sandbox.max_actions,
                'storage_path': self.sandbox.storage_path
            },
            'learning': {
                'enabled': self.learning.enabled,
                'model_path': self.learning.model_path,
                'min_samples': self.learning.min_samples,
                'update_interval': self.learning.update_interval,
                'pattern_memory': self.learning.pattern_memory
            },
            'debug': self.debug,
            'log_level': self.log_level,
            'log_file': self.log_file
        }
    
    def save(self, path: str):
        """Save configuration to JSON file."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


# Default configuration instance
DEFAULT_CONFIG = PennywiseConfig()
