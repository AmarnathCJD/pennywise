"""
Scan results and data structures for PennyWise.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional

from ..config import SeverityLevel

@dataclass
class VulnerabilityFinding:
    """A security finding/vulnerability with full details."""
    id: str
    attack_type: str
    severity: SeverityLevel
    title: str
    description: str
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    db_structure: Optional[str] = None
    request: Optional[Dict[str, Any]] = None
    response: Optional[Dict[str, Any]] = None
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    confidence: float = 0.8
    cvss_score: float = 5.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'attack_type': self.attack_type.value if hasattr(self.attack_type, 'value') else str(self.attack_type),
            'severity': self.severity.value if hasattr(self.severity, 'value') else str(self.severity),
            'title': self.title,
            'description': self.description,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'evidence': self.evidence[:500] if self.evidence else '',
            'db_structure': self.db_structure,
            'recommendations': self.recommendations,
            'timestamp': self.timestamp.isoformat(),
            'confidence': self.confidence,
            'cvss_score': self.cvss_score
        }


@dataclass
class ScanResult:
    """Result of a vulnerability scan."""
    target_url: str
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    pages_scanned: int = 0
    requests_made: int = 0
    duration_seconds: float = 0.0
    status: str = "completed"
    errors: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def add_finding(self, finding: VulnerabilityFinding):
        """Add a finding to the result."""
        self.findings.append(finding)

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)

    def get_findings_by_severity(self, severity: str) -> List[VulnerabilityFinding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity.lower() == severity.lower()]

    def summary(self) -> Dict[str, Any]:
        """Get a summary of the scan results."""
        return {
            'target_url': self.target_url,
            'total_findings': len(self.findings),
            'pages_scanned': self.pages_scanned,
            'requests_made': self.requests_made,
            'duration_seconds': self.duration_seconds,
            'status': self.status,
            'errors_count': len(self.errors)
        }


# Alias for backward compatibility
Finding = VulnerabilityFinding