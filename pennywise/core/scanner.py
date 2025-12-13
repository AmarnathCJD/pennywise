"""
Scanner module for PennyWise.
Contains scan result data structures and interfaces.
"""

from .results import ScanResult, VulnerabilityFinding

# Alias for backward compatibility
Finding = VulnerabilityFinding
Finding = VulnerabilityFinding