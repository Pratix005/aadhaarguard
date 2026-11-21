"""aadhaarguard: find and redact Indian personal data (Aadhaar, PAN, GSTIN, UPI and more)."""

from .detectors import DEFAULT_DETECTORS, KINDS, Detector
from .logfilter import RedactingFilter
from .scanner import STYLES, Match, Scanner, partial_mask, redact, scan

__version__ = "0.2.0"

__all__ = [
    "DEFAULT_DETECTORS",
    "KINDS",
    "STYLES",
    "Detector",
    "Match",
    "RedactingFilter",
    "Scanner",
    "partial_mask",
    "redact",
    "scan",
    "__version__",
]
