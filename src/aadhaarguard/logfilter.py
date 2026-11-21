"""A logging.Filter that redacts Indian PII before records are written.

    import logging
    from aadhaarguard import RedactingFilter

    handler = logging.StreamHandler()
    handler.addFilter(RedactingFilter(style="partial"))
"""

from __future__ import annotations

import logging
from typing import Iterable, Optional

from .scanner import Scanner


class RedactingFilter(logging.Filter):
    def __init__(
        self,
        style: str = "tag",
        kinds: Optional[Iterable[str]] = None,
        min_confidence: float = 0.5,
        scanner: Optional[Scanner] = None,
    ) -> None:
        super().__init__()
        self.style = style
        self.scanner = scanner or Scanner(kinds=kinds, min_confidence=min_confidence)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # bad format args: leave the record for logging to report
            return True
        redacted = self.scanner.redact(message, style=self.style)
        if redacted != message:
            record.msg = redacted
            record.args = None
        if record.exc_info and not record.exc_text:
            # Exception messages often carry user input; format and redact now.
            record.exc_text = self.scanner.redact(
                logging.Formatter().formatException(record.exc_info), style=self.style
            )
        elif record.exc_text:
            record.exc_text = self.scanner.redact(record.exc_text, style=self.style)
        return True
