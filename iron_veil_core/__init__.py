"""Iron Veil Open-Core — Sanitizer & Untrusted Repo Quarantiner."""

from .sanitizer import SanitizeResult, quarantine_untrusted_repo, scrub_untrusted_text

__all__ = ["SanitizeResult", "quarantine_untrusted_repo", "scrub_untrusted_text"]
__version__ = "1.2.0"
