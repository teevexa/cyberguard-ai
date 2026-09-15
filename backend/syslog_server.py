"""A real RFC 3164-ish syslog UDP listener. Runs inside the same asyncio
event loop as FastAPI/uvicorn (started from main.py's lifespan hook), so no
separate process or thread is needed.

Parsing is deliberately lenient: real-world syslog senders vary a lot, and a
receiver that drops a message because it didn't match one exact format is
worse than one that falls back to "store it with best-effort fields." The
one thing we don't fake: detection here is simple severity/keyword pattern
matching, not the RandomForest model — system log text and network flow
records are different data shapes, and the model was never trained on text.
"""

import logging
import re
from datetime import datetime, timezone

logger = logging.getLogger("cyberguard.syslog")

SEVERITY_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
FACILITY_NAMES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp",
    "cron", "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]

_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?:1\s+)?(?P<rest>.*)$", re.DOTALL)
# Plain UDP syslog has no header field for auth/org routing, so a sender that
# wants its messages attributed to a specific organization (rather than the
# bootstrap default org) can prepend this token to the message text itself —
# the same per-org API key already issued for POST /events/ingest (see
# models.ApiKey / Settings > Organization > API Keys). Optional and stripped
# from the stored message either way; an absent, unknown, or revoked token
# just falls back to the default org rather than dropping the message.
_ORG_KEY_RE = re.compile(r"^\[key:(?P<key>\S+)\]\s*(?P<rest>.*)$", re.DOTALL)
_WITH_TIMESTAMP_RE = re.compile(
    r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?P<host>\S+)\s+(?P<tag>[\w\-./]+?)(?:\[\d+\])?:\s*(?P<msg>.*)$",
    re.DOTALL,
)
_HOST_TAG_RE = re.compile(r"^(?P<host>\S+)\s+(?P<tag>[\w\-./]+?)(?:\[\d+\])?:\s*(?P<msg>.*)$", re.DOTALL)

SUSPICIOUS_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"failed password", r"authentication failure", r"invalid user",
        r"permission denied", r"unauthorized", r"brute[\s-]?force",
        r"sql injection", r"exploit", r"port\s?scan", r"segfault",
        r"out of memory", r"disk full",
    ]
]


def parse_syslog_line(raw: str) -> dict:
    raw = raw.strip()
    pri_match = _PRI_RE.match(raw)
    if pri_match:
        pri = int(pri_match.group("pri"))
        facility_num, severity_num = divmod(pri, 8)
        rest = pri_match.group("rest")
    else:
        facility_num, severity_num = 1, 6  # user.info — reasonable default
        rest = raw

    facility = FACILITY_NAMES[facility_num] if facility_num < len(FACILITY_NAMES) else f"facility{facility_num}"
    severity = SEVERITY_NAMES[severity_num] if severity_num < len(SEVERITY_NAMES) else "info"

    m = _WITH_TIMESTAMP_RE.match(rest) or _HOST_TAG_RE.match(rest)
    if m:
        host, tag, message = m.group("host"), m.group("tag"), m.group("msg")
    else:
        host, tag, message = "unknown", None, rest

    org_key = None
    key_match = _ORG_KEY_RE.match(message)
    if key_match:
        org_key = key_match.group("key")
        message = key_match.group("rest")

    flagged, reason = _classify(severity, message)

    return {
        "source_host": host,
        "facility": facility,
        "severity": severity,
        "tag": tag,
        "message": message,
        "raw": raw,
        "flagged": flagged,
        "flag_reason": reason,
        "org_key": org_key,
    }


def _classify(severity: str, message: str) -> tuple[bool, str | None]:
    if severity in ("emerg", "alert", "crit", "err"):
        return True, f"syslog severity '{severity}'"
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(message):
            return True, f"matched pattern: {pattern.pattern}"
    return False, None


class SyslogProtocol:
    """Minimal asyncio DatagramProtocol — parses each packet and hands the
    result to on_message (kept synchronous+injectable so it's trivially
    testable without a real socket)."""

    def __init__(self, on_message):
        self.on_message = on_message

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        try:
            raw = data.decode("utf-8", errors="replace")
            parsed = parse_syslog_line(raw)
            parsed["received_at"] = datetime.now(timezone.utc)
            self.on_message(parsed)
        except Exception:
            logger.exception("Failed to process syslog datagram from %s", addr)

    def error_received(self, exc):
        logger.warning("Syslog UDP error: %s", exc)
