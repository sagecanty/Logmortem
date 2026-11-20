"""
redact.py — strip secrets and personal data from logs before the prompt.

THREAT_MODEL T10: log lines routinely contain things that shouldn't leave
the org: tokens in request headers, keys in stack traces, customers'
emails. Everything in the prompt goes to a third-party API, and anything
the model repeats ends up in the RCA artifact and job summary.

Redaction happens once, in build_context(), so the dry run, the prompt,
the eval harness and the rendered RCA all see the same redacted text.
Patterns are deliberately specific (known token prefixes, key=value
shapes) so incident evidence like IPs, ports, hostnames and commit SHAs
survives.
"""

import re

# (pattern, label) — order matters: specific token formats before generic ones
_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
     "private-key"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "aws-access-key"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), "anthropic-key"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "github-token"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "github-token"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "slack-token"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), "api-key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "jwt"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{16,}"), "auth-header"),
    (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "email"),
]

# key=value / key: value — keep the key name (useful evidence), drop the value
_KV = re.compile(
    r"(?i)\b((?:aws_)?(?:secret(?:_access)?_key|password|passwd|pwd|secret|"
    r"api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|token))"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)


def redact(text: str) -> tuple[str, int]:
    """Return (redacted_text, number_of_values_redacted)."""
    if not text:
        return text, 0
    count = 0

    def _kv(m):
        nonlocal count
        if m.group(3).startswith("[REDACTED"):
            return m.group(0)
        count += 1
        return f"{m.group(1)}{m.group(2)}[REDACTED:secret]"

    text = _KV.sub(_kv, text)
    for rx, label in _PATTERNS:
        text, n = rx.subn(f"[REDACTED:{label}]", text)
        count += n
    return text, count


def redact_events(events: list[dict], field: str) -> tuple[list[dict], int]:
    """Redact `field` in each dict. Returns (new_list, total_redactions)."""
    out, total = [], 0
    for e in events:
        value = e.get(field)
        if isinstance(value, str):
            clean, n = redact(value)
            total += n
            e = {**e, field: clean}
        out.append(e)
    return out, total
