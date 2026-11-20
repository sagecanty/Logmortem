"""
guard.py — deterministic checks between the model and the human.

THREAT_MODEL T4 (fabricated evidence) and T5 (malicious action items).

The system prompt makes the model *likely* to resist prompt injection, and
the eval harness measures how often it does. This module covers the runs
where it doesn't: it runs on every RCA in production, not just in evals,
and its behavior doesn't depend on the model cooperating.

  - Commit SHAs that aren't in the collected deploy history are marked
    inline as unverified (the eval's grounding check, now enforced at runtime).
  - Action items containing download-and-execute or similar commands are
    withheld entirely. A tired on-call engineer should never be one
    copy-paste away from an attacker's payload.
  - URLs and IPs anywhere in the draft are defanged (hxxp://, [.]) so they
    can't be clicked or pasted straight into a terminal.

Every change is reported as a finding; any finding marks the draft
UNVERIFIED in the rendered output.
"""

import re

_SHA = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)
_URL = re.compile(r"\b(?:https?|ftp)://[^\s)\]>\"'`]+", re.IGNORECASE)
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Patterns that should never reach a human as a recommended action. Kept
# deliberately narrow: ordinary ops commands (kubectl, systemctl, SQL) pass.
_DANGEROUS = [
    (re.compile(r"\b(?:curl|wget)\b[^\n;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", re.I),
     "download piped into a shell"),
    (re.compile(r"\b(?:curl|wget|invoke-webrequest|iwr)\b", re.I),
     "remote download command"),
    (re.compile(r"\b(?:ba|z)?sh\s+-c\b", re.I), "inline shell execution"),
    (re.compile(r"\$\("), "command substitution"),
    (re.compile(r"\bbase64\s+(?:-d|--decode)\b", re.I), "encoded payload decode"),
    (re.compile(r"\b(?:nc|ncat|netcat)\s+-", re.I), "netcat"),
    (re.compile(r"\b(?:iex|invoke-expression)\b", re.I), "PowerShell execution"),
    (re.compile(r"\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)\b", re.I), "recursive force delete"),
    (re.compile(r"\bchmod\s+\+x\b", re.I), "making a file executable"),
]

_TEXT_FIELDS = ("title", "summary", "root_cause", "trigger", "impact",
                "deploy_correlation")
_LIST_FIELDS = ("contributing_factors", "hypotheses")


def defang(text: str) -> tuple[str, int]:
    """hxxp-style defanging for URLs and IPv4 addresses. Returns (text, count)."""
    count = 0

    def _url(m):
        nonlocal count
        count += 1
        u = re.sub(r"^(h)tt(ps?)", r"\1xx\2", m.group(0), flags=re.I)
        u = re.sub(r"^ftp", "fxp", u, flags=re.I)
        return u.replace(".", "[.]")

    def _ip(m):
        nonlocal count
        count += 1
        return m.group(0).replace(".", "[.]")

    text = _URL.sub(_url, text)
    text = _IPV4.sub(_ip, text)
    return text, count


def _known_shas(context: dict) -> set[str]:
    known = {str(d.get("commit", "")).lower()[:8] for d in context.get("deploys", [])}
    known.discard("")
    return known


def _mark_unknown_shas(text: str, known: set[str]) -> tuple[str, list[str]]:
    unknown = []

    def _sub(m):
        s = m.group(0)
        if not any(c in "abcdefABCDEF" for c in s):  # timestamps, counts, ports
            return s
        if s.lower()[:8] in known:
            return s
        unknown.append(s)
        return f"{s} [unverified: not in deploy history]"

    return _SHA.sub(_sub, text), unknown


def _clean_text(text: str, where: str, known: set[str], findings: list[str]) -> str:
    text, n = defang(text)
    if n:
        findings.append(f"{where}: {n} URL/IP reference(s) defanged")
    text, unknown = _mark_unknown_shas(text, known)
    for s in unknown:
        findings.append(f"{where}: cites commit {s}, which is not in the collected deploy history")
    return text


def apply_guard(rca: dict, context: dict) -> tuple[dict, list[str]]:
    """
    Return (guarded_rca, findings). The input dict is not modified.
    An empty findings list means nothing was changed.
    """
    out = dict(rca)
    findings: list[str] = []
    known = _known_shas(context)

    if out.get("_repaired"):
        findings.append("model output was malformed JSON and was auto-repaired; "
                        "fields may be truncated or misplaced")

    for f in _TEXT_FIELDS:
        if isinstance(out.get(f), str):
            out[f] = _clean_text(out[f], f, known, findings)

    for f in _LIST_FIELDS:
        if isinstance(out.get(f), list):
            out[f] = [
                _clean_text(v, f"{f}[{i}]", known, findings) if isinstance(v, str) else v
                for i, v in enumerate(out[f])
            ]

    if isinstance(out.get("timeline"), list):
        out["timeline"] = [
            {**e, "event": _clean_text(e["event"], f"timeline[{i}]", known, findings)}
            if isinstance(e, dict) and isinstance(e.get("event"), str) else e
            for i, e in enumerate(out["timeline"])
        ]

    if isinstance(out.get("action_items"), list):
        items = []
        for i, item in enumerate(out["action_items"]):
            if not isinstance(item, dict):
                items.append(item)
                continue
            action = str(item.get("action", ""))
            reasons = sorted({label for rx, label in _DANGEROUS if rx.search(action)})
            if reasons:
                findings.append(f"action_items[{i}]: withheld ({', '.join(reasons)})")
                items.append({**item, "action": "[withheld by output guard: the "
                              "suggested step contained " + ", ".join(reasons) +
                              ". Work out this step manually from the evidence.]"})
            else:
                items.append({**item, "action": _clean_text(
                    action, f"action_items[{i}]", known, findings)})
        out["action_items"] = items

    return out, findings
