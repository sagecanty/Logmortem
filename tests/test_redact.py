"""
tests/test_redact.py — secrets and personal data stripped before the prompt (THREAT_MODEL T10).

Fake credentials below are synthetic and invalid by construction.
"""

import json
from datetime import datetime
from pathlib import Path

from src.collector import build_context
from src.redact import redact

ROOT = Path(__file__).resolve().parent.parent

SECRETS = {
    "aws-access-key": "AKIAABCDEFGHIJKLMNOP",
    "anthropic-key": "sk-ant-api03-" + "x" * 40,
    "github-token": "ghp_" + "a1B2" * 9,
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "email": "jane.doe@example.com",
}


def test_each_token_type_is_redacted():
    for label, value in SECRETS.items():
        out, n = redact(f"ERROR auth failed for {value} on request 4411")
        assert value not in out, label
        assert f"[REDACTED:{label}]" in out, label
        assert n == 1, label


def test_key_value_keeps_key_drops_value():
    out, n = redact('db connect failed password=hunter2 user=app token: "abc123xyz"')
    assert "hunter2" not in out and "abc123xyz" not in out
    assert "password=[REDACTED:secret]" in out
    assert "user=app" in out
    assert n == 2


def test_bearer_header():
    out, _ = redact("GET /api 401 Authorization: Bearer abcdefghijklmnop0123456789")
    assert "abcdefghijklmnop0123456789" not in out


def test_private_key_block():
    out, _ = redact("loaded -----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY----- ok")
    assert "MIIEow" not in out and out.endswith(" ok")


def test_incident_evidence_survives():
    line = ("ERROR app: connect to 10.0.3.12:5432 refused; commit 9c8d7e6f; "
            "/var/log at 93%; max_connections=20; 2026-05-14T09:02:37")
    out, n = redact(line)
    assert out == line and n == 0


def test_build_context_redacts_logs_and_commit_messages():
    ctx = build_context(
        log_group="/aws/ecs/x",
        start_time=datetime(2026, 5, 14, 9), end_time=datetime(2026, 5, 14, 10),
        alert="a",
        logs=[{"timestamp": "2026-05-14T09:01:00", "message": f"ERROR key {SECRETS['aws-access-key']} rejected"}],
        deploys=[{"time": "t", "workflow": "w", "status": "success", "commit": "9c8d7e6f",
                  "commit_message": f"rotate token={SECRETS['github-token']}", "author": "a"}],
    )
    blob = json.dumps(ctx)
    assert SECRETS["aws-access-key"] not in blob
    assert SECRETS["github-token"] not in blob
    assert ctx["redacted_values"] == 2


def test_no_fixture_evidence_is_redacted():
    # Redaction must not eat the evidence the eval scores against
    for f in sorted((ROOT / "fixtures").glob("*.json")):
        data = json.loads(f.read_text())
        for e in data["logs"]:
            out, n = redact(e["message"])
            assert n == 0, f"{f.name}: {e['message']}"
