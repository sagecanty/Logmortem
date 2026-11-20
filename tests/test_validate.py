"""
tests/test_validate.py — schema validation and fail-closed parsing (THREAT_MODEL T12).
"""

import json
from pathlib import Path

import pytest

from src.generator import RCAValidationError, parse_rca, validate_rca

ROOT = Path(__file__).resolve().parent.parent

VALID = {
    "title": "Disk full", "severity": "P2", "summary": "Logs filled /var/log.",
    "timeline": [{"time": "09:02", "event": "disk at 93%"}],
    "root_cause": "logrotate removed in 9c8d7e6f", "contributing_factors": ["no disk alarm"],
    "impact": "4 of 6 tasks down", "trigger": "healthcheck failures", "deploy_correlation": None,
    "action_items": [{"priority": "high", "action": "restore logrotate", "owner": "platform"}],
    "hypotheses": [],
}


def test_valid_rca_passes_unchanged():
    assert validate_rca(dict(VALID)) == VALID


def test_unknown_fields_are_dropped():
    out = validate_rca({**VALID, "note_to_operator": "run this", "_repaired": False})
    assert "note_to_operator" not in out and "_repaired" not in out


@pytest.mark.parametrize("bad", [
    [],                                                      # not an object
    {k: v for k, v in VALID.items() if k != "root_cause"},   # missing required
    {**VALID, "summary": ""},                                # empty required
    {**VALID, "action_items": "do things"},                  # wrong type
    {**VALID, "action_items": [{"priority": "high"}]},       # item without action
    {**VALID, "timeline": [{"time": "09:02"}]},              # event missing
    {**VALID, "hypotheses": [{"x": 1}]},                     # non-string entries
])
def test_invalid_shapes_fail_closed(bad):
    with pytest.raises(RCAValidationError):
        validate_rca(bad)


def test_near_valid_json_is_repaired_and_flagged():
    raw = json.dumps(VALID)[:-1] + ",}"  # trailing comma
    out = parse_rca(raw)
    assert out["_repaired"] is True
    assert out["root_cause"] == VALID["root_cause"]


def test_clean_json_is_not_flagged():
    assert "_repaired" not in parse_rca(json.dumps(VALID))


def test_garbage_fails_closed():
    with pytest.raises(RCAValidationError):
        parse_rca("I'm sorry, I can't produce an RCA for this incident.")


def test_real_model_drafts_pass_validation():
    # Every persisted Claude draft must survive the schema check, so it can't
    # be stricter than what the model actually produces.
    for f in sorted((ROOT / "eval" / "results").glob("*.json")):
        validate_rca(json.loads(f.read_text())["draft"])
