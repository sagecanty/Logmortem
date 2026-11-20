"""
tests/test_flood.py — context flooding (THREAT_MODEL T11).

The old selection kept the first 50 error lines and the first 200 lines.
An attacker who could write enough lines early in the window (e.g. by
sending requests whose bad input gets logged as ERROR) could push the
real cause out of the prompt entirely.
"""

import random
import string
from datetime import datetime

from src.collector import build_context
from src.generator import build_prompt

CAUSE = "FATAL db: too many connections (max_connections=20)"


def _ts(minute: int, second: int) -> str:
    return f"2026-04-08T02:{minute:02d}:{second:02d}"


def _ctx(logs):
    return build_context(
        log_group="/aws/ecs/svc",
        start_time=datetime(2026, 4, 8, 2), end_time=datetime(2026, 4, 8, 3),
        alert="TaskCount low", logs=logs, deploys=[],
    )


def test_identical_flood_collapses_and_cause_survives():
    flood = [{"timestamp": _ts(1, i % 60), "message": f"ERROR GET /login?u={i} 400 bad request"}
             for i in range(500)]
    ctx = _ctx(flood + [{"timestamp": _ts(30, 0), "message": CAUSE}])
    assert any(e["message"] == CAUSE for e in ctx["error_logs"])
    assert any(e["message"] == CAUSE for e in ctx["all_logs"])
    assert ctx["collapsed_repeats"] == 499
    assert "x500 similar lines" in build_prompt(ctx)


def test_varied_flood_before_cause_cannot_push_it_out():
    rng = random.Random(7)
    def junk():
        return "ERROR " + "".join(rng.choices(string.ascii_lowercase, k=24))
    flood = [{"timestamp": _ts(1 + i // 60, i % 60), "message": junk()} for i in range(400)]
    ctx = _ctx(flood + [{"timestamp": _ts(45, 0), "message": CAUSE}])
    assert any(e["message"] == CAUSE for e in ctx["error_logs"])
    assert any(e["message"] == CAUSE for e in ctx["all_logs"])
    assert ctx["omitted_log_events"] > 0
    assert "omitted to fit the context budget" in build_prompt(ctx)


def test_selection_stays_chronological():
    logs = [{"timestamp": _ts(i // 60, i % 60), "message": f"line {chr(97 + i % 26)}{chr(97 + i // 26 % 26)}{chr(97 + i // 676)}"}
            for i in range(600)]
    ctx = _ctx(logs)
    stamps = [e["timestamp"] for e in ctx["all_logs"]]
    assert stamps == sorted(stamps)
