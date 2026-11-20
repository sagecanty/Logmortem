"""
collector.py — fetches CloudWatch logs and GitHub Actions deploy history
"""

import os
import re
import boto3
import requests
from datetime import datetime, timedelta

from src.redact import redact_events

# Context budget: how many lines the prompt gets
ERROR_LOG_CAP = 50
ALL_LOG_CAP = 200
_HEAD_SHARE = 0.25  # of the cap kept from the start of the window; the rest from the end
_DIGITS = re.compile(r"\d+")


def select_lines(events: list[dict], cap: int) -> tuple[list[dict], int, int]:
    """
    Pick which log lines fit in the prompt (THREAT_MODEL T11).

    Plain `events[:cap]` keeps only the start of the window, so anyone who
    can write log lines (including outsiders, through logged request fields)
    could flood the start of an incident and push the decisive lines out.

    1. Collapse repeats: lines identical except for numbers become one line
       with a repeat_count, so a flood of the same message costs one slot.
    2. If still over the cap, keep the first 25% and the last 75% of the
       window instead of only the first N.

    Returns (selected, omitted_count, collapsed_count). Order stays chronological.
    """
    kept: dict[str, dict] = {}
    collapsed = []
    for e in events:
        key = _DIGITS.sub("#", e.get("message", ""))
        if key in kept:
            kept[key]["repeat_count"] += 1
            continue
        item = {**e, "repeat_count": 1}
        kept[key] = item
        collapsed.append(item)

    dupes = len(events) - len(collapsed)
    if len(collapsed) <= cap:
        return collapsed, 0, dupes
    head = max(1, int(cap * _HEAD_SHARE))
    tail = cap - head
    return collapsed[:head] + collapsed[-tail:], len(collapsed) - cap, dupes


def collect_logs(log_group: str, start_time: datetime, end_time: datetime) -> list[dict]:
    """
    Fetch log events from CloudWatch Logs for the given group and time range.
    Returns a list of {timestamp, message} dicts, sorted by time.
    Filters out health check noise automatically.
    """
    client = boto3.client("logs")

    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)

    # Extend window slightly before incident to catch pre-incident signals
    pre_window_ms = int((start_time - timedelta(minutes=10)).timestamp() * 1000)

    events = []
    kwargs = {
        "logGroupName": log_group,
        "startTime": pre_window_ms,
        "endTime": end_ms,
        "limit": 500,
    }

    try:
        while True:
            response = client.filter_log_events(**kwargs)
            for event in response.get("events", []):
                msg = event.get("message", "").strip()
                # Filter health check noise
                if any(noise in msg for noise in [
                    "ELB-HealthChecker",
                    "health check",
                    "GET /health",
                    "GET /ping",
                ]):
                    continue
                events.append({
                    "timestamp": datetime.fromtimestamp(
                        event["timestamp"] / 1000
                    ).isoformat(),
                    "message": msg,
                })
            next_token = response.get("nextToken")
            if not next_token:
                break
            kwargs["nextToken"] = next_token
    except client.exceptions.ResourceNotFoundException:
        print(f"   ⚠️  Log group '{log_group}' not found in CloudWatch")
    except Exception as e:
        print(f"   ⚠️  CloudWatch error: {e}")

    return sorted(events, key=lambda x: x["timestamp"])


def collect_deploys(repo: str, start_time: datetime) -> list[dict]:
    """
    Fetch GitHub Actions workflow runs for the repo in the 24h window
    before the incident start time.
    Returns list of {time, workflow, status, commit, author} dicts.
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("   ⚠️  GITHUB_TOKEN not set, skipping deploy history")
        return []

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }

    # Look back 24h before incident
    since = (start_time - timedelta(hours=24)).isoformat() + "Z"
    url = f"https://api.github.com/repos/{repo}/actions/runs"
    params = {"created": f">={since}", "per_page": 50}

    deploys = []
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        runs = response.json().get("workflow_runs", [])

        for run in runs:
            deploys.append({
                "time": run.get("created_at", ""),
                "workflow": run.get("name", ""),
                "status": run.get("conclusion", run.get("status", "")),
                "commit": run.get("head_sha", "")[:8],
                "commit_message": run.get("head_commit", {}).get("message", "").split("\n")[0],
                "author": run.get("head_commit", {}).get("author", {}).get("name", ""),
                "url": run.get("html_url", ""),
            })
    except requests.exceptions.RequestException as e:
        print(f"   ⚠️  GitHub API error: {e}")

    return sorted(deploys, key=lambda x: x["time"])


def build_context(
    log_group: str,
    start_time: datetime,
    end_time: datetime,
    alert: str,
    logs: list[dict],
    deploys: list[dict],
) -> dict:
    """
    Assemble all collected data into a single context dict
    passed to the RCA generator.
    """
    duration_minutes = int((end_time - start_time).total_seconds() / 60)

    # Secrets / personal data never reach the prompt or the RCA (THREAT_MODEL T10)
    logs, redacted_logs = redact_events(logs, "message")
    deploys, redacted_deploys = redact_events(deploys, "commit_message")

    # Extract error-level logs for prominence
    error_logs = [
        e for e in logs
        if any(kw in e["message"].lower() for kw in [
            "error", "exception", "fatal", "critical",
            "oom", "killed", "failed", "timeout", "refused"
        ])
    ]

    selected_errors, _, _ = select_lines(error_logs, ERROR_LOG_CAP)
    selected_logs, omitted, collapsed = select_lines(logs, ALL_LOG_CAP)

    return {
        "log_group": log_group,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "duration_minutes": duration_minutes,
        "alert": alert,
        "total_log_events": len(logs),
        "error_log_count": len(error_logs),
        "error_logs": selected_errors,
        "all_logs": selected_logs,
        "omitted_log_events": omitted,
        "collapsed_repeats": collapsed,
        "deploys": deploys,
        "recent_deploys": [d for d in deploys if d.get("status") in ["failure", "success"]],
        "redacted_values": redacted_logs + redacted_deploys,
    }
