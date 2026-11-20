"""
test_workflow_security.py — regression gates for CI/CD threats in THREAT_MODEL.md.

  T7  expression injection: no `${{ ... }}` inside any `run:` script.
      Actions substitutes expressions into the script text before the shell
      runs, so an attacker-influenced value (e.g. a workflow name) becomes
      code. Values must go through `env:` and be read as "$VAR".
  T8  no long-lived AWS keys referenced anywhere in workflows (OIDC only).
  T13 every third-party action pinned to a full 40-char commit SHA, since
      tags like @v4 can be moved to point at different code.

Same rule as eval/harness.py: validate the instrument before trusting it.
The checker is run against known-bad snippets first, so a green result
means "checked and clean", not "checker silently matched nothing".

No YAML library on purpose: zero extra dependencies, and the scan reads
the raw text the runner actually sees.
"""

import re
from pathlib import Path

import pytest

WORKFLOW_DIR = Path(__file__).resolve().parent.parent / ".github" / "workflows"
WORKFLOWS = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))

_RUN_KEY = re.compile(r"^(?P<indent>\s*)(?:-\s+)?run:\s*(?P<rest>.*)$")
_USES_KEY = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>[^\s#]+)")
_SHA_PINNED = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def run_blocks(text: str) -> list[tuple[int, str]]:
    """Return (line_no, script_text) for every `run:` key, inline or block scalar."""
    lines = text.splitlines()
    blocks = []
    i = 0
    while i < len(lines):
        m = _RUN_KEY.match(lines[i])
        if not m:
            i += 1
            continue
        start = i + 1
        key_indent = len(m.group("indent"))
        rest = m.group("rest").strip()
        if rest and rest[0] not in "|>":
            blocks.append((start, rest))  # inline: run: echo hi
            i += 1
            continue
        body = []
        i += 1
        while i < len(lines):
            line = lines[i]
            if line.strip() and (len(line) - len(line.lstrip())) <= key_indent:
                break
            body.append(line)
            i += 1
        blocks.append((start, "\n".join(body)))
    return blocks


def injection_findings(text: str) -> list[str]:
    return [
        f"line {ln}: `${{{{` expression inside run: script"
        for ln, script in run_blocks(text)
        if "${{" in script
    ]


def unpinned_actions(text: str) -> list[str]:
    bad = []
    for ln, line in enumerate(text.splitlines(), 1):
        m = _USES_KEY.match(line)
        if not m:
            continue
        ref = m.group("ref").strip("'\"")
        if ref.startswith("./") or ref.startswith("docker://"):
            continue  # local or digest-addressed; out of scope for this gate
        if not _SHA_PINNED.match(ref):
            bad.append(f"line {ln}: {ref} is not pinned to a commit SHA")
    return bad


# ── instrument validation: the checker must catch known-bad input ──────────

BAD_INLINE = """
steps:
  - run: echo "${{ github.event.workflow_run.name }}"
"""

BAD_BLOCK = """
steps:
  - name: Post
    run: |
      echo "start"
      echo "**Triggered by:** ${{ github.event.workflow_run.name }}"
  - name: Next
    uses: actions/checkout@v4
"""

GOOD = """
env:
  RUN_NAME: ${{ github.event.workflow_run.name }}
steps:
  - name: Post
    run: |
      printf '%s\\n' "$RUN_NAME"
    env:
      X: ${{ secrets.X }}
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262  # v4.4.0
"""


def test_checker_flags_inline_injection():
    assert injection_findings(BAD_INLINE)


def test_checker_flags_block_injection():
    assert injection_findings(BAD_BLOCK)


def test_checker_ignores_expressions_in_env():
    assert injection_findings(GOOD) == []


def test_checker_flags_tag_pinned_action():
    assert unpinned_actions(BAD_BLOCK) == ["line 8: actions/checkout@v4 is not pinned to a commit SHA"]


def test_checker_accepts_sha_pinned_action():
    assert unpinned_actions(GOOD) == []


# ── the real gates, run against every workflow in the repo ────────────────

def test_workflows_exist():
    assert WORKFLOWS, f"no workflows found in {WORKFLOW_DIR}"


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_no_expression_injection_in_run_scripts(wf):  # T7
    assert injection_findings(wf.read_text()) == []


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_actions_pinned_to_commit_sha(wf):  # T13
    assert unpinned_actions(wf.read_text()) == []


@pytest.mark.parametrize("wf", WORKFLOWS, ids=lambda p: p.name)
def test_no_static_aws_keys(wf):  # T8
    text = wf.read_text()
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        assert name not in text, f"{wf.name} references {name}; use OIDC (AWS_ROLE_ARN)"
