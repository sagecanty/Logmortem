"""
The exact command auto-rca.yml runs must actually start. `python src/main.py`
crashed with ModuleNotFoundError (src.* imports), so the workflow could not
have produced an RCA. This runs the module entry point offline (fixture +
--dry-run: no AWS, GitHub or API calls) and fails if it can't import or run.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_module_entrypoint_runs_offline():
    result = subprocess.run(
        [sys.executable, "-m", "src.main",
         "--from-fixture", "fixtures/pool-exhaustion.json", "--dry-run"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "RECENT DEPLOYS" in result.stdout


def test_workflow_uses_module_entrypoint():
    wf = (ROOT / ".github" / "workflows" / "auto-rca.yml").read_text()
    assert "python -m src.main" in wf
    assert "python src/main.py" not in wf
