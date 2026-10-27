#!/usr/bin/env python3
"""Tests hooks/session-start.py with a fake home and a fake project.

Checks that the core rules go in only in projects with a .guardrail.json, that a
folder without one receives the notice that guardrail is off only once, and that
the sandbox notice appears only once, and only where guardrail is on. Exits 1 at
the first failure.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "session-start.py"


def run(home: Path, cwd: Path) -> str:
    env = dict(os.environ, HOME=str(home))
    env.pop("GUARDRAIL_CONFIG", None)
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"cwd": str(cwd), "session_id": "test"}),
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=10,
    )
    if proc.returncode != 0:
        raise AssertionError(f"exit {proc.returncode}: {proc.stderr[:300]}")
    return proc.stdout


def check(name: str, condition: bool) -> int:
    print(("ok   " if condition else "FAIL ") + name)
    return 0 if condition else 1


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="guardrail-ss-") as tmp:
        base = Path(tmp)
        home = base / "home"
        (home / ".claude").mkdir(parents=True)
        (home / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
        project = base / "project"
        (project / ".git").mkdir(parents=True)
        (project / ".mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")

        out = run(home, project)
        failures += check("unconfigured folder: no rules", "Production is read" not in out)
        failures += check("unconfigured folder: notice that guardrail is off", "not active" in out and "/guardrail:setup" in out)
        failures += check("the notice cites the production surface", ".mcp.json" in out)
        failures += check("the agent must ask the user yes/no", "AskUserQuestion" in out and "«No»" in out)
        failures += check("unconfigured folder: no sandbox notice", "sandbox" not in out)
        failures += check("state saved", (home / ".claude" / "guardrail.state.json").is_file())

        out2 = run(home, project)
        failures += check("notice not repeated at the second session", "to report" not in out2)
        failures += check("still no rules", "Production is read" not in out2)

        # Any folder, without production hints: same notice, without surface.
        plain = base / "plain"
        (plain / ".git").mkdir(parents=True)
        out3 = run(home, plain)
        failures += check("folder without MCP or deploy: notice here too", "not active" in out3)
        failures += check("folder without MCP or deploy: no surface cited", "surface" not in out3)

        # The user turns it on: rules, and the sandbox-off notice only once.
        (project / ".guardrail.json").write_text("{}", encoding="utf-8")
        out4 = run(home, project)
        failures += check("project on: core rules printed", "core rules" in out4 and "Production is read" in out4)
        failures += check("project on: sandbox-off notice", "sandbox" in out4 and "is off" in out4)
        failures += check("project on: no guardrail-off notice", "not active" not in out4)
        out5 = run(home, project)
        failures += check("project on: rules also afterwards", "Production is read" in out5)
        failures += check("project on: notices not repeated", "to report" not in out5)

        # ~/.guardrail.json alone turns nothing on.
        (home / ".guardrail.json").write_text("{}", encoding="utf-8")
        out6 = run(home, plain)
        failures += check("~/.guardrail.json does not turn on the folders under the home", "Production is read" not in out6)

        # Configured and with the sandbox on: no notice.
        (home / ".claude" / "settings.json").write_text('{"sandbox": {"enabled": true}}', encoding="utf-8")
        other = base / "other"
        (other / ".git").mkdir(parents=True)
        (other / ".mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")
        (other / ".guardrail.json").write_text('{"prod_mcp_servers": ["postgres"]}', encoding="utf-8")
        out7 = run(home, other)
        failures += check("configured project and sandbox on: no notice", "to report" not in out7)

        # Old state file (Italian keys): the notices already shown are not repeated.
        legacy = base / "legacy"
        (legacy / ".git").mkdir(parents=True)
        (home / ".claude" / "guardrail.state.json").write_text(
            json.dumps({"avvisi_mostrati": [f"inattivo:{legacy}"]}), encoding="utf-8"
        )
        out8 = run(home, legacy)
        failures += check("old state file: notice counted as already shown", "not active" not in out8)

    print(f"\nsession-start: {'all green' if not failures else f'{failures} failures'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
