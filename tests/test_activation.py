#!/usr/bin/env python3
"""Checks that guardrail only controls the projects that opted in.

Runs hooks/guard.py without GUARDRAIL_CONFIG, with a fake home and fake folders:
a forbidden command must pass where there is no .guardrail.json and be blocked
where there is one, also in a subfolder, under a configured parent directory, or
after a `cd` out of the project. Where it is off, only the rules that protect
guardrail itself apply, plus masking, which applies wherever the map exists.
Exits 1 at the first failure.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "hooks" / "guard.py"
FORBIDDEN = {"tool_name": "Bash", "tool_input": {"command": 'rm -rf "$GUARDRAIL_CANARY"'}}


def outcome(home: Path, cwd: Path, project: Path | None = None, mask_map: Path | None = None, tool: dict = FORBIDDEN) -> str:
    env = dict(os.environ, HOME=str(home), GUARDRAIL_MASK_MAP=str(mask_map or home / "no-map.tsv"))
    for key in ("GUARDRAIL_CONFIG", "GUARDRAIL_DISABLE", "CLAUDE_PROJECT_DIR"):
        env.pop(key, None)
    if project:
        env["CLAUDE_PROJECT_DIR"] = str(project)
    proc = subprocess.run(
        [sys.executable, str(GUARD)],
        input=json.dumps({**tool, "cwd": str(cwd), "session_id": "test"}),
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=10,
    )
    if proc.returncode != 0:
        raise AssertionError(f"exit {proc.returncode}: {proc.stderr[:300]}")
    if not proc.stdout.strip():
        return "allow"
    return json.loads(proc.stdout)["hookSpecificOutput"].get("permissionDecision", "allow")


def check(name: str, got: str, expected: str) -> int:
    ok = got == expected
    print(f"{'ok  ' if ok else 'FAIL'}  expected={expected:<5} got={got:<5}  {name}")
    return 0 if ok else 1


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="guardrail-act-") as tmp:
        base = Path(tmp)
        home = base / "home"
        home.mkdir()

        free = home / "free"
        (free / ".git").mkdir(parents=True)
        failures += check("folder without .guardrail.json: off", outcome(home, free), "allow")

        (home / ".guardrail.json").write_text('{"deny_commands": ["^ls$"]}', encoding="utf-8")
        failures += check("~/.guardrail.json alone turns nothing on", outcome(home, free), "allow")

        chosen = home / "chosen"
        (chosen / ".git").mkdir(parents=True)
        (chosen / "src").mkdir()
        (chosen / ".guardrail.json").write_text("{}", encoding="utf-8")
        failures += check("project with an empty .guardrail.json: on", outcome(home, chosen), "deny")
        failures += check("subfolder of the project: on", outcome(home, chosen / "src"), "deny")
        ls = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        failures += check("project on: the lists of ~/.guardrail.json apply", outcome(home, chosen, tool=ls), "deny")

        client = home / "client"
        (client / "repo-a" / ".git").mkdir(parents=True)
        (client / ".guardrail.json").write_text("{}", encoding="utf-8")
        failures += check("configured parent directory: on", outcome(home, client / "repo-a"), "deny")

        failures += check("cd out of the active project: stays on", outcome(home, free, project=chosen), "deny")
        failures += check("cd into an active project: on", outcome(home, chosen, project=free), "deny")

        # From a folder where it is off, guardrail cannot be turned off or loosened where it is on.
        def bash(cmd: str) -> dict:
            return {"tool_name": "Bash", "tool_input": {"command": cmd}}

        def write(path: Path) -> dict:
            return {"tool_name": "Write", "tool_input": {"file_path": str(path), "content": '{"allow_commands": [".*"]}'}}

        failures += check("off: rm of another project's .guardrail.json", outcome(home, free, tool=bash(f"rm {chosen}/.guardrail.json")), "deny")
        failures += check("off: the same inside bash -c", outcome(home, free, tool=bash(f"bash -c 'rm {chosen}/.guardrail.json'")), "deny")
        failures += check("off: Write on ~/.guardrail.json", outcome(home, free, tool=write(home / ".guardrail.json")), "ask")
        failures += check("off: redirect on ~/.guardrail.json", outcome(home, free, tool=bash("echo '{}' > ~/.guardrail.json")), "ask")
        failures += check("off: Write in the plugin code", outcome(home, free, tool=write(home / ".claude" / "plugins" / "x" / "guard.py")), "deny")
        failures += check("off: Write on ~/.claude/settings.json", outcome(home, free, tool=write(home / ".claude" / "settings.json")), "ask")
        failures += check("off: everything else passes", outcome(home, free, tool=write(free / "note.txt")), "allow")
        failures += check("off: find -delete of the .guardrail.json", outcome(home, free, tool=bash(f"find {chosen} -name .guardrail.json -delete")), "deny")
        failures += check("off: ln -sf in place of the .guardrail.json", outcome(home, free, tool=bash(f"ln -sf /dev/null {chosen}/.guardrail.json")), "deny")
        settings = write(chosen / ".claude" / "settings.local.json")
        failures += check("off: Write on another project's settings", outcome(home, free, tool=settings), "ask")
        failures += check("on: Write on the project's settings", outcome(home, chosen, tool=settings), "ask")
        failures += check("off: Write in a project's hooks", outcome(home, free, tool=write(chosen / ".claude" / "hooks" / "x.sh")), "ask")
        failures += check("off: Write on an ordinary file in .claude/", outcome(home, free, tool=write(chosen / ".claude" / "note.md")), "allow")

        # A script written on purpose is not a side door.
        (free / "remove.sh").write_text(f"#!/bin/sh\nrm {chosen}/.guardrail.json\n", encoding="utf-8")
        failures += check("off: script that removes a .guardrail.json", outcome(home, free, tool=bash("bash remove.sh")), "deny")
        (chosen / "remove.sh").write_text("#!/bin/sh\nrm .guardrail.json\n", encoding="utf-8")
        failures += check("on: script that removes the .guardrail.json", outcome(home, chosen, tool=bash("bash remove.sh")), "deny")
        (free / "harmless.sh").write_text('#!/bin/sh\nrm -rf "$X"\n', encoding="utf-8")
        failures += check("off: script with something else inside passes", outcome(home, free, tool=bash("bash harmless.sh")), "allow")

        # A script that launches another one: the second is read too.
        (free / "first.sh").write_text("#!/bin/sh\nbash remove.sh\n", encoding="utf-8")
        failures += check("off: script that launches the removing script", outcome(home, free, tool=bash("bash first.sh")), "deny")

        # Globs, upper case, whole folders, second names.
        failures += check("off: rm with a glob", outcome(home, free, tool=bash(f"rm {chosen}/.guardrail*")), "deny")
        failures += check("off: rm in upper case (NTFS)", outcome(home, free, tool=bash(f"rm {chosen}/.GUARDRAIL.JSON")), "deny")
        failures += check("off: rm *.json does not take hidden files", outcome(home, free, tool=bash(f"rm {chosen}/*.json")), "allow")
        failures += check("off: rm -rf of the active project", outcome(home, free, tool=bash(f"rm -rf {chosen}")), "deny")
        failures += check("off: rm -rf of the folder above", outcome(home, free, tool=bash(f"rm -rf {client}")), "deny")
        failures += check("on: git rm -r .", outcome(home, chosen, tool=bash("git rm -r .")), "deny")
        failures += check("on: mv of the project", outcome(home, chosen, tool=bash(f"mv {chosen} {home}/elsewhere")), "deny")
        failures += check("on: rm -rf of an ordinary subfolder", outcome(home, chosen, tool=bash("rm -rf src")), "allow")
        failures += check("off: ln -s towards .guardrail.json", outcome(home, free, tool=bash(f"ln -s {chosen}/.guardrail.json note.json")), "deny")
        failures += check("off: cp -l of .guardrail.json", outcome(home, free, tool=bash(f"cp -l {chosen}/.guardrail.json copy.json")), "deny")
        failures += check("off: plain cp of .guardrail.json", outcome(home, free, tool=bash(f"cp {chosen}/.guardrail.json copy.json")), "allow")
        (free / "note.json").symlink_to(chosen / ".guardrail.json")
        failures += check("off: Write on a link to the .guardrail.json", outcome(home, free, tool=write(free / "note.json")), "ask")
        failures += check("off: redirect on a link to the .guardrail.json", outcome(home, free, tool=bash("echo '{}' > note.json")), "ask")

        # Where it is on, allow_commands does not exempt the removal, and a confirmation
        # on the .guardrail.json does not hide a block from the other rules.
        (chosen / ".guardrail.json").write_text('{"allow_commands": ["^rm "]}', encoding="utf-8")
        failures += check("on: allow_commands does not exempt the removal", outcome(home, chosen, tool=bash("rm .guardrail.json")), "deny")
        failures += check("on: confirmation on the .guardrail.json + rm -rf $X: the block wins",
                          outcome(home, chosen, tool=bash('echo x >> .guardrail.json; cat note | rm -rf "$X"')), "deny")
        (chosen / ".guardrail.json").write_text("{}", encoding="utf-8")

        # A copy of the project in a temporary folder (outside the home) turns nothing
        # on: removing it does not turn guardrail off. As long as the session does not work in it.
        copy = base / "project-copy"
        (copy / ".git").mkdir(parents=True)
        (copy / ".claude").mkdir()
        (copy / ".guardrail.json").write_text("{}", encoding="utf-8")
        failures += check("copy in /tmp: rm -rf passes", outcome(home, chosen, tool=bash(f"rm -rf {copy}")), "allow")
        failures += check("copy in /tmp: rm of its .guardrail.json passes", outcome(home, chosen, tool=bash(f"rm {copy}/.guardrail.json")), "allow")
        failures += check("copy in /tmp: also from a folder that is off", outcome(home, free, tool=bash(f"rm -rf {copy}")), "allow")
        failures += check("copy in /tmp: its settings can be written", outcome(home, chosen, tool=bash(f"echo '{{}}' > {copy}/.claude/settings.json")), "allow")
        failures += check("copy in /tmp the session works in: rm -rf denied", outcome(home, copy, tool=bash(f"rm -rf {copy}")), "deny")
        failures += check("copy in /tmp that is the session's project: denied", outcome(home, chosen, project=copy, tool=bash(f"rm -rf {copy}")), "deny")
        failures += check("copy in /tmp removed through a variable: denied", outcome(home, chosen, tool=bash('C=x; rm "$C/.guardrail.json"')), "deny")
        # A .guardrail.json that is a link towards /tmp is still the project's configuration.
        linked_config = home / "linked-config"
        (linked_config / ".git").mkdir(parents=True)
        (base / "linked-conf.json").write_text("{}", encoding="utf-8")
        (linked_config / ".guardrail.json").symlink_to(base / "linked-conf.json")
        failures += check("link towards /tmp in place of the .guardrail.json: the write asks", outcome(home, linked_config, tool=bash("echo '{}' > .guardrail.json")), "ask")

        # A link to /dev/null in place of the file does not turn guardrail off.
        linked_null = home / "linked-null"
        (linked_null / ".git").mkdir(parents=True)
        (linked_null / ".guardrail.json").symlink_to("/dev/null")
        failures += check("link to /dev/null in place of the .guardrail.json: stays on", outcome(home, linked_null), "deny")

        (base / "mask.tsv").write_text("warehouse\tsite1\n", encoding="utf-8")
        od = {"tool_name": "Bash", "tool_input": {"command": "od -c note.txt"}}
        failures += check("project off: masking applies all the same", outcome(home, free, mask_map=base / "mask.tsv", tool=od), "deny")

    print(f"\nactivation: {'all green' if not failures else f'{failures} failures'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
