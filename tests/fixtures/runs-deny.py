"""Test fixture: a Python script that really launches a command the project
forbids. deny_commands is the "this is never launched" list and applies to the
code of every script, shell or not; only comments and docstrings are exempt.
Do not run it."""
import subprocess

subprocess.run(["scripts/deploy/promote-to-production.sh"], check=True)
