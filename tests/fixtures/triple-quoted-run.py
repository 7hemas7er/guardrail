"""Test fixture: the forbidden command sits in a triple-quoted string that is
NOT a docstring. Only docstrings found by the parser are exempt. Do not run it."""
import subprocess

subprocess.run(["""scripts/deploy/promote-to-production.sh"""], check=True)
