"""Test fixture: a Python tool whose usage text quotes a command the project
forbids. The project regexes are written for a command line: met in this
docstring they describe, they do not run. On 2026-10-05 `python3
tools/deploy-ftp.py --dry-run x` was denied for exactly this reason, nine
times. Do not run it.

Usage:
    scripts/deploy/promote-to-production.sh   # the forbidden one, only quoted
    python3 usage-mentions-deny.py --dry-run
"""
import sys

if __name__ == "__main__":
    print("dry run" if "--dry-run" in sys.argv else "nothing")
