#!/usr/bin/env python3
"""Hook SessionStart: inietta nel contesto dell'agente le regole essenziali.

Stampa su stdout RULES-CORE.md (breve, ~30 righe): Claude Code aggiunge lo stdout
dei hook SessionStart al contesto della sessione. Le regole complete per servizio
stanno in services/ e si caricano con la skill `guardrail`.
"""
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
core = root / "RULES-CORE.md"
try:
    text = core.read_text(encoding="utf-8").strip()
except OSError:
    sys.exit(0)

print("<!-- guardrail: regole essenziali, iniettate a ogni sessione -->")
print(text)
print(f"<!-- regole complete per servizio: {root / 'services'} (skill: guardrail) -->")
