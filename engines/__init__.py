"""Scanning engines. Each module exposes scan(target) -> list[finding dict].

Every engine returns findings in the same Semgrep-shaped dict so analyze.py can
merge and report them without knowing which engine produced them:

    {"check_id", "path", "start": {"line", "col"}, "end": {...},
     "extra": {"message", "severity", "lines", "metadata": {...}}}
"""
