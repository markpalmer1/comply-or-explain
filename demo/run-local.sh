#!/usr/bin/env bash
# Offline fallback for the demo: scan infra/ and evaluate, exactly as the GitHub Action does.
# Usage: demo/run-local.sh [YYYY-MM-DD]   (optional date simulates exception expiry)
set -uo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
[ -x .venv/bin/python ] && PY=.venv/bin/python
"$PY" -m checkov.main -d infra --framework terraform -o json --soft-fail > checkov.json 2>/dev/null
"$PY" evaluate.py ${1:+--today "$1"}
rc=$?
echo
echo "PR comment written to comment.md, evidence to evidence.json (exit $rc)"
exit $rc
