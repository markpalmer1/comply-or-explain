# 🛡️ Comply or Explain

A compliance PR bot with **exceptions as code**. Every infrastructure change is checked against our control library before it merges. If it breaks a control, you either:

- **Comply:** fix the code, or
- **Explain:** raise a time-limited, resource-specific exception in `exceptions/`, approved by the security team through CODEOWNERS.

Every decision is written to a hashed evidence record, so audit evidence collects itself.

## How it works

```
PR → Checkov scans infra/ → evaluate.py maps findings to controls.yaml, applies exceptions/
   → one sticky PR comment + evidence.json artifact → PR blocked on FAIL or EXPIRED
```

| Status | Meaning | Blocks PR? |
|---|---|---|
| ✅ PASS | All mapped checks pass | No |
| ❌ FAIL | Control broken, no exception | **Yes** |
| ⚠️ ACCEPTED | Covered by an exception expiring in > 14 days | No |
| ⏳ EXPIRING | Covered by an exception expiring within 14 days | No (warning) |
| ❌ EXPIRED | The exception has expired | **Yes** |

## Raising an exception

1. Copy `exceptions/_template.yaml` to `exceptions/EXC-NNN.yaml`.
2. Fill in every field. It must name **one control and one resource**, and expire within **90 days**.
3. Open a PR. CODEOWNERS requests security team review; the merged PR is the approval record.

Exceptions that no longer match a failing control are flagged as stale so they can be cleaned up.

## Adding a control

Add an entry to `controls.yaml` mapping Checkov check IDs to the control and its framework references (ISO 27001, SOC 2, NIST CSF). Checkov findings not mapped to a control are ignored.

## Running locally

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
demo/run-local.sh              # scan + evaluate, writes comment.md and evidence.json
demo/run-local.sh 2026-12-02   # simulate a later date (exception expiry)
.venv/bin/python evaluate.py --verify evidence.json   # detect tampering
.venv/bin/python -m pytest -q tests
```

## Setting up on GitHub

1. Push this repo to GitHub (`main` branch).
2. Replace `@your-org/security-team` in `.github/CODEOWNERS` with a real team or username.
3. In **Settings → Branches**, protect `main`: require a PR, require code owner review, and require the `compliance` status check.
4. Open a PR that touches `infra/` and the bot will comment.

See [demo/DEMO.md](demo/DEMO.md) for the hackathon demo runbook.
