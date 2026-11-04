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

## Sending evidence to Vanta

`export_vanta.py` turns `evidence.json` into Vanta [Build Integrations API](https://developer.vanta.com/reference/build-integrations/overview) calls for a private integration:

1. **Custom resources** (`PUT /v1/resources/custom_resource`): one record per control and resource, with `status`, `compliant`, frameworks, exception details, commit, run ID and evidence hash. A Vanta custom test that fails when `compliant` is false then drives the mapped Vanta controls continuously.
2. **Evidence uploads** (`POST /v1/documents/{documentId}/uploads`): `evidence.json` attached to the Vanta document named by `grc.vanta.document_id` in `controls.yaml`.

It refuses to export evidence that fails its hash check.

```bash
.venv/bin/python export_vanta.py              # dry run: writes the exact requests to vanta-dry-run/
.venv/bin/python export_vanta.py --send       # real sync (needs the env vars below)
```

The `grc-sync` workflow runs this on every push to `main` (and on demand). Without Vanta secrets it is a dry run and shows the payload summary on the run page.

**To connect a real Vanta tenant** (not yet tested against one):
1. Create a private integration in Vanta and a custom resource using `vanta-dry-run/custom-resource-schema.jtd.json` as its schema.
2. Replace the `example-` document IDs in `controls.yaml` with real Vanta document IDs.
3. Add repo secrets `VANTA_CLIENT_ID`, `VANTA_CLIENT_SECRET` and `VANTA_RESOURCE_ID`.
4. Create a Vanta custom test on the resource that fails when `compliant` is false, and map it to your controls.

## Running locally

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
demo/run-local.sh              # scan + evaluate, writes comment.md and evidence.json
demo/run-local.sh 2026-12-02   # simulate a later date (exception expiry)
.venv/bin/python export_vanta.py   # preview what Vanta would receive
.venv/bin/python evaluate.py --verify evidence.json   # detect tampering
.venv/bin/python -m pytest -q tests
```

## Setting up on GitHub

1. Push this repo to GitHub (`main` branch).
2. Replace `@your-org/security-team` in `.github/CODEOWNERS` with a real team or username.
3. In **Settings → Branches**, protect `main`: require a PR, require code owner review, and require the `compliance` status check.
4. Open a PR that touches `infra/` and the bot will comment.

See [demo/DEMO.md](demo/DEMO.md) for the hackathon demo runbook.
