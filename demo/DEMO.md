# Demo runbook (under 3 minutes)

## Before you go on stage

- [ ] Repo pushed to GitHub, `main` protected (PR + code owner review + `compliance` check required).
- [ ] Prepare the demo branch (below) and run it once end-to-end so the Actions pip cache is warm. Then close that PR and recreate it from a fresh branch for the live run.
- [ ] Change the expiry in `demo/EXC-001.yaml` so it's 15–90 days after demo day (it must show **ACCEPTED**, not EXPIRING).
- [ ] Have the offline fallback ready in a terminal: `demo/run-local.sh`.
- [ ] Record a backup screen capture of the whole flow.

## Prepare the demo branch

```bash
git checkout -b demo/public-storage
```

In `infra/main.tf`, in the `azurerm_storage_account.public_assets` block, change:

```hcl
public_network_access_enabled   = true
allow_nested_items_to_be_public = true
```

Commit, but **don't push yet**:

```bash
git commit -am "Serve marketing images from public storage"
```

## On stage

1. **The problem (20s).** "Audit evidence today is screenshots and spreadsheets. Exceptions live in someone's inbox and never expire."

2. **Blocked (40s).** `git push -u origin demo/public-storage`, open the PR. The bot comments ❌ **NET-01**, mapped to ISO 27001 A.8.20, SOC 2 CC6.1 and NIST CSF PR.AA-05, and the check goes red. Point at the "How to resolve" section: comply or explain.

3. **Explain (40s).**
   ```bash
   cp demo/EXC-001.yaml exceptions/EXC-001.yaml
   git add exceptions/EXC-001.yaml && git commit -m "Raise EXC-001 for public marketing assets" && git push
   ```
   The comment updates in place to ⚠️ **ACCEPTED until …**, the check goes green, and CODEOWNERS requests a security team review. "The merged PR *is* the approval record."

4. **Expiry (30s).** Set `expires:` in `exceptions/EXC-001.yaml` to yesterday's date, commit and push. Back to ❌ **EXPIRED**: "Exceptions can't quietly live forever."

5. **Evidence (30s).** Open the run's **Summary → Artifacts → compliance-evidence**. Show `evidence.json`: every decision, the framework mapping, the exception owner and expiry, the commit and run ID, and the SHA-256. Locally, edit a status and run `python evaluate.py --verify evidence.json` to show ❌ TAMPERED.

6. **Into the GRC platform (30s, optional).** Open the latest **grc-sync** run on `main` (Actions tab). Its summary shows exactly what Vanta receives: one record per control and resource, flagged compliant or not, plus the evidence file attached to each control's evidence request. "No one uploads a screenshot to Vanta; the merge does it." (Trigger it beforehand with **Run workflow** if nothing has merged.)

7. **Close (20s).** "Test once, comply many. Fix it or explain it, and either way the evidence collects itself."

## Offline fallback (no wifi, Actions queue stuck)

Same story, all local:

```bash
demo/run-local.sh              # after editing main.tf: FAIL
cp demo/EXC-001.yaml exceptions/
demo/run-local.sh              # ACCEPTED
demo/run-local.sh 2026-12-02   # simulate a date after expiry: EXPIRED
cat comment.md                 # the PR comment the bot would post
.venv/bin/python export_vanta.py   # what Vanta would receive
```

## Reset after the demo

```bash
git checkout main && rm -f exceptions/EXC-001.yaml
```
