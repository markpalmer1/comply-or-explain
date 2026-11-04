#!/usr/bin/env python3
"""Comply or Explain: evaluate Checkov findings against a control library and exceptions as code.

Every (control, resource) pair gets one status:
  PASS      all mapped checks passed
  FAIL      a mapped check failed and no exception covers it            (blocks the PR)
  ACCEPTED  failed, covered by an exception expiring in > 14 days
  EXPIRING  failed, covered by an exception expiring within 14 days     (warning)
  EXPIRED   failed, covered by an exception that has expired            (blocks the PR)
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path

import yaml

VERSION = "0.1.0"
MAX_EXCEPTION_DAYS = 90
EXPIRING_WITHIN_DAYS = 14
COMMENT_MARKER = "<!-- comply-or-explain -->"
REQUIRED_EXCEPTION_FIELDS = (
    "id", "control", "resource", "owner", "justification", "compensating_control", "expires",
)
BLOCKING = {"FAIL", "EXPIRED"}
STATUS_ORDER = ["FAIL", "EXPIRED", "EXPIRING", "ACCEPTED", "PASS"]
STATUS_LABELS = {
    "FAIL": "failing", "EXPIRED": "expired", "EXPIRING": "expiring",
    "ACCEPTED": "accepted", "PASS": "passing",
}
FRAMEWORK_LABELS = {"iso27001": "ISO 27001", "soc2": "SOC 2", "nist_csf": "NIST CSF"}
PASS_COLLAPSE_THRESHOLD = 5


class ExceptionFileError(Exception):
    """One or more exception files are invalid."""


# --- Loading -------------------------------------------------------------------------------

def load_checkov(path: Path) -> list[dict]:
    """Return [{check_id, resource, passed}] from Checkov JSON (single report or a list of them)."""
    data = json.loads(path.read_text())
    reports = data if isinstance(data, list) else [data]
    findings = []
    for report in reports:
        results = report.get("results", {})
        for key, passed in (("passed_checks", True), ("failed_checks", False)):
            for check in results.get(key, []):
                findings.append(
                    {"check_id": check["check_id"], "resource": check["resource"], "passed": passed}
                )
    return findings


def load_controls(path: Path) -> list[dict]:
    return yaml.safe_load(path.read_text()) or []


def _as_date(value) -> dt.date:
    if isinstance(value, dt.date):
        return value
    return dt.date.fromisoformat(str(value))


def load_exceptions(directory: Path, controls: list[dict], today: dt.date) -> list[dict]:
    """Load and validate exceptions/*.yaml (files starting with '_' are templates and skipped)."""
    control_ids = {c["id"] for c in controls}
    exceptions, errors, seen_ids = [], [], set()
    for path in sorted(directory.glob("*.y*ml")):
        if path.name.startswith("_"):
            continue
        try:
            exc = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as e:
            errors.append(f"`{path.name}`: invalid YAML ({e})")
            continue
        missing = [f for f in REQUIRED_EXCEPTION_FIELDS if not exc.get(f)]
        if missing:
            errors.append(f"`{path.name}`: missing required field(s): {', '.join(missing)}")
            continue
        try:
            exc["expires"] = _as_date(exc["expires"])
        except ValueError:
            errors.append(f"`{path.name}`: `expires` must be an ISO date (YYYY-MM-DD)")
            continue
        if exc["control"] not in control_ids:
            errors.append(f"`{path.name}`: unknown control `{exc['control']}`")
        if exc["id"] in seen_ids:
            errors.append(f"`{path.name}`: duplicate exception id `{exc['id']}`")
        if (exc["expires"] - today).days > MAX_EXCEPTION_DAYS:
            errors.append(
                f"`{path.name}`: expiry {exc['expires']} is more than {MAX_EXCEPTION_DAYS} days away"
            )
        seen_ids.add(exc["id"])
        exc["file"] = path.name
        exceptions.append(exc)
    if errors:
        raise ExceptionFileError("\n".join(errors))
    return exceptions


# --- Evaluation ----------------------------------------------------------------------------

def evaluate(findings: list[dict], controls: list[dict], exceptions: list[dict], today: dt.date) -> dict:
    check_to_control = {check: c for c in controls for check in c["checks"]}
    groups: dict[tuple[str, str], dict] = {}
    ignored = 0
    for f in findings:
        control = check_to_control.get(f["check_id"])
        if control is None:
            ignored += 1
            continue
        group = groups.setdefault(
            (control["id"], f["resource"]), {"control": control, "checks": set(), "failed": set()}
        )
        group["checks"].add(f["check_id"])
        if not f["passed"]:
            group["failed"].add(f["check_id"])

    exc_by_key = {(e["control"], e["resource"]): e for e in exceptions}
    results, used = [], set()
    for (control_id, resource), group in groups.items():
        exc = None
        if not group["failed"]:
            status = "PASS"
        else:
            exc = exc_by_key.get((control_id, resource))
            if exc is None:
                status = "FAIL"
            else:
                used.add(exc["id"])
                days_left = (exc["expires"] - today).days
                if days_left < 0:
                    status = "EXPIRED"
                elif days_left <= EXPIRING_WITHIN_DAYS:
                    status = "EXPIRING"
                else:
                    status = "ACCEPTED"
        results.append({
            "control": group["control"],
            "resource": resource,
            "status": status,
            "checks": sorted(group["checks"]),
            "failed_checks": sorted(group["failed"]),
            "exception": exc,
        })

    results.sort(key=lambda r: (STATUS_ORDER.index(r["status"]), r["control"]["id"], r["resource"]))
    stale = [e for e in exceptions if e["id"] not in used]
    summary = {STATUS_LABELS[s]: sum(r["status"] == s for r in results) for s in STATUS_ORDER}
    return {"results": results, "stale": stale, "ignored": ignored, "summary": summary,
            "blocking": any(r["status"] in BLOCKING for r in results)}


# --- Evidence ------------------------------------------------------------------------------

def github_context() -> dict:
    pr = None
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).exists():
        pr = json.loads(Path(event_path).read_text()).get("pull_request", {}).get("number")
    return {
        "repo": os.environ.get("GITHUB_REPOSITORY", "local"),
        "pr": pr if pr is not None else "local",
        "commit": os.environ.get("GITHUB_SHA", "local")[:12],
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
    }


def hash_record(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "sha256"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def build_evidence(report: dict, today: dt.date) -> dict:
    record = {
        "tool": "comply-or-explain",
        "version": VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evaluated_for_date": today.isoformat(),
        **github_context(),
        "summary": report["summary"],
        "results": [
            {
                "control": r["control"]["id"],
                "resource": r["resource"],
                "status": r["status"],
                "checks": r["checks"],
                "failed_checks": r["failed_checks"],
                "frameworks": r["control"].get("frameworks", {}),
                "exception": None if not r["exception"] else {
                    "id": r["exception"]["id"],
                    "owner": r["exception"]["owner"],
                    "expires": r["exception"]["expires"].isoformat(),
                    "file": r["exception"]["file"],
                },
            }
            for r in report["results"]
        ],
        "stale_exceptions": [e["id"] for e in report["stale"]],
        "unmapped_findings_ignored": report["ignored"],
    }
    record["sha256"] = hash_record(record)
    return record


def verify_evidence(path: Path) -> bool:
    record = json.loads(path.read_text())
    return record.get("sha256") == hash_record(record)


# --- Rendering -----------------------------------------------------------------------------

def _frameworks(control: dict) -> str:
    parts = []
    for key, refs in control.get("frameworks", {}).items():
        parts.extend(f"{FRAMEWORK_LABELS.get(key, key)} {ref}" for ref in refs)
    return " · ".join(parts)


def _status_cell(r: dict) -> str:
    e = r["exception"]
    return {
        "PASS": "✅ PASS",
        "FAIL": "❌ FAIL",
        "EXPIRED": f"❌ EXPIRED {e and e['expires']} ({e and e['id']})",
        "EXPIRING": f"⏳ EXPIRING {e and e['expires']} ({e and e['id']}, owner {e and e['owner']})",
        "ACCEPTED": f"⚠️ ACCEPTED until {e and e['expires']} ({e and e['id']}, owner {e and e['owner']})",
    }[r["status"]]


def _row(r: dict) -> str:
    c = r["control"]
    return f"| {_status_cell(r)} | {c['id']} {c['title']} | `{r['resource']}` | {_frameworks(c)} |"


def render_comment(report: dict, evidence: dict) -> str:
    s = report["summary"]
    counts = [f"{s[label]} {label}" for label in STATUS_LABELS.values()
              if s[label] or label in ("failing", "passing")]
    icon = "❌" if report["blocking"] else "✅"
    lines = [COMMENT_MARKER, f"## 🛡️ Comply or Explain {icon} {' · '.join(counts)}", ""]

    header = ["| Status | Control | Resource | Frameworks |", "|---|---|---|---|"]
    active = [r for r in report["results"] if r["status"] != "PASS"]
    passing = [r for r in report["results"] if r["status"] == "PASS"]
    if active:
        lines += header + [_row(r) for r in active]
    if passing:
        if len(passing) > PASS_COLLAPSE_THRESHOLD or active:
            lines += ["", f"<details><summary>✅ {len(passing)} passing</summary>", ""]
            lines += header + [_row(r) for r in passing] + ["", "</details>"]
        else:
            lines += header + [_row(r) for r in passing]

    to_fix = {r["control"]["id"]: r["control"] for r in report["results"] if r["status"] in BLOCKING}
    if to_fix:
        lines += ["", "### How to resolve"]
        for cid, control in to_fix.items():
            lines.append(f"- **Comply:** {cid}: {control['fix']}")
        lines.append(
            "- **Or explain:** copy `exceptions/_template.yaml` to `exceptions/EXC-NNN.yaml`, "
            "fill in every field (max 90 days), and get it approved by a code owner. "
            "Expired exceptions must be renewed or the control fixed."
        )

    if report["stale"]:
        lines += ["", "### Stale exceptions"]
        lines += [f"- `{e['file']}` ({e['id']}) no longer matches a failing control and can be removed."
                  for e in report["stale"]]

    lines += ["", f"<sub>Evidence: run {evidence['run_id']} · sha256 `{evidence['sha256'][:12]}…` · "
                  f"{report['ignored']} unmapped Checkov findings ignored</sub>", ""]
    return "\n".join(lines)


def render_error_comment(message: str) -> str:
    return "\n".join([
        COMMENT_MARKER, "## 🛡️ Comply or Explain ❌ invalid exception file(s)", "",
        *[f"- {line}" for line in message.splitlines()], "",
        "Fix the exception file(s) above and push again.", "",
    ])


# --- CLI -----------------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--checkov", type=Path, default=Path("checkov.json"))
    p.add_argument("--controls", type=Path, default=Path("controls.yaml"))
    p.add_argument("--exceptions", type=Path, default=Path("exceptions"))
    p.add_argument("--comment-out", type=Path, default=Path("comment.md"))
    p.add_argument("--evidence-out", type=Path, default=Path("evidence.json"))
    p.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today(),
                   help="Override today's date (YYYY-MM-DD) to simulate expiry")
    p.add_argument("--verify", type=Path, metavar="EVIDENCE_JSON",
                   help="Verify an evidence file's hash and exit")
    args = p.parse_args(argv)

    if args.verify:
        ok = verify_evidence(args.verify)
        print(f"{'✅ VALID' if ok else '❌ TAMPERED'}: {args.verify}")
        return 0 if ok else 1

    controls = load_controls(args.controls)
    try:
        exceptions = load_exceptions(args.exceptions, controls, args.today)
    except ExceptionFileError as e:
        args.comment_out.write_text(render_error_comment(str(e)))
        print(f"Invalid exception file(s):\n{e}", file=sys.stderr)
        return 1

    report = evaluate(load_checkov(args.checkov), controls, exceptions, args.today)
    evidence = build_evidence(report, args.today)
    args.evidence_out.write_text(json.dumps(evidence, indent=2) + "\n")
    args.comment_out.write_text(render_comment(report, evidence))

    for r in report["results"]:
        print(f"{r['status']:<9} {r['control']['id']:<7} {r['resource']}")
    print(f"\n{report['summary']} · {report['ignored']} unmapped ignored · sha256 {evidence['sha256'][:12]}")
    return 1 if report["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
