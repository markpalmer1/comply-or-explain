#!/usr/bin/env python3
"""Export Comply or Explain evidence to Vanta (Build Integrations API, private integration).

Two things are sent:
  1. Custom resources: one record per (control, resource) result, so a Vanta custom test
     (e.g. "compliant is false") can pass or fail the mapped Vanta controls continuously.
  2. Document uploads: evidence.json attached to each Vanta document (evidence request)
     named by grc.vanta.document_id in controls.yaml.

Dry run (the default) writes the exact requests to --out-dir and sends nothing.
--send needs VANTA_CLIENT_ID, VANTA_CLIENT_SECRET and VANTA_RESOURCE_ID.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
import uuid
from pathlib import Path

import yaml

from evaluate import FRAMEWORK_LABELS, verify_evidence

API_BASE = os.environ.get("VANTA_API_BASE", "https://api.vanta.com")
SCOPES = "connectors.self:write-resource connectors.self:read-resource self:write-document"
PLACEHOLDER_PREFIX = "example-"
COMPLIANT_STATUSES = {"PASS", "ACCEPTED", "EXPIRING"}
DRY_RUN_RESOURCE_ID = "example-custom-resource-id"

# JSON Type Definition for the custom resource; paste into the Vanta dashboard when creating it.
CUSTOM_RESOURCE_SCHEMA = {
    "properties": {
        "control": {"type": "string"},
        "controlTitle": {"type": "string"},
        "resource": {"type": "string"},
        "status": {"enum": ["PASS", "FAIL", "ACCEPTED", "EXPIRING", "EXPIRED"]},
        "compliant": {"type": "boolean"},
        "failedChecks": {"type": "string"},
        "frameworks": {"type": "string"},
        "exceptionId": {"type": "string"},
        "exceptionOwner": {"type": "string"},
        "exceptionExpires": {"type": "string"},
        "repo": {"type": "string"},
        "commit": {"type": "string"},
        "runId": {"type": "string"},
        "evidenceSha256": {"type": "string"},
        "evaluatedAt": {"type": "timestamp"},
    }
}


def run_url(evidence: dict) -> str:
    repo = evidence.get("repo", "local")
    if repo == "local":
        return "https://github.com/"
    if evidence.get("run_id", "local") == "local":
        return f"https://github.com/{repo}"
    return f"https://github.com/{repo}/actions/runs/{evidence['run_id']}"


def frameworks_text(frameworks: dict) -> str:
    return "; ".join(
        f"{FRAMEWORK_LABELS.get(key, key)} {ref}" for key, refs in frameworks.items() for ref in refs
    )


def build_custom_resources(evidence: dict, resource_id: str) -> dict:
    """PUT /v1/resources/custom_resource body. Each PUT is a full replacement, so send every result."""
    records = []
    for r in evidence["results"]:
        exc = r.get("exception") or {}
        records.append({
            "displayName": f"{r['control']} · {r['resource']}",
            "uniqueId": f"{r['control']}:{r['resource']}",
            "externalUrl": run_url(evidence),
            "customProperties": {
                "control": r["control"],
                "controlTitle": r.get("control_title", ""),
                "resource": r["resource"],
                "status": r["status"],
                "compliant": r["status"] in COMPLIANT_STATUSES,
                "failedChecks": ", ".join(r.get("failed_checks", [])),
                "frameworks": frameworks_text(r.get("frameworks", {})),
                "exceptionId": exc.get("id", ""),
                "exceptionOwner": exc.get("owner", ""),
                "exceptionExpires": exc.get("expires", ""),
                "repo": str(evidence.get("repo", "")),
                "commit": str(evidence.get("commit", "")),
                "runId": str(evidence.get("run_id", "")),
                "evidenceSha256": evidence["sha256"],
                "evaluatedAt": evidence["generated_at"],
            },
        })
    return {"resourceId": resource_id, "resources": records}


def build_document_uploads(evidence: dict, controls: list[dict], evidence_path: Path) -> list[dict]:
    """One POST /v1/documents/{documentId}/uploads per Vanta document touched by these results."""
    doc_for_control = {
        c["id"]: c.get("grc", {}).get("vanta", {}).get("document_id") for c in controls
    }
    by_doc: dict[str, list[str]] = {}
    for r in evidence["results"]:
        doc = doc_for_control.get(r["control"])
        if doc and r["control"] not in by_doc.setdefault(doc, []):
            by_doc[doc].append(r["control"])

    file_bytes = evidence_path.read_bytes()
    uploads = []
    for doc, control_ids in by_doc.items():
        uploads.append({
            "method": "POST",
            "path": f"/v1/documents/{doc}/uploads",
            "content_type": "multipart/form-data",
            "fields": {
                "file": {
                    "filename": f"comply-or-explain-{evidence.get('run_id', 'local')}.json",
                    "source": str(evidence_path),
                    "bytes": len(file_bytes),
                    "sha256": hashlib.sha256(file_bytes).hexdigest(),
                },
                "effectiveAtDate": evidence["generated_at"][:10],
                "description": (
                    f"Comply or Explain evidence for {', '.join(control_ids)} "
                    f"({evidence.get('repo')} @ {evidence.get('commit')}, run {evidence.get('run_id')}, "
                    f"record sha256 {evidence['sha256']})"
                ),
            },
        })
    return uploads


# --- Sending (only with --send) -------------------------------------------------------------

def _request(method: str, path: str, *, token: str | None = None, body: bytes, content_type: str) -> dict:
    headers = {"Content-Type": content_type, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{API_BASE}{path}", data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode() or "{}"
    return json.loads(text)


def get_token(client_id: str, client_secret: str) -> str:
    body = json.dumps({
        "client_id": client_id, "client_secret": client_secret,
        "scope": SCOPES, "grant_type": "client_credentials",
    }).encode()
    return _request("POST", "/oauth/token", body=body, content_type="application/json")["access_token"]


def _multipart(fields: dict[str, str], file_field: str, filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    parts = []
    for name, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
        f"Content-Type: application/json\r\n\r\n".encode() + data + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def send(resources: dict, uploads: list[dict], evidence_path: Path) -> None:
    placeholders = [u["path"] for u in uploads if f"/{PLACEHOLDER_PREFIX}" in u["path"]]
    if resources["resourceId"].startswith(PLACEHOLDER_PREFIX) or placeholders:
        raise SystemExit("Refusing to send: replace example- IDs in controls.yaml / VANTA_RESOURCE_ID first.")
    token = get_token(os.environ["VANTA_CLIENT_ID"], os.environ["VANTA_CLIENT_SECRET"])
    result = _request("PUT", "/v1/resources/custom_resource", token=token,
                      body=json.dumps(resources).encode(), content_type="application/json")
    print(f"custom resources: {result}")
    data = evidence_path.read_bytes()
    for u in uploads:
        f = u["fields"]
        body, ctype = _multipart(
            {"effectiveAtDate": f["effectiveAtDate"], "description": f["description"]},
            "file", f["file"]["filename"], data,
        )
        print(f"{u['path']}: {_request('POST', u['path'], token=token, body=body, content_type=ctype)}")


# --- CLI ------------------------------------------------------------------------------------

def write_dry_run(out_dir: Path, resources: dict, uploads: list[dict]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "01-oauth-token.json").write_text(json.dumps({
        "method": "POST", "path": "/oauth/token", "content_type": "application/json",
        "body": {"client_id": "$VANTA_CLIENT_ID", "client_secret": "***redacted***",
                 "scope": SCOPES, "grant_type": "client_credentials"},
    }, indent=2) + "\n")
    (out_dir / "02-custom-resources.json").write_text(json.dumps({
        "method": "PUT", "path": "/v1/resources/custom_resource",
        "content_type": "application/json", "body": resources,
    }, indent=2) + "\n")
    (out_dir / "03-document-uploads.json").write_text(json.dumps(uploads, indent=2) + "\n")
    (out_dir / "custom-resource-schema.jtd.json").write_text(json.dumps(CUSTOM_RESOURCE_SCHEMA, indent=2) + "\n")


def render_summary(resources: dict, uploads: list[dict], dry_run: bool) -> str:
    records = resources["resources"]
    non_compliant = [r for r in records if not r["customProperties"]["compliant"]]
    lines = [
        f"## Vanta export {'(dry run, nothing sent)' if dry_run else '(sent)'}",
        "",
        f"- `PUT /v1/resources/custom_resource`: **{len(records)}** records "
        f"(**{len(non_compliant)}** non-compliant) to custom resource `{resources['resourceId']}`",
    ]
    lines += [f"- `{u['method']} {u['path']}`: evidence file ({u['fields']['file']['bytes']} bytes)" for u in uploads]
    lines += ["", "| Record | Status | Compliant | Frameworks |", "|---|---|---|---|"]
    for r in records:
        p = r["customProperties"]
        lines.append(f"| `{r['uniqueId']}` | {p['status']} | {'✅' if p['compliant'] else '❌'} | {p['frameworks']} |")
    lines += ["", "Suggested Vanta custom test: fail when any record has `compliant` = false."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--evidence", type=Path, default=Path("evidence.json"))
    p.add_argument("--controls", type=Path, default=Path("controls.yaml"))
    p.add_argument("--out-dir", type=Path, default=Path("vanta-dry-run"))
    p.add_argument("--send", action="store_true", help="Actually call the Vanta API (default is a dry run)")
    p.add_argument("--summary-out", type=Path, help="Also write the markdown summary here")
    args = p.parse_args(argv)

    if not verify_evidence(args.evidence):
        print(f"❌ {args.evidence} failed its hash check; refusing to export tampered evidence.", file=sys.stderr)
        return 1

    evidence = json.loads(args.evidence.read_text())
    controls = yaml.safe_load(args.controls.read_text()) or []
    titles = {c["id"]: c["title"] for c in controls}
    for r in evidence["results"]:
        r["control_title"] = titles.get(r["control"], "")

    resource_id = os.environ.get("VANTA_RESOURCE_ID") or DRY_RUN_RESOURCE_ID
    resources = build_custom_resources(evidence, resource_id)
    uploads = build_document_uploads(evidence, controls, args.evidence)

    if args.send:
        missing = [v for v in ("VANTA_CLIENT_ID", "VANTA_CLIENT_SECRET", "VANTA_RESOURCE_ID") if not os.environ.get(v)]
        if missing:
            print(f"--send needs {', '.join(missing)}", file=sys.stderr)
            return 1
        send(resources, uploads, args.evidence)
    else:
        write_dry_run(args.out_dir, resources, uploads)

    summary = render_summary(resources, uploads, dry_run=not args.send)
    if args.summary_out:
        args.summary_out.write_text(summary)
    print(summary)
    if not args.send:
        print(f"Requests written to {args.out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
