import datetime as dt
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import evaluate  # noqa: E402
import export_vanta  # noqa: E402

TODAY = dt.date(2026, 11, 4)
CONTROLS = [
    {"id": "NET-01", "title": "Storage not public", "checks": ["CKV_AZURE_59"],
     "frameworks": {"iso27001": ["A.8.20"]}, "fix": "x",
     "grc": {"vanta": {"document_id": "example-doc-network"}}},
    {"id": "CRY-01", "title": "TLS 1.2+", "checks": ["CKV_AZURE_44"],
     "frameworks": {"soc2": ["CC6.7"]}, "fix": "x",
     "grc": {"vanta": {"document_id": "example-doc-crypto"}}},
]
FINDINGS = [
    {"check_id": "CKV_AZURE_59", "resource": "azurerm_storage_account.a", "passed": False},
    {"check_id": "CKV_AZURE_59", "resource": "azurerm_storage_account.b", "passed": True},
    {"check_id": "CKV_AZURE_44", "resource": "azurerm_storage_account.a", "passed": True},
]
EXCEPTION = {
    "id": "EXC-001", "control": "NET-01", "resource": "azurerm_storage_account.a",
    "owner": "mark.palmer", "justification": "j", "compensating_control": "c",
    "expires": TODAY + dt.timedelta(days=30), "file": "EXC-001.yaml",
}


@pytest.fixture
def evidence_file(tmp_path):
    report = evaluate.evaluate(FINDINGS, CONTROLS, [], TODAY)
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evaluate.build_evidence(report, TODAY)))
    return path


def records_by_id(evidence):
    body = export_vanta.build_custom_resources(evidence, "rid")
    return {r["uniqueId"]: r for r in body["resources"]}


def test_one_record_per_control_and_resource(evidence_file):
    records = records_by_id(json.loads(evidence_file.read_text()))
    assert set(records) == {
        "NET-01:azurerm_storage_account.a",
        "NET-01:azurerm_storage_account.b",
        "CRY-01:azurerm_storage_account.a",
    }
    assert not records["NET-01:azurerm_storage_account.a"]["customProperties"]["compliant"]
    assert records["NET-01:azurerm_storage_account.b"]["customProperties"]["compliant"]


def test_accepted_exception_counts_as_compliant(tmp_path):
    report = evaluate.evaluate(FINDINGS, CONTROLS, [EXCEPTION], TODAY)
    evidence = evaluate.build_evidence(report, TODAY)
    record = records_by_id(evidence)["NET-01:azurerm_storage_account.a"]["customProperties"]
    assert record["status"] == "ACCEPTED" and record["compliant"]
    assert record["exceptionId"] == "EXC-001" and record["exceptionExpires"] == "2026-12-04"


def test_expired_exception_is_not_compliant():
    report = evaluate.evaluate(FINDINGS, CONTROLS, [{**EXCEPTION, "expires": TODAY - dt.timedelta(days=1)}], TODAY)
    record = records_by_id(evaluate.build_evidence(report, TODAY))["NET-01:azurerm_storage_account.a"]
    assert record["customProperties"]["status"] == "EXPIRED"
    assert not record["customProperties"]["compliant"]


def test_one_upload_per_vanta_document(evidence_file):
    evidence = json.loads(evidence_file.read_text())
    uploads = export_vanta.build_document_uploads(evidence, CONTROLS, evidence_file)
    assert sorted(u["path"] for u in uploads) == [
        "/v1/documents/example-doc-crypto/uploads",
        "/v1/documents/example-doc-network/uploads",
    ]
    assert all(evidence["sha256"] in u["fields"]["description"] for u in uploads)


def test_dry_run_writes_requests_without_secrets(evidence_file, tmp_path, monkeypatch):
    monkeypatch.setenv("VANTA_CLIENT_SECRET", "super-secret")
    out = tmp_path / "out"
    assert export_vanta.main(["--evidence", str(evidence_file), "--controls", str(write_controls(tmp_path)),
                              "--out-dir", str(out)]) == 0
    assert sorted(p.name for p in out.iterdir()) == [
        "01-oauth-token.json", "02-custom-resources.json",
        "03-document-uploads.json", "custom-resource-schema.jtd.json",
    ]
    assert "super-secret" not in "".join(p.read_text() for p in out.iterdir())


def test_refuses_tampered_evidence(evidence_file, tmp_path):
    record = json.loads(evidence_file.read_text())
    record["results"][0]["status"] = "PASS"
    evidence_file.write_text(json.dumps(record))
    assert export_vanta.main(["--evidence", str(evidence_file), "--controls", str(write_controls(tmp_path)),
                              "--out-dir", str(tmp_path / "out")]) == 1


def test_send_refuses_placeholder_ids(evidence_file):
    evidence = json.loads(evidence_file.read_text())
    resources = export_vanta.build_custom_resources(evidence, "real-resource-id")
    uploads = export_vanta.build_document_uploads(evidence, CONTROLS, evidence_file)
    with pytest.raises(SystemExit, match="Refusing to send"):
        export_vanta.send(resources, uploads, evidence_file)


def write_controls(tmp_path):
    import yaml
    path = tmp_path / "controls.yaml"
    path.write_text(yaml.safe_dump(CONTROLS))
    return path
