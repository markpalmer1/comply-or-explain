import datetime as dt
import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import evaluate  # noqa: E402

TODAY = dt.date(2026, 11, 4)
RESOURCE = "azurerm_storage_account.public_assets"
CONTROLS = [{
    "id": "NET-01", "title": "Storage not public", "checks": ["CKV_AZURE_59"],
    "frameworks": {"iso27001": ["A.8.20"], "soc2": ["CC6.1"]}, "fix": "Disable public access",
}]
FAILING = [{"check_id": "CKV_AZURE_59", "resource": RESOURCE, "passed": False}]


def exception(**overrides):
    exc = {
        "id": "EXC-001", "control": "NET-01", "resource": RESOURCE, "owner": "mark.palmer",
        "justification": "Public marketing assets", "compensating_control": "No PII",
        "expires": TODAY + dt.timedelta(days=30), "file": "EXC-001.yaml",
    }
    exc.update(overrides)
    return exc


def status(findings, exceptions):
    report = evaluate.evaluate(findings, CONTROLS, exceptions, TODAY)
    return report["results"][0]["status"], report


def test_passing_check_is_pass():
    s, report = status([{**FAILING[0], "passed": True}], [])
    assert s == "PASS" and not report["blocking"]


def test_no_exception_is_fail():
    s, report = status(FAILING, [])
    assert s == "FAIL" and report["blocking"]


def test_valid_exception_is_accepted():
    s, report = status(FAILING, [exception()])
    assert s == "ACCEPTED" and not report["blocking"]


def test_exception_within_14_days_is_expiring():
    s, report = status(FAILING, [exception(expires=TODAY + dt.timedelta(days=14))])
    assert s == "EXPIRING" and not report["blocking"]


def test_past_exception_is_expired_and_blocks():
    s, report = status(FAILING, [exception(expires=TODAY - dt.timedelta(days=1))])
    assert s == "EXPIRED" and report["blocking"]


def test_exception_for_other_resource_does_not_apply():
    s, report = status(FAILING, [exception(resource="azurerm_storage_account.other")])
    assert s == "FAIL"
    assert [e["id"] for e in report["stale"]] == ["EXC-001"]


def test_unmapped_findings_are_ignored():
    report = evaluate.evaluate(
        FAILING + [{"check_id": "CKV_AZURE_33", "resource": RESOURCE, "passed": False}],
        CONTROLS, [], TODAY,
    )
    assert report["ignored"] == 1 and len(report["results"]) == 1


def write_exception(tmp_path, name, **overrides):
    exc = exception(**overrides)
    exc.pop("file")
    exc["expires"] = exc["expires"].isoformat()
    (tmp_path / name).write_text(yaml.safe_dump(exc))


def test_expiry_over_90_days_is_invalid(tmp_path):
    write_exception(tmp_path, "EXC-001.yaml", expires=TODAY + dt.timedelta(days=91))
    with pytest.raises(evaluate.ExceptionFileError, match="more than 90 days"):
        evaluate.load_exceptions(tmp_path, CONTROLS, TODAY)


def test_missing_field_is_invalid(tmp_path):
    write_exception(tmp_path, "EXC-001.yaml", justification="")
    with pytest.raises(evaluate.ExceptionFileError, match="justification"):
        evaluate.load_exceptions(tmp_path, CONTROLS, TODAY)


def test_unknown_control_is_invalid(tmp_path):
    write_exception(tmp_path, "EXC-001.yaml", control="NOPE-99")
    with pytest.raises(evaluate.ExceptionFileError, match="unknown control"):
        evaluate.load_exceptions(tmp_path, CONTROLS, TODAY)


def test_template_is_skipped(tmp_path):
    write_exception(tmp_path, "_template.yaml", control="NOPE-99")
    assert evaluate.load_exceptions(tmp_path, CONTROLS, TODAY) == []


def test_evidence_hash_detects_tampering(tmp_path):
    report = evaluate.evaluate(FAILING, CONTROLS, [], TODAY)
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(evaluate.build_evidence(report, TODAY)))
    assert evaluate.verify_evidence(path)

    tampered = json.loads(path.read_text())
    tampered["results"][0]["status"] = "PASS"
    path.write_text(json.dumps(tampered))
    assert not evaluate.verify_evidence(path)
