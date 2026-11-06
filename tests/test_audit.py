import json

import pytest

from audit_log import AuditLog, AuditLogError


def test_audit_hash_chain_survives_reload(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    returned = log.append({"decision": "SIGNATURE_VALID", "message_id": "TX-1", "meta": {"x": 1}})
    returned["event"]["meta"]["x"] = 2
    assert log.verify()
    log.append({"decision": "REPLAY_DETECTED", "message_id": "TX-1"})
    assert log.verify()

    reloaded = AuditLog(path)
    assert reloaded.verify()
    assert len(reloaded.records) == 2


def test_audit_detects_modified_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append({"decision": "SIGNATURE_VALID", "message_id": "TX-1"})
    raw = path.read_text(encoding="utf-8")
    record = json.loads(raw)
    record["event"]["decision"] = "REJECTED"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(AuditLogError):
        AuditLog(path)
