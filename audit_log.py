"""Append-only JSONL audit log with a hash chain for the prototype.

A hash chain detects accidental or partial edits, but it is not tamper-proof if
an attacker can rewrite the complete file and recompute every hash. Production
systems need protected storage and an external signature/anchor (for example,
a managed WORM store or separately controlled signing service).
"""
from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path
from typing import Any

from rsa_crypto import canonical_json_bytes, sha256_hex, strict_json_loads


class AuditLogError(RuntimeError):
    pass


class AuditLog:
    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._records: list[dict[str, Any]] = []
        self._head = "0" * 64
        self._lock = threading.Lock()
        if self.path is not None and self.path.exists():
            self._load_and_verify()

    @property
    def records(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(copy.deepcopy(item) for item in self._records)

    @property
    def head(self) -> str:
        with self._lock:
            return self._head

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(event, dict):
            raise TypeError("audit event must be a dictionary")
        with self._lock:
            base = {
                "sequence": len(self._records) + 1,
                "previous_hash": self._head,
                "event": copy.deepcopy(event),
            }
            record_hash = sha256_hex(canonical_json_bytes(base))
            record = {**base, "record_hash": record_hash}
            if self.path is not None:
                try:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                except OSError as exc:
                    raise AuditLogError("could not persist audit record") from exc
            self._records.append(record)
            self._head = record_hash
            return copy.deepcopy(record)

    def verify(self) -> bool:
        with self._lock:
            head = "0" * 64
            for expected_seq, record in enumerate(self._records, start=1):
                base = {
                    "sequence": expected_seq,
                    "previous_hash": head,
                    "event": record.get("event"),
                }
                if record.get("sequence") != expected_seq:
                    return False
                if record.get("previous_hash") != head:
                    return False
                if record.get("record_hash") != sha256_hex(canonical_json_bytes(base)):
                    return False
                head = record["record_hash"]
            return head == self._head

    def _load_and_verify(self) -> None:
        assert self.path is not None
        loaded: list[dict[str, Any]] = []
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    record = strict_json_loads(line)
                    if not isinstance(record, dict):
                        raise AuditLogError("invalid record at line %d" % line_number)
                    loaded.append(record)
        except (OSError, ValueError) as exc:
            raise AuditLogError("could not read audit log") from exc

        head = "0" * 64
        for expected_seq, record in enumerate(loaded, start=1):
            base = {
                "sequence": expected_seq,
                "previous_hash": head,
                "event": record.get("event"),
            }
            expected_hash = sha256_hex(canonical_json_bytes(base))
            if (
                record.get("sequence") != expected_seq
                or record.get("previous_hash") != head
                or record.get("record_hash") != expected_hash
            ):
                raise AuditLogError("audit chain verification failed at record %d" % expected_seq)
            head = expected_hash
        self._records = loaded
        self._head = head
