from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from filelock import FileLock, Timeout

AUDIT_CATEGORIES = ("place", "cancel", "unknown")
_NONCE_RE = re.compile(r"^[A-Za-z0-9._~-]{16,128}$")
_KEY_DOMAIN = b"bullet-trade/write-audit/receipt-key/v1"
_MESSAGE_DOMAIN = b"bullet-trade/write-audit/receipt/v1\x00"


class WriteAuditError(RuntimeError):
    """A broker write attempt could not be durably recorded."""

    code = "AUDIT_UNAVAILABLE"


class AuditReceiptError(ValueError):
    """An audit receipt request is invalid."""

    code = "INVALID_AUDIT_RECEIPT_REQUEST"


def canonical_receipt_bytes(receipt: Dict[str, Any]) -> bytes:
    """Return the stable UTF-8 representation covered by the receipt MAC."""

    return json.dumps(
        receipt,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sign_receipt(token: str, receipt: Dict[str, Any]) -> str:
    """Sign a canonical receipt with a purpose-separated key derived from the token."""

    key = hmac.new(str(token).encode("utf-8"), _KEY_DOMAIN, hashlib.sha256).digest()
    return hmac.new(
        key, _MESSAGE_DOMAIN + canonical_receipt_bytes(receipt), hashlib.sha256
    ).hexdigest()


def verify_receipt(token: str, envelope: Dict[str, Any], expected_nonce: str) -> bool:
    """Verify an ``admin.audit_receipt`` response without exposing the token."""

    if not isinstance(envelope, dict) or set(envelope) != {
        "receipt",
        "signature_algorithm",
        "signature",
    }:
        return False
    if envelope.get("signature_algorithm") != "HMAC-SHA256":
        return False
    receipt = envelope.get("receipt")
    signature = envelope.get("signature")
    if (
        not isinstance(receipt, dict)
        or set(receipt)
        != {
            "schema_version",
            "store_id",
            "boot_sequence",
            "boot_id",
            "global_seq",
            "counters",
            "issued_at",
            "nonce",
        }
        or not isinstance(signature, str)
        or not re.fullmatch(r"[0-9a-f]{64}", signature)
        or type(receipt.get("schema_version")) is not int
        or receipt.get("schema_version") != 1
        or not isinstance(expected_nonce, str)
        or not _NONCE_RE.fullmatch(expected_nonce)
        or receipt.get("nonce") != expected_nonce
        or not re.fullmatch(r"[0-9a-f]{32}", str(receipt.get("store_id") or ""))
        or not re.fullmatch(r"[0-9a-f]{32}", str(receipt.get("boot_id") or ""))
        or type(receipt.get("boot_sequence")) is not int
        or int(receipt["boot_sequence"]) <= 0
        or type(receipt.get("global_seq")) is not int
        or int(receipt["global_seq"]) < 0
        or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z",
            str(receipt.get("issued_at") or ""),
        )
    ):
        return False
    counters = receipt.get("counters")
    if not isinstance(counters, dict) or set(counters) != set(AUDIT_CATEGORIES):
        return False
    if any(type(counters.get(key)) is not int or counters[key] < 0 for key in AUDIT_CATEGORIES):
        return False
    if sum(counters.values()) != receipt["global_seq"]:
        return False
    return hmac.compare_digest(sign_receipt(token, receipt), signature)


class WriteAuditStore:
    """Synchronous, fail-closed SQLite journal for broker write attempts."""

    def __init__(self, path: str):
        raw_path = str(path or "").strip()
        candidate = Path(raw_path).expanduser() if raw_path else Path()
        if not raw_path or raw_path == ":memory:" or not candidate.is_absolute():
            raise WriteAuditError("absolute persistent write-audit database path is required")
        self.path = str(candidate.resolve())
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._process_lock = FileLock(
            f"{self.path}.lock",
            timeout=0,
            thread_local=False,
        )
        self._closed = False
        try:
            self._process_lock.acquire(timeout=0)
        except Timeout as exc:
            raise WriteAuditError("write-audit database is already in use") from exc
        except Exception as exc:
            raise WriteAuditError("write-audit process lock is unavailable") from exc
        self.boot_id = uuid.uuid4().hex
        self.store_id = ""
        self.boot_sequence = 0
        try:
            self._conn = sqlite3.connect(
                self.path,
                timeout=30.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            with self._lock:
                self._configure()
                self._initialize()
        except Exception as exc:
            connection = getattr(self, "_conn", None)
            try:
                if connection is not None:
                    connection.close()
            finally:
                self._process_lock.release()
            if isinstance(exc, WriteAuditError):
                raise
            raise WriteAuditError("write-audit initialization failed") from exc

    def _configure(self) -> None:
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=30000")

    def _initialize(self) -> None:
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                    store_id TEXT NOT NULL,
                    boot_sequence INTEGER NOT NULL CHECK (boot_sequence >= 0),
                    boot_id TEXT NOT NULL,
                    global_seq INTEGER NOT NULL CHECK (global_seq >= 0),
                    place_count INTEGER NOT NULL CHECK (place_count >= 0),
                    cancel_count INTEGER NOT NULL CHECK (cancel_count >= 0),
                    unknown_count INTEGER NOT NULL CHECK (unknown_count >= 0),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY,
                    category TEXT NOT NULL CHECK (category IN ('place', 'cancel', 'unknown')),
                    boot_sequence INTEGER NOT NULL CHECK (boot_sequence > 0),
                    boot_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                )
                """)
            now = _utc_now()
            row = self._conn.execute("SELECT * FROM audit_state WHERE singleton = 1").fetchone()
            if row is None:
                event_count = int(
                    self._conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
                )
                if event_count:
                    raise WriteAuditError("write-audit integrity check failed")
                store_id = uuid.uuid4().hex
                boot_sequence = 1
                self._conn.execute(
                    """
                    INSERT INTO audit_state (
                        singleton, schema_version, store_id, boot_sequence, boot_id,
                        global_seq, place_count, cancel_count, unknown_count,
                        created_at, updated_at
                    ) VALUES (1, 1, ?, ?, ?, 0, 0, 0, 0, ?, ?)
                    """,
                    (store_id, boot_sequence, self.boot_id, now, now),
                )
            else:
                if int(row["schema_version"]) != 1:
                    raise WriteAuditError("unsupported write-audit schema")
                self._validate_state_in_transaction(row)
                store_id = str(row["store_id"])
                boot_sequence = int(row["boot_sequence"]) + 1
                self._conn.execute(
                    """
                    UPDATE audit_state
                    SET boot_sequence = ?, boot_id = ?, updated_at = ?
                    WHERE singleton = 1
                    """,
                    (boot_sequence, self.boot_id, now),
                )
            self._conn.commit()
            self.store_id = store_id
            self.boot_sequence = boot_sequence
        except Exception:
            self._rollback_quietly()
            raise

    def record(self, category: str) -> Dict[str, Any]:
        if category not in AUDIT_CATEGORIES:
            raise ValueError("unsupported audit category")
        column = f"{category}_count"
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute("SELECT * FROM audit_state WHERE singleton = 1").fetchone()
                if row is None:
                    raise WriteAuditError("write-audit state is missing")
                self._validate_state_in_transaction(row)
                seq = int(row["global_seq"]) + 1
                occurred_at = _utc_now()
                self._conn.execute(
                    """
                    INSERT INTO audit_events (seq, category, boot_sequence, boot_id, occurred_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (seq, category, self.boot_sequence, self.boot_id, occurred_at),
                )
                self._conn.execute(
                    f"""
                    UPDATE audit_state
                    SET global_seq = ?, {column} = {column} + 1, updated_at = ?
                    WHERE singleton = 1
                    """,
                    (seq, occurred_at),
                )
                self._conn.commit()
                return {"seq": seq, "category": category}
            except Exception as exc:
                self._rollback_quietly()
                if isinstance(exc, WriteAuditError):
                    raise
                raise WriteAuditError("write-audit commit failed") from exc

    def receipt(self, token: str, nonce: Any) -> Dict[str, Any]:
        normalized_nonce = str(nonce or "")
        if not _NONCE_RE.fullmatch(normalized_nonce):
            raise AuditReceiptError("nonce must be 16-128 URL-safe characters")
        with self._lock:
            try:
                self._conn.execute("BEGIN")
                row = self._conn.execute("SELECT * FROM audit_state WHERE singleton = 1").fetchone()
                if row is not None:
                    self._validate_state_in_transaction(row)
                self._conn.commit()
            except Exception as exc:
                self._rollback_quietly()
                if isinstance(exc, WriteAuditError):
                    raise
                raise WriteAuditError("write-audit read failed") from exc
        if row is None:
            raise WriteAuditError("write-audit state is missing")
        receipt = {
            "schema_version": 1,
            "store_id": str(row["store_id"]),
            "boot_sequence": int(row["boot_sequence"]),
            "boot_id": str(row["boot_id"]),
            "global_seq": int(row["global_seq"]),
            "counters": {
                "place": int(row["place_count"]),
                "cancel": int(row["cancel_count"]),
                "unknown": int(row["unknown_count"]),
            },
            "issued_at": _utc_now(),
            "nonce": normalized_nonce,
        }
        return {
            "receipt": receipt,
            "signature_algorithm": "HMAC-SHA256",
            "signature": sign_receipt(token, receipt),
        }

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._conn.close()
            finally:
                self._closed = True
                self._process_lock.release()

    def _rollback_quietly(self) -> None:
        try:
            self._conn.rollback()
        except Exception:
            pass

    def _validate_state_in_transaction(self, row: sqlite3.Row) -> None:
        aggregate = self._conn.execute("""
            SELECT
                COUNT(*) AS event_count,
                COALESCE(MAX(seq), 0) AS max_seq,
                COALESCE(SUM(category = 'place'), 0) AS place_count,
                COALESCE(SUM(category = 'cancel'), 0) AS cancel_count,
                COALESCE(SUM(category = 'unknown'), 0) AS unknown_count
            FROM audit_events
            """).fetchone()
        if aggregate is None:
            raise WriteAuditError("write-audit integrity check failed")
        expected = (
            int(row["global_seq"]),
            int(row["place_count"]),
            int(row["cancel_count"]),
            int(row["unknown_count"]),
        )
        observed = (
            int(aggregate["event_count"]),
            int(aggregate["place_count"]),
            int(aggregate["cancel_count"]),
            int(aggregate["unknown_count"]),
        )
        if expected != observed or int(aggregate["max_seq"]) != int(row["global_seq"]):
            raise WriteAuditError("write-audit integrity check failed")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
