from __future__ import annotations

import asyncio
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import pytest

from bullet_trade.server.app import ServerApplication
from bullet_trade.server.config import ServerConfig
from bullet_trade.server.session import ClientSession
from bullet_trade.server.write_audit import (
    AuditReceiptError,
    WriteAuditError,
    WriteAuditStore,
    canonical_receipt_bytes,
    verify_receipt,
)


class _Writer:
    def __init__(self) -> None:
        self.messages = []
        self._closing = False

    def is_closing(self) -> bool:
        return self._closing

    def write(self, data: bytes) -> None:
        self.messages.append(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self._closing = True

    async def wait_closed(self) -> None:
        return None


class _OrderingApp:
    def __init__(self, error: Optional[Exception] = None) -> None:
        self.events = []
        self.error = error

    def prepare_request(self, action: str) -> None:
        self.events.append(("audit", action))
        if self.error:
            raise self.error

    async def handle_request(self, session: ClientSession, action: str, payload: Dict) -> Dict:
        self.events.append(("adapter", action))
        return {"ok": True}

    def log_access(self, *args: Any, **kwargs: Any) -> None:
        return None


def test_store_persists_identity_sequence_counters_and_boots(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    first = WriteAuditStore(str(path))
    first.record("place")
    first.record("cancel")
    first.record("unknown")
    receipt1 = first.receipt("token-one", "nonce-abcdefghijklmnop")
    first.close()

    second = WriteAuditStore(str(path))
    receipt2 = second.receipt("token-one", "nonce-qrstuvwxyz123456")

    before = receipt1["receipt"]
    after = receipt2["receipt"]
    assert after["store_id"] == before["store_id"]
    assert after["boot_sequence"] == before["boot_sequence"] + 1
    assert after["boot_id"] != before["boot_id"]
    assert after["global_seq"] == 3
    assert after["counters"] == {"place": 1, "cancel": 1, "unknown": 1}
    assert verify_receipt("token-one", receipt2)
    assert not verify_receipt("token-two", receipt2)
    second.close()


def test_concurrent_records_have_gapless_global_sequence(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    store = WriteAuditStore(str(path))
    categories = ["place", "cancel", "unknown"] * 40
    with ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(store.record, categories))

    assert sorted(item["seq"] for item in results) == list(range(1, 121))
    envelope = store.receipt("token", "concurrency-nonce-0001")
    assert envelope["receipt"]["global_seq"] == 120
    assert envelope["receipt"]["counters"] == {
        "place": 40,
        "cancel": 40,
        "unknown": 40,
    }
    store.close()

    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 120


def test_receipt_is_canonical_nonce_bound_and_contains_no_secrets(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    store = WriteAuditStore(str(path))
    token = "private-token-never-persist"
    envelope = store.receipt(token, "client-nonce-abcdef012345")
    receipt = envelope["receipt"]

    assert canonical_receipt_bytes(receipt) == json.dumps(
        receipt,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    tampered = json.loads(json.dumps(envelope))
    tampered["receipt"]["nonce"] = "different-nonce-123456"
    assert not verify_receipt(token, tampered)
    assert token.encode() not in path.read_bytes()
    assert "account" not in json.dumps(envelope)
    assert "symbol" not in json.dumps(envelope)
    assert "quantity" not in json.dumps(envelope)
    store.close()


@pytest.mark.parametrize("nonce", ["", "short", "space is forbidden 123", "x" * 129])
def test_receipt_rejects_invalid_nonce(tmp_path: Path, nonce: str) -> None:
    store = WriteAuditStore(str(tmp_path / "audit.sqlite3"))
    with pytest.raises(AuditReceiptError):
        store.receipt("token", nonce)
    store.close()


def test_closed_database_fails_audit(tmp_path: Path) -> None:
    store = WriteAuditStore(str(tmp_path / "audit.sqlite3"))
    store.close()
    with pytest.raises(WriteAuditError, match="commit failed"):
        store.record("place")


def test_sqlite_uses_full_synchronous_commits(tmp_path: Path) -> None:
    store = WriteAuditStore(str(tmp_path / "audit.sqlite3"))
    assert store._conn.execute("PRAGMA synchronous").fetchone()[0] == 2
    assert store._conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    store.close()


def test_receipt_fails_closed_on_counter_corruption(tmp_path: Path) -> None:
    store = WriteAuditStore(str(tmp_path / "audit.sqlite3"))
    store.record("place")
    store._conn.execute("UPDATE audit_state SET place_count = 7 WHERE singleton = 1")
    with pytest.raises(WriteAuditError, match="integrity check failed"):
        store.receipt("token", "corruption-check-nonce-01")
    store.close()


def test_broker_action_allowlist_audits_unknown_before_dispatch(tmp_path: Path) -> None:
    config = ServerConfig(token="token", write_audit_db_path=str(tmp_path / "audit.sqlite3"))
    app = ServerApplication(
        config=config,
        router=SimpleNamespace(list_accounts=lambda: []),
        adapters=SimpleNamespace(
            data_adapter=None, broker_adapter=SimpleNamespace(cleanup=lambda: None)
        ),
    )
    with pytest.raises(ValueError, match="unknown broker action"):
        app.prepare_request("broker.cleanup")
    receipt = app.write_audit.receipt("token", "unknown-action-nonce-01")
    assert receipt["receipt"]["counters"] == {"place": 0, "cancel": 0, "unknown": 1}
    app.write_audit.close()


@pytest.mark.asyncio
async def test_authenticated_admin_receipt_and_read_actions_do_not_increment(
    tmp_path: Path,
) -> None:
    config = ServerConfig(token="token", write_audit_db_path=str(tmp_path / "audit.sqlite3"))
    app = ServerApplication(
        config=config,
        router=SimpleNamespace(list_accounts=lambda: []),
        adapters=SimpleNamespace(data_adapter=None, broker_adapter=None),
    )
    for action in (
        "broker.account",
        "broker.positions",
        "broker.orders",
        "broker.trades",
        "broker.order_status",
    ):
        app.prepare_request(action)
    session = SimpleNamespace(is_authenticated=True)
    envelope = await app.handle_request(
        session,
        "admin.audit_receipt",
        {"nonce": "authenticated-nonce-0001"},
    )
    assert envelope["receipt"]["global_seq"] == 0
    assert verify_receipt("token", envelope)
    with pytest.raises(PermissionError):
        await app.handle_request(
            SimpleNamespace(is_authenticated=False),
            "admin.audit_receipt",
            {"nonce": "unauthenticated-nonce-01"},
        )
    app.write_audit.close()


@pytest.mark.asyncio
async def test_session_commits_audit_before_handle_request(monkeypatch) -> None:
    app = _OrderingApp()
    writer = _Writer()
    session = ClientSession(app, asyncio.StreamReader(), writer, "127.0.0.1")  # type: ignore[arg-type]
    session._active = True
    messages = iter(
        [
            {
                "type": "request",
                "id": "not-persisted",
                "action": "broker.place_order",
                "payload": {"symbol": "secret", "quantity": 100},
            }
        ]
    )

    async def _read(_reader):
        try:
            return next(messages)
        except StopIteration:
            session._active = False
            raise asyncio.IncompleteReadError(b"", 4)

    monkeypatch.setattr("bullet_trade.server.session.read_message", _read)
    with pytest.raises(asyncio.IncompleteReadError):
        await session._loop()
    assert app.events == [
        ("audit", "broker.place_order"),
        ("adapter", "broker.place_order"),
    ]


@pytest.mark.asyncio
async def test_session_audit_failure_makes_zero_adapter_calls(monkeypatch) -> None:
    app = _OrderingApp(WriteAuditError("write-audit commit failed"))
    writer = _Writer()
    session = ClientSession(app, asyncio.StreamReader(), writer, "127.0.0.1")  # type: ignore[arg-type]
    session._active = True
    messages = iter(
        [
            {
                "type": "request",
                "id": "not-persisted",
                "action": "broker.cancel_order",
                "payload": {"order_id": "secret"},
            }
        ]
    )

    async def _read(_reader):
        try:
            return next(messages)
        except StopIteration:
            session._active = False
            raise asyncio.IncompleteReadError(b"", 4)

    monkeypatch.setattr("bullet_trade.server.session.read_message", _read)
    with pytest.raises(asyncio.IncompleteReadError):
        await session._loop()
    assert app.events == [("audit", "broker.cancel_order")]
