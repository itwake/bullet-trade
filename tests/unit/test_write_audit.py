from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Tuple

import pytest

from bullet_trade.server.app import ServerApplication
from bullet_trade.server.config import ServerConfig
from bullet_trade.server.write_audit import (
    AuditReceiptError,
    WriteAuditError,
    WriteAuditStore,
    canonical_receipt_bytes,
    verify_receipt,
)


class _BrokerAdapter:
    def __init__(self) -> None:
        self.calls = []

    async def get_account_info(self, _account) -> Dict[str, Any]:
        self.calls.append("account")
        return {"dtype": "dict", "value": {"ok": True}}

    async def place_order(self, _account, _payload) -> Dict[str, Any]:
        self.calls.append("place")
        return {"order_id": "not-audited-data"}

    async def cancel_order(self, _account, _order_id) -> Dict[str, Any]:
        self.calls.append("cancel")
        return {"value": True}


def _app(path: str) -> Tuple[ServerApplication, _BrokerAdapter]:
    broker = _BrokerAdapter()
    config = ServerConfig(token="token", write_audit_db_path=path)
    router = SimpleNamespace(
        list_accounts=lambda: [],
        get=lambda _key: SimpleNamespace(config=SimpleNamespace(key="default")),
    )
    app = ServerApplication(
        config=config,
        router=router,
        adapters=SimpleNamespace(data_adapter=None, broker_adapter=broker),
    )
    return app, broker


def _session(authenticated: bool = True):
    return SimpleNamespace(
        is_authenticated=authenticated,
        account_key=None,
        sub_account_id=None,
    )


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
    assert verify_receipt("token-one", receipt2, "nonce-qrstuvwxyz123456")
    assert not verify_receipt("token-two", receipt2, "nonce-qrstuvwxyz123456")
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
    assert not verify_receipt(token, tampered, "client-nonce-abcdef012345")
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


@pytest.mark.asyncio
async def test_direct_handle_audits_writes_and_unknown_before_dispatch(tmp_path: Path) -> None:
    app, broker = _app(str(tmp_path / "audit.sqlite3"))
    await app.handle_request(_session(), "broker.place_order", {"side": "BUY"})
    await app.handle_request(_session(), "broker.cancel_order", {"order_id": "private"})
    with pytest.raises(ValueError, match="unknown broker action"):
        await app.handle_request(_session(), "broker.cleanup", {})

    assert broker.calls == ["place", "cancel"]
    assert app.write_audit is not None
    envelope = app.write_audit.receipt("token", "direct-handle-nonce-001")
    assert envelope["receipt"]["counters"] == {"place": 1, "cancel": 1, "unknown": 1}
    app.write_audit.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("configured_path", ["", "relative-audit.sqlite3"])
async def test_missing_or_relative_audit_keeps_reads_but_rejects_writes(
    configured_path: str,
) -> None:
    app, broker = _app(configured_path)
    assert app.write_audit is None
    if configured_path:
        assert not Path(configured_path).exists()
    health = await app.handle_request(_session(), "admin.health", {})
    assert health["value"]["audit_ready"] is False
    assert [key for key in health["value"] if key.startswith("audit_")] == ["audit_ready"]
    account = await app.handle_request(_session(), "broker.account", {})
    assert account["value"]["ok"] is True

    for action, payload in (
        ("broker.place_order", {"side": "BUY"}),
        ("broker.cancel_order", {"order_id": "private"}),
        ("broker.cleanup", {}),
    ):
        with pytest.raises(WriteAuditError) as exc_info:
            await app.handle_request(_session(), action, payload)
        assert exc_info.value.code == "AUDIT_UNAVAILABLE"
    with pytest.raises(WriteAuditError):
        await app.handle_request(
            _session(), "admin.audit_receipt", {"nonce": "unavailable-nonce-0001"}
        )
    assert broker.calls == ["account"]


@pytest.mark.asyncio
async def test_unwritable_or_corrupt_audit_keeps_server_readable(tmp_path: Path) -> None:
    blocking_file = tmp_path / "not-a-directory"
    blocking_file.write_text("x", encoding="utf-8")
    corrupt_file = tmp_path / "corrupt.sqlite3"
    corrupt_file.write_bytes(b"not sqlite")

    for path in (blocking_file / "audit.sqlite3", corrupt_file):
        app, broker = _app(str(path))
        assert app.write_audit is None
        assert (await app.handle_request(_session(), "admin.health", {}))["value"][
            "audit_ready"
        ] is False
        await app.handle_request(_session(), "broker.account", {})
        with pytest.raises(WriteAuditError):
            await app.handle_request(_session(), "broker.place_order", {"side": "BUY"})
        assert broker.calls == ["account"]


@pytest.mark.asyncio
async def test_deleted_event_blocks_next_write_before_adapter(tmp_path: Path) -> None:
    app, broker = _app(str(tmp_path / "audit.sqlite3"))
    await app.handle_request(_session(), "broker.place_order", {"side": "BUY"})
    assert app.write_audit is not None
    app.write_audit._conn.execute("DELETE FROM audit_events WHERE seq = 1")

    with pytest.raises(WriteAuditError, match="integrity check failed"):
        await app.handle_request(_session(), "broker.place_order", {"side": "BUY"})
    assert broker.calls == ["place"]
    assert (await app.handle_request(_session(), "admin.health", {}))["value"][
        "audit_ready"
    ] is False
    app.write_audit.close()


@pytest.mark.asyncio
async def test_corrupt_chain_is_rejected_during_restart_but_reads_work(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    store = WriteAuditStore(str(path))
    store.record("place")
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM audit_events WHERE seq = 1")
        connection.commit()
    with pytest.raises(WriteAuditError, match="integrity check failed"):
        WriteAuditStore(str(path))
    app, broker = _app(str(path))
    assert app.write_audit is None
    await app.handle_request(_session(), "broker.account", {})
    with pytest.raises(WriteAuditError):
        await app.handle_request(_session(), "broker.cancel_order", {"order_id": "private"})
    assert broker.calls == ["account"]


@pytest.mark.asyncio
async def test_write_audit_runs_off_event_loop(tmp_path: Path, monkeypatch) -> None:
    app, broker = _app(str(tmp_path / "audit.sqlite3"))
    assert app.write_audit is not None
    original_record = app.write_audit.record

    def slow_record(category: str):
        time.sleep(0.1)
        return original_record(category)

    monkeypatch.setattr(app.write_audit, "record", slow_record)
    write_task = asyncio.create_task(
        app.handle_request(_session(), "broker.place_order", {"side": "BUY"})
    )
    await asyncio.sleep(0.01)
    assert not write_task.done()
    assert (await app.handle_request(_session(), "admin.health", {}))["value"][
        "audit_ready"
    ] is True
    await write_task
    assert broker.calls == ["place"]
    app.write_audit.close()


@pytest.mark.asyncio
async def test_authenticated_receipt_is_strict_and_nonce_bound(tmp_path: Path) -> None:
    app, _broker = _app(str(tmp_path / "audit.sqlite3"))
    nonce = "authenticated-nonce-0001"
    envelope = await app.handle_request(_session(), "admin.audit_receipt", {"nonce": nonce})
    assert verify_receipt("token", envelope, nonce)
    assert not verify_receipt("token", envelope, "replayed-nonce-0000002")
    assert not verify_receipt("wrong-token", envelope, nonce)

    wrong_algorithm = json.loads(json.dumps(envelope))
    wrong_algorithm["signature_algorithm"] = "HMAC-SHA1"
    assert not verify_receipt("token", wrong_algorithm, nonce)
    extra_field = json.loads(json.dumps(envelope))
    extra_field["receipt"]["unexpected"] = True
    assert not verify_receipt("token", extra_field, nonce)
    with pytest.raises(PermissionError):
        await app.handle_request(
            _session(False),
            "admin.audit_receipt",
            {"nonce": "unauthenticated-nonce-01"},
        )
    assert app.write_audit is not None
    app.write_audit.close()
