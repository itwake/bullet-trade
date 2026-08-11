# Broker write-attempt audit

The QMT relay durably records every authenticated broker write attempt before request
dispatch. The journal is fail-closed: if the synchronous SQLite commit fails, the
broker adapter is not called.

Configure an explicit absolute, access-controlled path:

```dotenv
QMT_SERVER_WRITE_AUDIT_DB=D:\quant\state\qmt-write-audit.sqlite3
```

There is no default path and relative paths are rejected. Missing, relative,
unwritable, or corrupt audit storage does not take down read RPCs or `admin.health`,
but all `place`, `cancel`, and unknown `broker.*` actions fail with
`AUDIT_UNAVAILABLE` before adapter dispatch. `admin.health` exposes only the boolean
`audit_ready`; it does not expose the path or initialization error. SQLite runs in
WAL mode with `synchronous=FULL`. The journal contains only an event sequence,
category (`place`, `cancel`, or `unknown`), boot identifiers, and UTC timestamps. It
does not contain tokens, accounts, symbols, quantities, prices, request IDs, order
IDs, or request payloads.

The server holds a non-blocking cross-process lock at `<database>.lock` for the
store lifetime. A second process cannot open the same audit database or advance its
boot metadata. The lock file may remain after shutdown and contains no secret data.

Broker RPCs use an explicit allowlist: `account`, `positions`, `orders`, `trades`,
`order_status`, `place_order`, and `cancel_order`. Any other `broker.*` action is
durably counted as `unknown` and rejected before adapter dispatch.

`data.market_probe` is a strictly read-only market-data RPC. It projects a fixed
schema from QMT tick and instrument facts and never calls a broker adapter or
advances any write-audit counter. Missing, ambiguous, or malformed source fields
cause the probe to fail instead of being replaced with zero or false defaults.
Health reports this action as degraded until the current Helper runtime has
returned an actual schema-valid probe; method presence alone is not a capability
signal.

## Authenticated receipt

After the normal token handshake, request `admin.audit_receipt` with a fresh
16–128-character URL-safe nonce:

```json
{"action":"admin.audit_receipt","payload":{"nonce":"collector-20260811-084500-a1b2c3"}}
```

The response contains `receipt`, `signature_algorithm`, and `signature`. The receipt
contains the persistent `store_id`, current `boot_sequence` and `boot_id`, global
sequence, the three cumulative counters, UTC issue time, and the caller nonce.

Verification is deterministic:

Before verification, require the expected nonce to equal the receipt nonce and
strictly validate the documented envelope, algorithm, receipt, and counter fields.
Then:

1. Encode `receipt` as UTF-8 JSON with sorted keys, ASCII escaping, no whitespace,
   and no NaN values.
2. Derive the signing key as
   `HMAC-SHA256(token, "bullet-trade/write-audit/receipt-key/v1")`.
3. Verify the hexadecimal signature over
   `"bullet-trade/write-audit/receipt/v1\\0" + canonical_receipt_bytes`.

The nonce binds a receipt to the collector challenge. The token is never stored in
the audit database or returned in the receipt.
