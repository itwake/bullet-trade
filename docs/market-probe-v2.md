# Strict market probe v2

`data.market_probe` is a read-only RPC for formal cross-provider market-data
comparison. It does not use the compatibility `data.history` path, download
history, create a market subscription, or call any broker API.

The request is exact:

```json
{"security":"000001.XSHE"}
```

The response is exact and has `schema_version=2`:

```json
{
  "schema_version": 2,
  "security": "000001.XSHE",
  "tick": {
    "timestamp": "20260811100220",
    "last_price": 12.3,
    "volume": 1234,
    "previous_close": 12.0,
    "bid1_price": 12.29,
    "bid1_volume": 100,
    "ask1_price": 12.31,
    "ask1_volume": 300,
    "suspended": false,
    "is_st": false
  },
  "minute_bar": {
    "timestamp": "20260811100100",
    "open": 12.1,
    "high": 12.4,
    "low": 12.0,
    "close": 12.3,
    "volume": 321
  }
}
```

All timestamps are 14 ASCII digits in Asia/Shanghai civil time. `tick.timestamp`
is the QMT snapshot time. `minute_bar.timestamp` is the bar's inclusive start
label. Native QMT 1-minute indexes are end labels, so the Helper subtracts exactly
one minute after proving that the source endpoint is not later than the tick's
current minute and is a valid Shanghai stock-session endpoint.

The Helper performs exactly one local bar read for the request:

```python
ContextInfo.get_market_data_ex(
    ["open", "high", "low", "close", "volume"],
    [qmt_security],
    period="1m",
    start_time="",
    end_time=tick_minute,
    count=1,
    dividend_type="none",
    fill_data=False,
    subscribe=False,
)
```

OHLC values are emitted from QMT without price rounding. Prices are exact JSON
integers or floats in the inclusive range `0..1_000_000_000_000`; integers are
never converted through float. Bar `volume` is the raw QMT lot/hand value and is
emitted as an exact JSON integer in `0..2^53-1`, without the compatibility
`volume * 100` conversion used by `data.history`. The Helper may receive an
integer-valued QMT float volume inside that range and converts it to the exact
wire integer; the Relay accepts only the resulting JSON integer. Booleans,
strings, NaN, infinity, negative numbers, fractional or oversized volume, extra
fields, missing fields, wrong securities, and unclosed bars are rejected.

The Helper health payload exposes exact integer
`qmt_apis.market_probe_schema_version=2`. `admin.health` exposes
`actions.data.market_probe={"status":"ready","schema_version":2}` before the
first probe only when that exact Helper version is present,
`qmt_apis.market_probe=true`, and the live Helper context has callable
`get_full_tick`, `get_market_data_ex`, and one supported instrument-detail method.
Missing, malformed, or v1 capability facts remain degraded, so a client can avoid
sending an action unknown to an older Relay/Helper and keep its unknown-action
audit counter unchanged.

The QMT API parameters, field types, `subscribe=False` local-read behavior, and
unadjusted `dividend_type="none"` semantics follow the official
[ContextInfo.get_market_data_ex documentation](https://dict.thinktrader.net/innerApi/data_function.html)
and [QMT market data structures](https://dict.thinktrader.net/innerApi/data_structure.html).

## Formal evidence scope

Formal Phase 1 comparison is limited to a liquid, normally trading mainland
A-share that the operator has explicitly verified in the QMT UI immediately
before the run. Funds, ETFs, indices, bonds, convertible bonds, options, futures,
and other instruments must not be used as formal checklist evidence.

The Helper intentionally does not infer this classification from a six-digit
code or name prefix. QMT's official
[instrument-detail documentation](https://dict.thinktrader.net/dictionary/stock.html)
does not define a stable stock value for `ProductType`, and its documented stock
example omits that field while the published enumeration is for non-stock
products. Treating a missing/default value as “A-share” would therefore be a
guess. The operator's UI verification remains a deployment/sign-off condition
until QMT exposes an exact, versioned stock-type fact through this Helper.
