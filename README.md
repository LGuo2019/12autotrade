# rsi_scanner

TwelveData RSI scanner that monitors a watchlist on 2-hour timeframe and sends Telegram alerts on RSI crossings, while honoring free-plan API limits with a safety reserve.

## Requirements

- Python 3.10+
- `pip install -r requirements.txt`

## Config

Edit `config.yaml` and `symbols/markets.txt`.

Env vars:
- `TWELVEDATA_API_KEY`
- `TELEGRAM_TOKEN`
- `TELEGRAM_CHAT_ID`

If `mapping_file` is set in `config.yaml`, scanner symbols come from mapping keys
(TwelveData symbols) and alert `Symbol` uses mapping values (IG market names).

## Run Modes

Dry run (no HTTP calls):

```bash
python -m rsi_scanner.main --once --dry-run
```

Dry run with real Telegram messages (market data still dry-run):

```bash
python -m rsi_scanner.main --once --dry-run --send-telegram
```

Simulation (no HTTP calls, replay CSV):

```bash
python -m rsi_scanner.main --once --sim-csv data/rsi_sim.csv
```

CSV format:

```text
symbol,datetime,rsi
EUR/USD,2026-02-14 16:00:00,68.21
EUR/USD,2026-02-14 18:00:00,72.40
```

Simulation (no HTTP calls, replay JSON fixtures):

```bash
python -m rsi_scanner.main --once --sim-json tests/fixtures
```

Simulation with real Telegram messages:

```bash
python -m rsi_scanner.main --once --sim-json tests/fixtures --send-telegram
```

SIM mode defaults to in-memory state (`:memory:`), so repeated runs do not look stuck on cached candles.

JSON format (per-file in a directory):

```json
{
  "values": [
    {"datetime": "2026-02-14 16:00:00", "rsi": "68.21"},
    {"datetime": "2026-02-14 18:00:00", "rsi": "72.40"}
  ],
  "status": "ok"
}
```

Or a single JSON file mapping symbols to `values` arrays:

```json
{
  "EUR/USD": [
    {"datetime": "2026-02-14 16:00:00", "rsi": "68.21"},
    {"datetime": "2026-02-14 18:00:00", "rsi": "72.40"}
  ]
}
```

Live mode (scheduler every 2h at HH:01 UTC):

```bash
python -m rsi_scanner.main
```

If you run without `--once`, the process waits for the next `HH:01 UTC` trigger and now logs that wait time explicitly.

## Notes

- All TwelveData calls flow through a global `CreditBudget` with a 5% safety reserve.
- Scheduler runs at HH:01 UTC to allow the latest 2h candle to finalize.
- Alerts trigger only on `NEUTRAL -> OVERBOUGHT` or `NEUTRAL -> OVERSOLD` transitions.
- Optional: set `scanner.alert_on_first_seen_extreme: true` to alert once when a symbol is first observed already in `OVERBOUGHT`/`OVERSOLD`.
- Optional US stocks time window:
  - `scanner.us_stocks_restrict_hours: true`
  - `scanner.us_stocks_tz: America/New_York`
  - `scanner.us_stocks_start: "07:30"` and `scanner.us_stocks_end: "18:00"` (2h before open to 2h after close)
  - `scanner.us_stock_symbols_file: data/us_stock_symbols.txt`
- Optional IG watchlist auto-add on alerts:
  - `scanner.ig_auto_add_watchlist_on_alert: true`
  - `scanner.ig_watchlist_name: "My Watchlist"`
  - `scanner.ig_watchlist_cache_file: "data/ig_watchlist_cache.json"` (cache watchlist id/epics and symbol->epic resolution locally)
  - `scanner.ig_symbol_epic_map_file: rsi_universe_epic_to_twelvedata_symbol.json`
  - Requires `ig` credentials in `config.yaml` (or env vars via `*_env` keys).
  - Runtime is cache-only for watchlist metadata/symbol matching. Build/refresh cache with:

```bash
python scripts/populate_ig_watchlist_cache.py --config config.yaml
```
- Cooldown is 3600 seconds per symbol.
- SQLite state is stored in `rsi_scanner.db` in the working directory.

## Logging

Plain logs:

```bash
python -m rsi_scanner.main --once --log-level INFO
```

Use persistent DB state explicitly:

```bash
python -m rsi_scanner.main --once --db-path rsi_scanner.db
```

Verbose per-symbol logs:

```bash
python -m rsi_scanner.main --once --dry-run --log-level INFO
```

JSON logs:

```bash
python -m rsi_scanner.main --once --json-logs
```

## List Markets

Export supported markets from TwelveData into CSV:

```bash
python -m rsi_scanner.list_markets --output markets.csv
```

Export as TSV:

```bash
python -m rsi_scanner.list_markets --format tsv --output markets.tsv
```

Limit to exchanges only (lowest credit usage):

```bash
python -m rsi_scanner.list_markets --only exchanges --output exchanges.csv
```

Choose specific datasets:

```bash
python -m rsi_scanner.list_markets --only exchanges,stocks,forex_pairs,cryptocurrencies
```

## Map IG Watchlist Names

Map IG watchlist names (for example 133 rows from \"My watchlist\" and \"24 Hours Shares\") to TwelveData symbols:

```bash
python -m rsi_scanner.map_ig_watchlist \
  --ig-file ig_watchlist.csv \
  --markets markets.csv \
  --output ig_to_twelvedata.csv
```

Supported IG input formats:
- `.txt`: one market name per line
- `.csv`: auto-detects one of `name`, `market`, `market_name`, `epic`, `instrument` (or first column)

Tune matching strictness:

```bash
python -m rsi_scanner.map_ig_watchlist --ig-file ig_watchlist.csv --min-score 0.80
```

## One-Off IG API Mapping Script

Use a separate script that calls IG Labs REST directly, fetches:
- `My watchlist`
- `24 Hours Shares`

Then maps each IG instrument to TwelveData and writes:
- JSON mapping: TwelveData symbol -> IG market name
- Detailed CSV with scores and metadata

Run:

```bash
python scripts/ig_watchlists_to_twelvedata_map.py \
  --config config.yaml \
  --mapping-out ig_to_twelvedata_mapping.json
```

Required config/env fields:

```yaml
ig:
  api_key_env: IG_API_KEY
  identifier_env: IG_IDENTIFIER
  password_env: IG_PASSWORD

twelvedata:
  api_key_env: TWELVEDATA_API_KEY
```

You can also place direct secrets under `ig.api_key`, `ig.identifier`, `ig.password`, and `twelvedata.api_key`.
