# 12autotrade Run Workflow (New Machine)

## 1. Clone and setup

```bash
git clone https://github.com/LGuo2019/12autotrade.git
cd 12autotrade
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2. Configure `config.yaml`

Set/verify credentials:

- `twelvedata.api_key_env` (or direct `twelvedata.api_key`)
- `telegram.token_env` + `telegram.chat_id_env` (or direct values)
- `ig.api_key_env` + `ig.identifier_env` + `ig.password_env` + `ig.account_id`

Key scanner settings to keep:

- `scanner.ig_auto_add_watchlist_on_alert: true`
- `scanner.ig_watchlist_name: "My Watchlist"` (or your target watchlist)
- `mapping_file: 12_IG_mapping_universe.json`

## 3. Refresh IG EPIC mapping (recommended)

```bash
python3 scripts/find_ig_epics_for_symbols.py \
  --config config.yaml \
  --mapping 12_IG_mapping_universe.json \
  --epic-map rsi_universe_epic_to_twelvedata_symbol.json \
  --out data/ig_epic_candidates.json \
  --apply
```

## 4. Build IG watchlist runtime cache

```bash
python3 scripts/populate_ig_watchlist_cache.py --config config.yaml --watchlist-name "My Watchlist"
```

## 5. Test one scan run

```bash
python3 -m rsi_scanner.main --once --log-level INFO
```

## 6. Run bot in background

```bash
bash scripts/bot_control.sh start
bash scripts/bot_control.sh status
```

## 7. Stop bot

```bash
bash scripts/bot_control.sh stop
```

## Notes

- Scheduler runs every 2 hours at `HH:01 UTC` with catch-up for missed slots.
- US stocks are scanned only in NY time window (`07:30-18:00`, `America/New_York`).
- Telegram alerts are sent on configured RSI transitions.
- After alert, bot immediately tries to add the symbol's IG EPIC into the configured IG watchlist.
- If a symbol has no resolved IG EPIC, alert still works; only IG auto-add is skipped for that symbol.
