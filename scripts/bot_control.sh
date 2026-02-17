#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PID_FILE="data/bot.pid"
LOG_FILE="data/bot.log"

is_running() {
  if [[ -f "$PID_FILE" ]]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "${pid}" ]] && kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    # stale pid file
    rm -f "$PID_FILE"
  fi
  return 1
}

start_bot() {
  mkdir -p data
  if is_running; then
    echo "already_running pid=$(cat "$PID_FILE")"
    tail -n 20 "$LOG_FILE" 2>/dev/null || true
    return 0
  fi

  nohup python3 -u -m rsi_scanner.main \
    --config config.yaml \
    --log-level INFO > "$LOG_FILE" 2>&1 & echo $! > "$PID_FILE"

  sleep 1
  if is_running; then
    echo "started pid=$(cat "$PID_FILE")"
  else
    echo "failed_to_start"
    tail -n 50 "$LOG_FILE" 2>/dev/null || true
    exit 1
  fi
  tail -n 20 "$LOG_FILE" 2>/dev/null || true
}

stop_bot() {
  if [[ -f "$PID_FILE" ]]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE"
  fi
  pkill -f "python3 -u -m rsi_scanner.main" 2>/dev/null || true
  pkill -f "python3 -m rsi_scanner.main" 2>/dev/null || true
  if pgrep -f "python3 .*rsi_scanner.main" >/dev/null 2>&1; then
    echo "still_running"
  else
    echo "stopped"
  fi
}

status_bot() {
  if is_running; then
    echo "running pid=$(cat "$PID_FILE")"
  else
    echo "not_running"
  fi

  python3 - <<'PY'
import math
import sqlite3
import yaml
from datetime import datetime, timezone
from pathlib import Path

cfg_path = Path("config.yaml")
db_path = Path("rsi_scanner.db")
if not cfg_path.exists() or not db_path.exists():
    print("budget_status unknown")
    raise SystemExit(0)

cfg = yaml.safe_load(cfg_path.read_text()) or {}
limits = (cfg.get("limits") or {})
reserve = float(limits.get("reserve_pct", 0.05))
per_day = int(limits.get("per_day", 800))
effective_day = max(0, int(math.floor(per_day * (1.0 - reserve))))
day_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")

conn = sqlite3.connect(db_path)
try:
    row = conn.execute("SELECT credits_used FROM api_usage WHERE day=?", (day_key,)).fetchone()
    used = int(row[0]) if row else 0
except sqlite3.OperationalError:
    used = 0
finally:
    conn.close()

remaining = max(0, effective_day - used)
print(
    f"budget_status day={day_key} remaining={remaining} effective_day={effective_day} used={used}"
)
PY

  tail -n 20 "$LOG_FILE" 2>/dev/null || true
}

case "${1:-}" in
  start) start_bot ;;
  stop) stop_bot ;;
  status) status_bot ;;
  *)
    echo "usage: $0 {start|stop|status}"
    exit 1
    ;;
esac
