@echo off
setlocal
cd /d "%~dp0"
set "PYTHON=.venv\Scripts\python.exe"
set "PID_FILE=data\bot.pid"
set "STATE_FILE=data\bot.state.json"
set "LOG_FILE=data\bot.log"
set "ERR_FILE=data\bot.err.log"
set "SUPERVISOR_LOG=data\bot_supervisor.log"
if exist "%STATE_FILE%" (
  "%PYTHON%" -c "import json,time; from pathlib import Path; p=Path(r'%STATE_FILE%'); data=json.loads(p.read_text(encoding='utf-8')); age=max(0,int(time.time())-int(data.get('updated_at',0))); state=data.get('state','unknown'); pid=data.get('pid',''); next_run=data.get('next_run_utc'); wait=data.get('wait_seconds'); parts=[state]; parts.append(f'pid={pid}' if pid else ''); parts.append(f'age={age}s'); parts.append(f'next_run_utc={next_run}' if next_run else ''); parts.append(f'wait_seconds={wait}' if wait is not None else ''); print('state_status ' + ' '.join([x for x in parts if x])); raise SystemExit(0 if age <= 180 else 1)"
  if errorlevel 1 (
    echo not_running
    if exist "%PID_FILE%" del "%PID_FILE%" >nul 2>nul
  ) else (
    echo running
  )
) else (
  echo not_running
)
if exist "%PYTHON%" "%PYTHON%" -c "import math,sqlite3,yaml; from datetime import datetime, timezone; from pathlib import Path; cfg=Path('config.yaml'); db=Path('rsi_scanner.db'); raw=(yaml.safe_load(cfg.read_text()) if cfg.exists() else {}) or {}; limits=raw.get('limits') or {}; reserve=float(limits.get('reserve_pct',0.05)); per_day=int(limits.get('per_day',800)); effective=max(0,int(math.floor(per_day*(1.0-reserve)))); day_key=datetime.now(timezone.utc).strftime('%%Y-%%m-%%d'); used=0; conn=sqlite3.connect(db) if db.exists() else None; row=conn.execute('SELECT credits_used FROM api_usage WHERE day=?',(day_key,)).fetchone() if conn else None; used=int(row[0]) if row else 0; conn.close() if conn else None; print(f'budget_status day={day_key} remaining={max(0,effective-used)} effective_day={effective} used={used}')"
if exist "%SUPERVISOR_LOG%" powershell -NoProfile -Command "Write-Host '--- supervisor ---'; Get-Content '%SUPERVISOR_LOG%' -Tail 10"
if exist "%LOG_FILE%" powershell -NoProfile -Command "$line = Get-Content '%LOG_FILE%' -Tail 1; if ($line) { Write-Host ('last_log ' + $line) }"
if exist "%LOG_FILE%" powershell -NoProfile -Command "Get-Content '%LOG_FILE%' -Tail 20"
if exist "%ERR_FILE%" powershell -NoProfile -Command "Write-Host '--- stderr ---'; Get-Content '%ERR_FILE%' -Tail 20"
endlocal
