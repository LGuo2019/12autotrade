@echo off
setlocal
cd /d "%~dp0"
set "PYTHON=.venv\Scripts\python.exe"
set "PID_FILE=data\bot.pid"
set "LOG_FILE=data\bot.log"
set "ERR_FILE=data\bot.err.log"
set "SUPERVISOR_LOG=data\bot_supervisor.log"
set "STARTUP_STABILIZE_SECONDS=5"
if not exist "%PYTHON%" (
  echo Missing Windows venv. Run setup_windows.bat first.
  exit /b 1
)
mkdir data >nul 2>nul
if exist "%PID_FILE%" (
  set /p BOTPID=<"%PID_FILE%"
  if defined BOTPID (
    powershell -NoProfile -Command "if (Get-Process -Id %BOTPID% -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }" >nul 2>nul
    if not errorlevel 1 (
      echo already_running pid=%BOTPID%
      if exist "%LOG_FILE%" powershell -NoProfile -Command "Get-Content '%LOG_FILE%' -Tail 20"
      exit /b 0
    )
  )
  del "%PID_FILE%" >nul 2>nul
)
echo %date% %time% start_requested>>"%SUPERVISOR_LOG%"
powershell -NoProfile -Command "$p = Start-Process -FilePath '.\.venv\Scripts\python.exe' -ArgumentList @('-u','-m','rsi_scanner.main','--config','config.yaml','--log-level','INFO') -WorkingDirectory '.' -WindowStyle Hidden -RedirectStandardOutput 'data\bot.log' -RedirectStandardError 'data\bot.err.log' -PassThru; Set-Content -Path 'data\bot.pid' -Value $p.Id -Encoding ascii"
if errorlevel 1 (
  echo failed_to_start
  exit /b 1
)
set "WAIT_COUNT=0"
:wait_for_pid
if exist "%PID_FILE%" goto have_pid
set /a WAIT_COUNT+=1
if %WAIT_COUNT% GEQ 10 goto pid_timeout
timeout /t 1 >nul
goto wait_for_pid
:have_pid
set /p BOTPID=<"%PID_FILE%"
if not defined BOTPID goto pid_timeout
echo %date% %time% start_confirmed pid=%BOTPID%>>"%SUPERVISOR_LOG%"
timeout /t %STARTUP_STABILIZE_SECONDS% >nul
powershell -NoProfile -Command "if (Get-Process -Id %BOTPID% -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }" >nul 2>nul
if errorlevel 1 goto child_died_early
call status_bot.bat
endlocal
exit /b 0

:child_died_early
echo %date% %time% child_died_early pid=%BOTPID%>>"%SUPERVISOR_LOG%"
echo bot_exited_early pid=%BOTPID%
if exist "%LOG_FILE%" powershell -NoProfile -Command "Get-Content '%LOG_FILE%' -Tail 20"
if exist "%ERR_FILE%" powershell -NoProfile -Command "Get-Content '%ERR_FILE%' -Tail 20"
endlocal
exit /b 1

:pid_timeout
echo failed_to_start
if exist "%ERR_FILE%" powershell -NoProfile -Command "Get-Content '%ERR_FILE%' -Tail 20"
endlocal
exit /b 1
