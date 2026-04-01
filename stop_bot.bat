@echo off
setlocal
cd /d "%~dp0"
set "SUPERVISOR_LOG=data\bot_supervisor.log"
if exist data\bot.pid (
  set /p BOTPID=<data\bot.pid
  echo %date% %time% stop_requested pid=%BOTPID%>>"%SUPERVISOR_LOG%"
  taskkill /PID %BOTPID% /F >nul 2>nul
  del data\bot.pid >nul 2>nul
)
echo stopped
endlocal
