@echo off
setlocal enabledelayedexpansion

echo [NetSentinel] Stopping backend (port 8000) and frontend (port 5173)...

for %%P in (8000 5173) do (
    for /f "tokens=5" %%A in ('netstat -ano ^| findstr ":%%P" ^| findstr "LISTENING"') do (
        echo   killing PID %%A on port %%P
        taskkill /PID %%A /T /F >nul 2>&1
    )
)

rem Fallback: catch either window even if the port scan above missed it.
taskkill /FI "WINDOWTITLE eq NetSentinel-Backend*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq NetSentinel-Frontend*" /T /F >nul 2>&1

echo [NetSentinel] Stopped.
endlocal
