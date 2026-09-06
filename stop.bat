@echo off
setlocal enabledelayedexpansion

set "MODE=%~1"

if /i "%MODE%"=="docker" goto :docker
if not "%MODE%"=="" (
    echo [NetSentinel] Unknown mode %MODE% - use "stop.bat" or "stop.bat docker".
    exit /b 1
)

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
goto :eof

:docker
where docker >nul 2>&1
if errorlevel 1 (
    echo [NetSentinel] Docker was not found on PATH - nothing to stop.
    goto :docker_frontend
)

echo [NetSentinel] Stopping the containerized stack (Postgres, Redis, MinIO, backend)...
pushd "%~dp0"
call docker compose down
popd

:docker_frontend
rem The frontend runs directly via npm even in docker mode (see start.bat) - stop it too.
taskkill /FI "WINDOWTITLE eq NetSentinel-Frontend*" /T /F >nul 2>&1

echo [NetSentinel] Stopped.
endlocal
