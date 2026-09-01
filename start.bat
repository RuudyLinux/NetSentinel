@echo off
setlocal

set "ROOT=%~dp0"

if not exist "%ROOT%var\netsentinel.db" (
    echo [NetSentinel] First run: migrating and seeding database...
    pushd "%ROOT%backend"
    call uv run alembic upgrade head
    if errorlevel 1 goto :fail
    call uv run python -m scripts.seed
    if errorlevel 1 goto :fail
    popd
)

echo [NetSentinel] Starting backend on http://127.0.0.1:8000 ...
start "NetSentinel-Backend" cmd /k "cd /d "%ROOT%backend" && uv run uvicorn app.main:app --reload"

echo [NetSentinel] Starting frontend on http://localhost:5173 ...
start "NetSentinel-Frontend" cmd /k "cd /d "%ROOT%frontend" && npm run dev"

echo [NetSentinel] Both started in separate windows. Run stop.bat to stop them.
goto :eof

:fail
popd
echo [NetSentinel] Setup failed - see errors above.
exit /b 1
