@echo off
setlocal

set "ROOT=%~dp0"
set "MODE=%~1"

if /i "%MODE%"=="docker" goto :docker
if "%MODE%"=="" goto :local
echo [NetSentinel] Unknown mode %MODE% - use "start.bat" or "start.bat docker".
exit /b 1

:local
rem ---------------- Local dev path (default): SQLite + uvicorn + npm dev ----------------
rem Always migrate, not just on first run: an existing dev database created
rem before a new migration was added (e.g. password_reset_tokens) must still
rem pick it up. Both alembic upgrade and the seed script are idempotent, so
rem running them every start is safe and self-healing.
echo [NetSentinel] Applying database migrations...
pushd "%ROOT%backend"
call uv run alembic upgrade head
if errorlevel 1 goto :fail
call uv run python -m scripts.seed
if errorlevel 1 goto :fail
popd

echo [NetSentinel] Starting backend on http://127.0.0.1:8000 ...
start "NetSentinel-Backend" cmd /k "cd /d "%ROOT%backend" && uv run uvicorn app.main:app --reload"

echo [NetSentinel] Starting frontend on http://localhost:5173 ...
start "NetSentinel-Frontend" cmd /k "cd /d "%ROOT%frontend" && npm run dev"

echo [NetSentinel] Both started in separate windows. Run stop.bat to stop them.
goto :eof

:docker
rem ---------------- Containerized path: Postgres + MinIO + backend via docker-compose ----------------
rem Frontend has no Dockerfile yet (see docker-compose.yml), so it still runs directly
rem via npm - its dev-server proxy works the same whether the backend it's proxying to
rem is local or containerized, since both land on http://127.0.0.1:8000.
where docker >nul 2>&1
if errorlevel 1 (
    echo [NetSentinel] Docker was not found on PATH. Install Docker Desktop first.
    exit /b 1
)

echo [NetSentinel] Building and starting the containerized stack (Postgres, Redis, MinIO, backend)...
pushd "%ROOT%"
call docker compose up -d --build
if errorlevel 1 goto :fail
popd

echo [NetSentinel] Starting frontend on http://localhost:5173 ...
start "NetSentinel-Frontend" cmd /k "cd /d "%ROOT%frontend" && npm run dev"

echo [NetSentinel] Backend:        http://127.0.0.1:8000
echo [NetSentinel] MinIO console:  http://127.0.0.1:9001  (netsentinel / netsentinel-dev-only)
echo [NetSentinel] Postgres:       localhost:5432          (netsentinel / netsentinel-dev-only)
echo [NetSentinel] Run "stop.bat docker" to stop the containerized stack.
goto :eof

:fail
popd
echo [NetSentinel] Setup failed - see errors above.
exit /b 1
