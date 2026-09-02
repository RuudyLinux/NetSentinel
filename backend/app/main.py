from fastapi import APIRouter, FastAPI

health_router = APIRouter()


@health_router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def create_app() -> FastAPI:
    from app.api import (
        ai,
        audit_logs,
        audits,
        auth,
        configurations,
        dashboard,
        devices,
        findings,
        frameworks,
        reports,
        users,
    )
    from app.config import settings
    from app.services.compliance.rules import load_all_packs
    from app.services.remediation.packs import load_remediations

    packs = load_all_packs(settings.rules_dir)
    remediations = load_remediations(settings.mappings_dir)
    referenced = {rule.remediation_id for pack in packs for rule in pack.rules}
    missing = referenced - remediations.keys()
    if missing:
        raise RuntimeError(f"rules reference missing remediations: {sorted(missing)}")

    app = FastAPI(title="NetSentinel AI", version="0.1.0")
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(users.router, prefix="/api/v1")
    app.include_router(dashboard.router, prefix="/api/v1")
    app.include_router(devices.router, prefix="/api/v1")
    app.include_router(configurations.router, prefix="/api/v1")
    app.include_router(audits.router, prefix="/api/v1")
    app.include_router(findings.router, prefix="/api/v1")
    app.include_router(frameworks.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(audit_logs.router, prefix="/api/v1")
    app.include_router(ai.router, prefix="/api/v1")
    return app


app = create_app()
