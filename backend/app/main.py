from fastapi import APIRouter, FastAPI

health_router = APIRouter()


@health_router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def create_app() -> FastAPI:
    from app.api import auth, users

    app = FastAPI(title="NetSentinel AI", version="0.1.0")
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(users.router, prefix="/api/v1")
    return app


app = create_app()
