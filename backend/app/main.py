from fastapi import APIRouter, FastAPI

health_router = APIRouter()


@health_router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def create_app() -> FastAPI:
    app = FastAPI(title="NetSentinel AI", version="0.1.0")
    app.include_router(health_router, prefix="/api/v1")
    return app


app = create_app()
