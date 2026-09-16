from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from pydantic import BaseModel
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from api.routes import admin, auth
from config import settings
from core.rate_limiter import limiter
from models.user import Base, engine


class CsrfSettings(BaseModel):
    secret_key: str = settings.csrf_secret_key or settings.jwt_secret
    cookie_secure: bool = settings.cookie_secure
    cookie_samesite: str = settings.cookie_samesite
    cookie_key: str = "csrf_access_token"
    header_name: str = "X-CSRFToken"
    token_location: str = "header"
    httponly: bool = False  # el cliente DEBE leer el token para el doble envío


@CsrfProtect.load_config
def get_csrf_config() -> CsrfSettings:
    return CsrfSettings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Crea las tablas en PostgreSQL al arrancar (producción: usar Alembic)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(title="PassPort Inc. API", lifespan=lifespan)

# SlowAPI: límites estado global + handler 429
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(CsrfProtectError)
async def csrf_exception_handler(
    request: Request, exc: CsrfProtectError
) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])