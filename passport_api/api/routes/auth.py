from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_csrf_protect import CsrfProtect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import current_user, get_db
from config import settings
from core.rate_limiter import limiter
from core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from models.user import User
from schemas.user_schema import Token, UserCreate, UserResponse

router = APIRouter()


async def _authenticate(db: AsyncSession, email: str, password: str) -> User | None:
    # Mensaje único de error para no revelar si el email existe
    user = await db.scalar(
        select(User).where(User.email == email.strip().lower())
    )
    if user and verify_password(password, user.password_hash):
        return user
    return None


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register(
    request: Request,
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
) -> User:
    # En producción inmutar el rol a "user": crear admins debe hacerse a mano en BD
    existing = await db.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "El email ya está registrado")
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),  # hashing bcrypt
        role=payload.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/login/jwt", response_model=Token)
@limiter.limit("5/minute")
async def login_jwt(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
) -> Token:
    # Retorna el JWT en el body; el cliente lo envía en "Authorization: Bearer"
    user = await _authenticate(db, form.username, form.password)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciales inválidas")
    return Token(access_token=create_access_token(str(user.id)))


@router.post("/login/cookie")
@limiter.limit("5/minute")
async def login_cookie(
    request: Request,
    response: Response,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
    csrf_protect: CsrfProtect = Depends(),
):
    user = await _authenticate(db, form.username, form.password)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credenciales inválidas")

    # Sesión en cookie JWT con HttpOnly + Secure (no legible por JS -> anti-XSS)
    response.set_cookie(
        "access_token",
        create_access_token(str(user.id)),
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )

    # Doble envío CSRF: se guarda el signed_token en cookie y el token
    # sin firmar en el body para que el cliente lo reenvíe via X-CSRFToken
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    csrf_protect.set_csrf_cookie(signed_token, response)
    return {"detail": "Sesión iniciada", "csrf_token": csrf_token}


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    user: User = Depends(current_user),
    csrf_protect: CsrfProtect = Depends(),
):
    # Mutación de sesión basada en cookie -> requiere token CSRF válido
    await csrf_protect.validate_csrf(request)
    response.delete_cookie("access_token", path="/")
    csrf_protect.unset_csrf_cookie(response)
    return {"detail": "Sesión cerrada"}