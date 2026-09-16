from typing import AsyncGenerator

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import decode_access_token
from models.user import SessionLocal, User

bearer_scheme = HTTPBearer(auto_error=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session


async def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
) -> User:
    # Autenticación dual: JWT por header "Authorization: Bearer" O por cookie HttpOnly
    token = (
        credentials.credentials
        if credentials
        else request.cookies.get("access_token")
    )
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token requerido")
    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido")

    # El rol se lee de la BD (fuente de verdad), no del token
    user = await db.get(User, int(payload["sub"]))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario no encontrado")
    return user


async def admin_required(user: User = Depends(current_user)) -> User:
    # RBAC: bloquea cualquier acceso si el rol no es "admin"
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Se requiere rol admin")
    return user