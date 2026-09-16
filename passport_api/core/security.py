from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from config import settings

# Hashing bcrypt: passwords nunca se almacenan en texto plano
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # verify es resistente a timing attacks
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(sub: str) -> str:
    payload = {
        "sub": sub,
        # exp + iat en UTC: evita reutilización indefinida del token
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc)
        + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])