import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

# Validación anti-XSS: se rechazan caracteres que permitan inyectar markup/HTML
_DANGEROUS_CHARS = re.compile(r"[<>]")


class UserCreate(BaseModel):
    email: str
    password: str
    role: Literal["user", "admin"] = "user"

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if _DANGEROUS_CHARS.search(value) or not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+", value
        ):
            raise ValueError("email inválido o contiene caracteres peligrosos")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("la contraseña debe tener al menos 8 caracteres")
        if _DANGEROUS_CHARS.search(value):
            raise ValueError("la contraseña contiene caracteres no permitidos")
        return value


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"