from sqlalchemy import String
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from config import settings

# Driver asyncpg: requiere URL postgresql+asyncpg:// en DATABASE_URL
engine = create_async_engine(settings.database_url, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    # Nunca guardar la contraseña, solo su hash bcrypt
    password_hash: Mapped[str] = mapped_column(String(255))
    # RBAC: dos roles soportados, "user" y "admin"
    role: Mapped[str] = mapped_column(String(20), default="user")