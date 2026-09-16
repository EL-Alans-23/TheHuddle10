from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import admin_required, get_db
from models.user import User
from schemas.user_schema import UserResponse

router = APIRouter()


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    admin: User = Depends(admin_required),  # RBAC: solo rol "admin"
    db: AsyncSession = Depends(get_db),
) -> list[User]:
    result = await db.scalars(select(User).order_by(User.id))
    return list(result.all())