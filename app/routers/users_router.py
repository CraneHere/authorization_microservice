from fastapi import APIRouter
from app.services.users_service import UsersService
from app.schemas.User_schema import User, RegisterUser
from typing import Optional, List

router = APIRouter(prefix='/users', tags=['Работа с пользователями'])

@router.get("/", summary="Получить всех пользователей")
async def get_all_users() -> Optional[List[User]]:
    result = await UsersService.get_all_users()
    return result

@router.get("/{id}", summary="Получиить пользователя по id")
async def get_user_by_id(id: int) -> Optional[User] | str:
    result = await UsersService.get_user_by_id(id)
    if result is None:
        return f'Пользователь с id {id} не найден'
    return result

@router.post("/register", summary="Добавить пользователя")
async def add_user(user: RegisterUser):
    result = await UsersService.add_user(**user.model_dump())
    return result