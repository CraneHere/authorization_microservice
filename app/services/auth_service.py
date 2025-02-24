from passlib.context import CryptContext

from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from app.config import get_auth_data
from app.services.users_service import UsersService

from fastapi import Request, HTTPException, status, Depends
# from fastapi.exceptions import TokenExpiredException, NoJwtException, NoUserIdException, ForbiddenException
from app.services.users_service import UsersService
import requests
from urllib.parse import urlencode
from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

YANDEX_TOKEN_URL = "https://oauth.yandex.ru/token"
YANDEX_USER_INFO_URL = "https://login.yandex.ru/info"

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=30)
    to_encode.update({"exp": expire})
    auth_data = get_auth_data()
    encode_jwt = jwt.encode(to_encode, auth_data['secret_key'], algorithm=auth_data['algorithm'])
    return encode_jwt

async def authenticate_user_by_username(username: str, password: str):
    user = await UsersService.get_user_by_username(username=username)
    if not user or verify_password(plain_password=password, hashed_password=user.password) is False:
        return None
    return user


def get_token(request: Request):
    token = request.cookies.get('users_access_token')
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Token not found')
    return token


async def get_current_user(token: str = Depends(get_token)):
    try:
        auth_data = get_auth_data()
        payload = jwt.decode(token, auth_data['secret_key'], algorithms=[auth_data['algorithm']])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Токен не валидный!')

    expire = payload.get('exp')
    expire_time = datetime.fromtimestamp(int(expire), tz=timezone.utc)
    if (not expire) or (expire_time < datetime.now(timezone.utc)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Токен истек')

    user_id = payload.get('sub')
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Не найден ID пользователя')

    user = await UsersService.get_user_by_id(int(user_id))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User not found')

    return user

async def get_yandex_token(code: str) -> str:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": settings.YANDEX_CLIENT_ID,
        "client_secret": settings.YANDEX_CLIENT_SECRET,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(YANDEX_TOKEN_URL, data=urlencode(data), headers=headers)
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Ошибка при получении токена")

    return response.json().get("access_token")

async def get_yandex_user_info(access_token: str) -> dict:
    headers = {"Authorization": f"OAuth {access_token}"}
    response = requests.get(YANDEX_USER_INFO_URL, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Ошибка при получении данных пользователя")

    return response.json()

async def authenticate_yandex_user(code: str, users_service) -> dict:
    access_token = await get_yandex_token(code)
    user_info = await get_yandex_user_info(access_token)

    yandex_id = user_info.get("id")
    email = user_info.get("default_email", f"{yandex_id}@yandex.ru")
    first_name = user_info.get("first_name", "")
    last_name = user_info.get("last_name", "")

    user = await users_service.get_user_by_yandex_id(yandex_id)
    if not user:
        user = await users_service.create_user(
            email=email,
            yandex_id=yandex_id,
            first_name=first_name,
            last_name=last_name,
        )

    token = users_service.create_jwt_token(user)

    return {"access_token": token, "token_type": "bearer"}