from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse, RedirectResponse
from typing import Optional
from app.schemas.User_schema import User, RegisterUser, AuthUser
from app.routers.users_router import router as users_router

app = FastAPI()

app.include_router(users_router)

@app.get("/")
def home_page():
    print('123')
    return {"message": "bro service"}