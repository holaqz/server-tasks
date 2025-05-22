from fastapi import APIRouter, Depends, HTTPException, status, Form, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from typing import List, Dict
from controllers.auth_controller import AuthController
from schemas.user_schemas import UserCreateRequest, UserLoginRequest, UserDTO, TokenDTO
from core.security import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])
auth_controller = AuthController()

@router.post("/register", response_model=UserDTO, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreateRequest):
    user = auth_controller.register(user_data)
    return user

@router.post("/login", response_model=TokenDTO)
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    login_data = UserLoginRequest(username=form_data.username, password=form_data.password)
    tokens = auth_controller.login(login_data)
    
    response.set_cookie(
        key="access_token",
        value=f"Bearer {tokens.access_token}",
        httponly=True,
        samesite="strict",
        max_age=1800
    )
    
    response.set_cookie(
        key="refresh_token",
        value=f"Bearer {tokens.refresh_token}",
        httponly=True,
        samesite="strict",
        max_age=7 * 24 * 3600
    )
    
    return tokens

@router.get("/me", response_model=UserDTO)
async def get_current_user_info(request: Request):
    current_user = await get_current_user(request)
    return auth_controller.get_user_by_id(current_user["id"])

@router.post("/logout")
async def logout(request: Request, response: Response):
    current_user = await get_current_user(request)
    auth_controller.logout(current_user["id"], current_user.get("token", ""))
    
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "Успешный выход из системы"}

@router.get("/tokens")
async def get_active_tokens(request: Request):
    current_user = await get_current_user(request)
    return auth_controller.get_active_tokens(current_user["id"])

@router.post("/tokens/revoke-all")
async def revoke_all_tokens(request: Request, response: Response):
    current_user = await get_current_user(request)
    result = auth_controller.revoke_all_tokens(current_user["id"])
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    response.headers["Clear-Site-Data"] = '"cookies", "storage"'
    return {
        **result,
        "message": "Все токены были отозваны и выполнен выход из системы"
    }

@router.post("/refresh")
async def refresh_token(request: Request, response: Response):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token or not refresh_token.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token не предоставлен"
        )
    
    refresh_token = refresh_token[7:]
    tokens = auth_controller.refresh_token(refresh_token)
    
    response.set_cookie(
        key="access_token",
        value=f"Bearer {tokens.access_token}",
        httponly=True,
        samesite="strict",
        max_age=1800
    )
    response.set_cookie(
        key="refresh_token",
        value=f"Bearer {tokens.refresh_token}",
        httponly=True,
        samesite="strict",
        max_age=7 * 24 * 3600
    )
    
    return tokens

@router.post("/change-password")
async def change_password(
    request: Request,
    response: Response,
    current_password: str,
    new_password: str
):
    current_user = await get_current_user(request)
    auth_controller.change_password(current_user["id"], current_password, new_password)
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "Пароль успешно изменен"} 