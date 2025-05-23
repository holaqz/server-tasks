from fastapi import APIRouter, Depends, HTTPException, status, Form, Response, Request
from typing import List, Dict
from controllers.auth_controller import AuthController
from schemas.user_schemas import UserCreateRequest, UserLoginRequest, UserDTO, TokenDTO, LoginResponseDTO
from core.security import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])
auth_controller = AuthController()

@router.post("/register", response_model=UserDTO)
async def register(user_data: UserCreateRequest):
    try:
        return auth_controller.register(user_data)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Произошла ошибка при регистрации: {str(e)}"
        )

@router.post("/login", response_model=LoginResponseDTO)
async def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    login_data = UserLoginRequest(username=username, password=password)
    tokens = auth_controller.login(login_data)
    
    response.set_cookie(
        key="access_token",
        value=tokens.access_token,
        httponly=True,
        samesite="strict"
    )
    
    response.set_cookie(
        key="refresh_token",
        value=tokens.refresh_token,
        httponly=True,
        samesite="strict"
    )
    
    return LoginResponseDTO(access_token=tokens.access_token)

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
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token не предоставлен"
        )
    
    tokens = auth_controller.refresh_token(refresh_token)
    
    response.set_cookie(
        key="access_token",
        value=tokens.access_token,
        httponly=True,
        samesite="strict"
    )
    response.set_cookie(
        key="refresh_token",
        value=tokens.refresh_token,
        httponly=True,
        samesite="strict"
    )
    
    return LoginResponseDTO(access_token=tokens.access_token)

@router.post("/change-password")
async def change_password(
    request: Request,
    response: Response,
    current_password: str = Form(...),
    new_password: str = Form(...)
):
    current_user = await get_current_user(request)
    auth_controller.change_password(current_user["id"], current_password, new_password)
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "Пароль успешно изменен"} 