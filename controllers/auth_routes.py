from fastapi import APIRouter, Depends, HTTPException, status, Form, Response, Request
from typing import List, Dict
from sqlalchemy.orm import Session
from schemas.user_schemas import UserCreateRequest, UserLoginRequest, UserDTO, TokenDTO, LoginResponseDTO
from core.security import get_current_user, require_permission
from core.config import User, ChangeLogs
from core.database import get_db
from .auth_controller import AuthController
from schemas.log_schemas import ChangeLogResponse
from schemas.exception_schemas import UserNotFoundError
from core.log import get_user_logs

router = APIRouter(prefix="/auth", tags=["auth"])
auth_controller = AuthController()

@router.post("/register", response_model=UserDTO)
async def register(user_data: UserCreateRequest, db: Session = Depends(get_db)):
    try:
        return auth_controller.register(user_data, db)
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
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    login_data = UserLoginRequest(username=username, password=password)
    tokens = auth_controller.login(login_data, db)
    
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
async def get_current_user_info(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return auth_controller.get_user_by_id(current_user.id, db)

@router.post("/logout")
async def logout(request: Request, response: Response, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    auth_controller.logout(current_user.id, getattr(current_user, 'token', ''), db)
    
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "Успешный выход из системы"}

@router.get("/tokens")
async def get_active_tokens(request: Request, current_user: User = Depends(get_current_user)):
    return auth_controller.get_active_tokens(current_user.id)

@router.post("/tokens/revoke-all")
async def revoke_all_tokens(
    request: Request, 
    response: Response,
    current_user: User = Depends(get_current_user)
):
    result = auth_controller.revoke_all_tokens(current_user.id)
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    response.headers["Clear-Site-Data"] = '"cookies", "storage"'
    return {
        **result,
        "message": "Все токены были отозваны и выполнен выход из системы"
    }

@router.post("/refresh")
async def refresh_token(request: Request, response: Response, db: Session = Depends(get_db)):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refresh token не предоставлен"
        )
    
    tokens = auth_controller.refresh_token(refresh_token, db)
    
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
    new_password: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    auth_controller.change_password(current_user.id, current_password, new_password, db)
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "Пароль успешно изменен"} 

@router.get("/{user_id}/logs", response_model=List[ChangeLogResponse],
           dependencies=[Depends(require_permission("get_story_user")), Depends(get_current_user)])
def get_user_logs(
    user_id: int,
    db: Session = Depends(get_db)
):
    try:
        logs = db.query(ChangeLogs).filter(
            ChangeLogs.entity_type == "User",
            ChangeLogs.entity_id == user_id
        ).order_by(ChangeLogs.created_at.desc()).all()

        if not logs:
            raise HTTPException(
                status_code=404,
                detail="Логи для данного пользователя не найдены"
            )

        return [ChangeLogResponse.from_orm(log) for log in logs]

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при получении логов пользователя: {str(e)}"
        )