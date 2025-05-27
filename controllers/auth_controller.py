from fastapi import HTTPException, status, Depends
from typing import List, Dict
from datetime import datetime, date
from sqlalchemy.orm import Session
from core.security import (
    create_jwt_token, verify_password, get_password_hash, 
    decode_jwt_token, revoke_token, revoke_all_user_tokens, is_token_revoked, clear_user_revoked_tokens
)
from core.config import get_settings, User, Role, UsersAndRoles
from schemas.user_schemas import UserCreateRequest, UserLoginRequest, UserDTO, TokenDTO

settings = get_settings()

class TokenInfo:
    def __init__(self, token_id: str, created_at: datetime, expires_at: datetime):
        self.token_id = token_id
        self.created_at = created_at
        self.expires_at = expires_at

    def to_dict(self):
        return {
            "token_id": self.token_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "is_expired": datetime.utcnow() > self.expires_at
        }

class AuthController:
    def __init__(self):
        self._active_tokens: Dict[int, List[Dict]] = {}
        self._used_refresh_tokens: set = set()
        
    def register(self, user_data: UserCreateRequest, db: Session) -> UserDTO:
        # Проверяем существование пользователя
        if db.query(User).filter(User.username == user_data.username).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Пользователь с таким именем уже зарегистрирован"
            )

        if user_data.password != user_data.password_confirm:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Пароли не совпадают"
            )

        # Создаем нового пользователя
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=get_password_hash(user_data.password),
            birth_date=user_data.birth_date,
            is_active=True
        )
        db.add(new_user)
        db.flush()  # Получаем id пользователя

        # Находим роль "user"
        user_role = db.query(Role).filter(Role.code == "user").first()
        if user_role:
            # Создаем связь пользователь-роль
            user_role_link = UsersAndRoles(
                user_id=new_user.id,
                role_id=user_role.id
            )
            db.add(user_role_link)

        db.commit()
        db.refresh(new_user)
        
        return UserDTO(
            id=new_user.id,
            username=new_user.username,
            email=new_user.email,
            birth_date=new_user.birth_date,
            roles=[role.code for role in new_user.roles],
            is_active=new_user.is_active
        )

    def login(self, login_data: UserLoginRequest, db: Session) -> TokenDTO:
        user = db.query(User).filter(User.username == login_data.username).first()
        if not user or not verify_password(login_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверное имя пользователя или пароль"
            )
            
        clear_user_revoked_tokens(user.id)
            
        active_tokens = self.get_active_tokens(user.id)
        if len(active_tokens) >= settings.MAX_ACTIVE_TOKENS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Достигнуто максимальное количество активных сессий ({settings.MAX_ACTIVE_TOKENS}). Пожалуйста, выйдите из других сессий"
            )
            
        token_data = {
            "sub": user.username,
            "id": user.id,
            "email": user.email
        }
        
        access_token = create_jwt_token(
            data=token_data,
            is_refresh=False
        )
        
        refresh_token = create_jwt_token(
            data=token_data,
            is_refresh=True
        )
        
        token_pair = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "created_at": datetime.utcnow().isoformat()
        }
        
        if user.id not in self._active_tokens:
            self._active_tokens[user.id] = []
        self._active_tokens[user.id].append(token_pair)
        
        return TokenDTO(access_token=access_token, refresh_token=refresh_token)

    def get_user_by_id(self, user_id: int, db: Session) -> UserDTO:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
            
        return UserDTO(
            id=user.id,
            username=user.username,
            email=user.email,
            birth_date=user.birth_date if user.birth_date else date(1990, 1, 1),
            roles=[role.code for role in user.roles],
            is_active=user.is_active
        )

    def logout(self, user_id: int, token: str):
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Не предоставлен активный токен"
            )
            
        revoke_token(token)
        
        if user_id in self._active_tokens:
            self._active_tokens[user_id] = [
                pair for pair in self._active_tokens[user_id] 
                if pair["access_token"] != token
            ]

    def get_active_tokens(self, user_id: int) -> List[Dict[str, str]]:
        tokens = []
        for token_pair in self._active_tokens.get(user_id, []):
            access_token = token_pair["access_token"]
            payload = decode_jwt_token(access_token)
            if (payload and 
                datetime.fromtimestamp(payload["exp"]) > datetime.utcnow() and
                not is_token_revoked(access_token, user_id)):
                tokens.append(token_pair)
        
        self._active_tokens[user_id] = tokens
        return tokens

    def revoke_all_tokens(self, user_id: int):
        revoke_all_user_tokens(user_id)
        
        if user_id in self._active_tokens:
            self._active_tokens[user_id] = []
            
        user_refresh_tokens = [
            token for token in self._used_refresh_tokens 
            if decode_jwt_token(token) and decode_jwt_token(token).get("id") == user_id
        ]
        for token in user_refresh_tokens:
            self._used_refresh_tokens.remove(token)
            
        return {
            "status": "success",
            "detail": "Все токены были отозваны и данные сессии очищены"
        }

    def refresh_token(self, refresh_token: str, db: Session) -> TokenDTO:
        payload = decode_jwt_token(refresh_token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Недействительный refresh token"
            )
            
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Неверный тип токена. Ожидается refresh token"
            )
            
        if refresh_token in self._used_refresh_tokens:
            user_id = payload.get("id")
            if user_id:
                revoke_all_user_tokens(user_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token уже был использован. Возможна попытка повторного использования токена"
            )
            
        user = db.query(User).filter(User.id == payload.get("id")).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Пользователь не найден"
            )
            
        token_data = {
            "sub": user.username,
            "id": user.id,
            "email": user.email
        }
        
        new_access_token = create_jwt_token(
            data=token_data,
            is_refresh=False
        )
        
        new_refresh_token = create_jwt_token(
            data=token_data,
            is_refresh=True
        )
        
        self._used_refresh_tokens.add(refresh_token)
        
        return TokenDTO(access_token=new_access_token, refresh_token=new_refresh_token)

    def change_password(self, user_id: int, current_password: str, new_password: str, db: Session):
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Пользователь не найден"
            )
            
        if not verify_password(current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Неверный текущий пароль"
            )
            
        user.hashed_password = get_password_hash(new_password)
        db.commit()
        
        # Отзываем все токены пользователя после смены пароля
        self.revoke_all_tokens(user_id)
        
        return {"status": "success", "detail": "Пароль успешно изменен"} 