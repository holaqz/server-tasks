from fastapi import HTTPException, status
from typing import List, Dict
import time
from datetime import datetime
from core.security import (
    create_jwt_token, verify_password, get_password_hash, 
    decode_jwt_token, revoke_token, revoke_all_user_tokens, is_token_revoked, clear_user_revoked_tokens
)
from core.config import get_settings
from schemas.user_schemas import UserCreateRequest, UserLoginRequest, UserDTO, TokenDTO

settings = get_settings()

class TokenInfo:
    def __init__(self, token_id: str, created_at: datetime, expires_at: datetime, device_info: str = "Unknown"):
        self.token_id = token_id
        self.created_at = created_at
        self.expires_at = expires_at
        self.device_info = device_info

    def to_dict(self):
        return {
            "token_id": self.token_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "device_info": self.device_info,
            "is_expired": datetime.utcnow() > self.expires_at
        }

class AuthController:
    def __init__(self):
        self._users: Dict[str, dict] = {}
        self._user_id_counter = 1
        self._active_tokens: Dict[int, List[Dict]] = {}
        self._used_refresh_tokens: set = set()
        self._token_info: Dict[str, TokenInfo] = {}
        
    def register(self, user_data: UserCreateRequest) -> UserDTO:
        if user_data.username in self._users:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Пользователь с таким именем уже зарегистрирован"
            )
        
        user_id = self._user_id_counter
        self._user_id_counter += 1
        
        user = {
            "id": user_id,
            "username": user_data.username,
            "email": user_data.email,
            "hashed_password": get_password_hash(user_data.password)
        }
        
        self._users[user_data.username] = user
        self._active_tokens[user_id] = []
        
        return UserDTO(**user)

    def login(self, login_data: UserLoginRequest) -> TokenDTO:
        user = self._users.get(login_data.username)
        if not user or not verify_password(login_data.password, user["hashed_password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверное имя пользователя или пароль"
            )
            
        clear_user_revoked_tokens(user["id"])
            
        active_tokens = self.get_active_tokens(user["id"])
        if len(active_tokens) >= settings.MAX_ACTIVE_TOKENS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Достигнуто максимальное количество активных сессий ({settings.MAX_ACTIVE_TOKENS}). Пожалуйста, выйдите из других сессий"
            )
            
        token_data = {
            "sub": user["username"],
            "id": user["id"],
            "email": user["email"]
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
        
        if user["id"] not in self._active_tokens:
            self._active_tokens[user["id"]] = []
        self._active_tokens[user["id"]].append(token_pair)
        
        return TokenDTO(access_token=access_token, refresh_token=refresh_token)

    def get_user_by_id(self, user_id: int) -> UserDTO:
        for user in self._users.values():
            if user["id"] == user_id:
                return UserDTO(**user)
        raise HTTPException(status_code=404, detail="Пользователь не найден")

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

    def refresh_token(self, refresh_token: str) -> TokenDTO:
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
                detail="Refresh token уже был использован"
            )
            
        user_id = payload.get("id")
        username = payload.get("sub")
        if not user_id or not username or username not in self._users:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Недействительные данные токена"
            )
            
        if is_token_revoked(refresh_token, user_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token был отозван"
            )
            
        self._used_refresh_tokens.add(refresh_token)
        
        token_data = {
            "sub": username,
            "id": user_id,
            "email": self._users[username]["email"]
        }
        
        new_access_token = create_jwt_token(data=token_data, is_refresh=False)
        new_refresh_token = create_jwt_token(data=token_data, is_refresh=True)
        
        token_pair = {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "created_at": datetime.utcnow().isoformat()
        }
        
        found = False
        if user_id in self._active_tokens:
            for i, pair in enumerate(self._active_tokens[user_id]):
                if pair["refresh_token"] == refresh_token:
                    self._active_tokens[user_id][i] = token_pair
                    found = True
                    break
                    
        if not found:
            if user_id not in self._active_tokens:
                self._active_tokens[user_id] = []
            self._active_tokens[user_id].append(token_pair)
        
        return TokenDTO(access_token=new_access_token, refresh_token=new_refresh_token)

    def change_password(self, user_id: int, current_password: str, new_password: str):
        user = None
        for u in self._users.values():
            if u["id"] == user_id:
                user = u
                break
                
        if not user or not verify_password(current_password, user["hashed_password"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Неверный текущий пароль"
            )
            
        user["hashed_password"] = get_password_hash(new_password)
        self.revoke_all_tokens(user_id) 