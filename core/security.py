from datetime import datetime, timedelta
from typing import Optional, Dict
from jose import JWTError, jwt
from passlib.context import CryptContext
from .config import get_settings
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status, Cookie, Request
import secrets
from sqlalchemy.orm import Session
from core.config import User, Role, Permission, UsersAndRoles, RolesAndPermissions
from core.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
settings = get_settings()

revoked_tokens = set()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_jwt_token(data: Dict[str, any], expires_delta: Optional[timedelta] = None, is_refresh: bool = False) -> str:
    to_encode = data.copy()
    now = datetime.utcnow()
    to_encode.update({"iat": now})
    
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + (
            timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS) if is_refresh 
            else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
    
    to_encode.update({
        "exp": expire,
        "type": "refresh" if is_refresh else "access",
        "jti": secrets.token_urlsafe(8)
    })
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt

def decode_jwt_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        
        if datetime.fromtimestamp(payload.get("exp")) < datetime.utcnow():
            return None
            
        return payload
    except JWTError:
        return None

def revoke_token(token: str):
    if token.startswith("Bearer "):
        token = token[7:]
    revoked_tokens.add(token)

def revoke_all_user_tokens(user_id: int):
    revoked_tokens.add(f"user_{user_id}")

def is_token_revoked(token: str, user_id: int) -> bool:
    if token.startswith("Bearer "):
        token = token[7:]
    return token in revoked_tokens or f"user_{user_id}" in revoked_tokens

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не предоставлен токен аутентификации"
        )

    try:
        payload = decode_jwt_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Недействительный токен"
            )
            
        if is_token_revoked(token, payload.get("id")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Токен был отозван"
            )
            
        user = db.query(User).filter(User.id == payload.get("id")).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Пользователь не найден"
            )
            
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Пользователь деактивирован"
            )
            
        # Добавляем токен к объекту пользователя для использования в других частях приложения
        setattr(user, 'token', token)
        return user
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Недействительный токен аутентификации"
        )

create_token = create_jwt_token
decode_token = decode_jwt_token

def clear_user_revoked_tokens(user_id: int):
    key = f"user_{user_id}"
    if key in revoked_tokens:
        revoked_tokens.remove(key)

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

def get_user_permissions(user: User, db: Session) -> set[str]:
    permissions = set()
    
    # Получаем только активные связи пользователь-роли
    for user_role_assoc in db.query(UsersAndRoles).filter(
        UsersAndRoles.user_id == user.id,
        UsersAndRoles.is_deleted == False
    ).all():
        role = user_role_assoc.role
        if role.is_deleted:
            continue
            
        for role_perm_assoc in db.query(RolesAndPermissions).filter(
            RolesAndPermissions.role_id == role.id,
            RolesAndPermissions.is_deleted == False
        ).all():
            permission = role_perm_assoc.permission
            if not permission.is_deleted:
                permissions.add(permission.code)
    
    return permissions

def require_permission(permission_code: str):
    def dependency(
        current_user: User = Depends(get_current_user), 
        db: Session = Depends(get_db)
    ):
        perms = get_user_permissions(current_user, db)
        if permission_code not in perms:
            raise HTTPException(
                status_code=403, 
                detail=f"Требуется разрешение '{permission_code}'"
            )
        return True
    return dependency