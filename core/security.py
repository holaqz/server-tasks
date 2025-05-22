from datetime import datetime, timedelta
from typing import Optional, Dict
from jose import JWTError, jwt
from passlib.context import CryptContext
from .config import get_settings
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status, Cookie, Request
import secrets

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

async def get_current_user(request: Request) -> Dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось проверить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    access_token_cookie = request.cookies.get("access_token")
    
    if access_token_cookie and access_token_cookie.startswith("Bearer "):
        token = access_token_cookie[7:]
    else:
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise credentials_exception
        token = authorization[7:]
    
    payload = decode_jwt_token(token)
    if payload is None or payload.get("type") != "access":
        raise credentials_exception

    user_id = payload.get("id")
    if user_id and is_token_revoked(token, user_id):
        raise credentials_exception
        
    payload["token"] = token
    return payload

create_token = create_jwt_token
decode_token = decode_jwt_token

def clear_user_revoked_tokens(user_id: int):
    key = f"user_{user_id}"
    if key in revoked_tokens:
        revoked_tokens.remove(key) 