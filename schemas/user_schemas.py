from pydantic import BaseModel, EmailStr, validator, Field, ConfigDict
from datetime import date
from typing import Optional, List

class UserBase(BaseModel):
    username: str
    email: EmailStr
    birth_date: date

    model_config = ConfigDict(from_attributes=True)

class UserCreateRequest(UserBase):
    password: str
    password_confirm: str

    @validator('password_confirm')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Пароли не совпадают')
        return v

    @validator('birth_date')
    def validate_birth_date(cls, v):
        if v > date.today():
            raise ValueError('Дата рождения не может быть в будущем')
        return v

class UserUpdateRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    birth_date: Optional[date] = None
    password: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class UserLoginRequest(BaseModel):
    username: str
    password: str

    model_config = ConfigDict(from_attributes=True)

class UserDTO(UserBase):
    id: int = Field(...)
    email: str
    is_active: bool
    roles: List[str] = []

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "username": "user123",
                "email": "user@example.com",
                "birth_date": "1990-01-01"
            }
        }
    )

    @validator('roles', pre=True)
    def extract_role_codes(cls, v):
        if isinstance(v, list):
            return [r.code if hasattr(r, 'code') else r for r in v]
        return v

class UserCollectionDTO(BaseModel):
    users: List[UserDTO]
    model_config = ConfigDict(from_attributes=True)

class TokenDTO(BaseModel):
    access_token: str
    refresh_token: str

    model_config = ConfigDict(from_attributes=True)

class LoginResponseDTO(BaseModel):
    access_token: str

    model_config = ConfigDict(from_attributes=True) 