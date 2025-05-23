from pydantic import BaseModel, EmailStr, validator, Field
from datetime import date
from typing import Optional

class UserBase(BaseModel):
    username: str
    email: EmailStr
    birth_date: date

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

class UserLoginRequest(BaseModel):
    username: str
    password: str

class UserDTO(UserBase):
    id: int = Field(...)

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "username": "user123",
                "email": "user@example.com",
                "birth_date": "1990-01-01"
            }
        }

class TokenDTO(BaseModel):
    access_token: str
    refresh_token: str

class LoginResponseDTO(BaseModel):
    access_token: str 