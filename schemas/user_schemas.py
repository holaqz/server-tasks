from pydantic import BaseModel, EmailStr
from typing import Optional

class UserCreateRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    def to_dto(self):
        return UserCreateDTO(username=self.username, email=self.email)

class UserLoginRequest(BaseModel):
    username: str
    password: str

    def to_dto(self):
        return TokenDTO

class UserDTO(BaseModel):
    id: int
    username: str
    email: EmailStr

    class Config:
        orm_mode = True

class UserCreateDTO(BaseModel):
    username: str
    email: EmailStr

class TokenDTO(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None
    id: Optional[int] = None 