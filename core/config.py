from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional, List
import os
from dotenv import load_dotenv
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, UniqueConstraint, func, Date
from sqlalchemy.orm import relationship

load_dotenv()

class Settings(BaseSettings):
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    MAX_ACTIVE_TOKENS: Optional[int] = int(os.getenv("MAX_ACTIVE_TOKENS", "5"))

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings() -> Settings:
    return Settings()

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    birth_date = Column(Date, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    user_roles = relationship('Role', 
                            secondary='users_and_roles',
                            primaryjoin='and_(User.id == UsersAndRoles.user_id, UsersAndRoles.is_deleted == False)',
                            secondaryjoin='Role.id == UsersAndRoles.role_id',
                            back_populates='users')

    @property
    def roles(self) -> List['Role']:
        return self.user_roles

class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255))
    code = Column(String(100), unique=True, nullable=False)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    users = relationship('User', 
                        secondary='users_and_roles',
                        primaryjoin='and_(Role.id == UsersAndRoles.role_id, UsersAndRoles.is_deleted == False)',
                        secondaryjoin='User.id == UsersAndRoles.user_id',
                        back_populates='user_roles')
    role_permissions = relationship('Permission', secondary='roles_and_permissions', back_populates='permission_roles')

    @property
    def permissions(self) -> List['Permission']:
        return self.role_permissions

class Permission(Base):
    __tablename__ = 'permissions'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255))
    code = Column(String(100), unique=True, nullable=False)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    permission_roles = relationship('Role', secondary='roles_and_permissions', back_populates='role_permissions')

class UsersAndRoles(Base):
    __tablename__ = 'users_and_roles'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    role_id = Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    is_deleted = Column(Boolean, default=False)
    deleted_at = Column(DateTime)
    deleted_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    __table_args__ = (UniqueConstraint('user_id', 'role_id', name='_user_role_uc'),)

    # Определяем отношения для аудита
    deleter = relationship('User', foreign_keys=[deleted_by], overlaps="user_roles,users")
    creator = relationship('User', foreign_keys=[created_by], overlaps="user_roles,users")
    # Основное отношение для связи пользователь-роль
    user = relationship('User', foreign_keys=[user_id], overlaps="user_roles,users")
    role = relationship('Role', foreign_keys=[role_id], overlaps="user_roles,users")

class RolesAndPermissions(Base):
    __tablename__ = 'roles_and_permissions'
    id = Column(Integer, primary_key=True)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    permission_id = Column(Integer, ForeignKey('permissions.id'), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    __table_args__ = (UniqueConstraint('role_id', 'permission_id', name='_role_permission_uc'),)