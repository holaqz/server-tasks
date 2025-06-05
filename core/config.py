from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional, List
import os
from dotenv import load_dotenv
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, UniqueConstraint, func, Date, Text
from sqlalchemy.orm import relationship
from datetime import datetime

load_dotenv()

class Settings(BaseSettings):
    SECRET_KEY: str = os.getenv("SECRET_KEY", "964c6c687d8e0b9a07164b791d36e19a40707a2fee52d7f0d657f5ecc48ac6619d1ce61ad039c914a16b26f3e5e36c81edb2f8e918e9f65c326081c77a43649446a3f9e4530feab0b72505c7b3c5bc0974c6d0ab260f351fc34b37a58110d47fbe4c8030995927e16b1875ba4c94a70a1044df39f86001c0d9ffd02035158d4747e9187118e0146a92c27594fa5b2b8ba87cfb35879895d9db0104017881956049ecb47b80843e68418859b7eb51595d3e52bf7a910921d12797d7ecbf26628993763973be556b3875eeed889d7dc4016c6d60b253cee67255a39d0a4f2c3792c0b677bd0c9c70914fd3d9c7937ed7e13b69fb89e21fea7f01c66cddbab56174")
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
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
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
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
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
    role_id = Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'), nullable=False)
    permission_id = Column(Integer, ForeignKey('permissions.id', ondelete='CASCADE'), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    is_deleted = Column(Boolean, default=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    __table_args__ = (UniqueConstraint('role_id', 'permission_id', name='_role_permission_uc'),)

    # Определяем отношения для аудита
    deleter = relationship('User', foreign_keys=[deleted_by])
    creator = relationship('User', foreign_keys=[created_by])
    # Основные отношения
    role = relationship('Role', foreign_keys=[role_id])
    permission = relationship('Permission', foreign_keys=[permission_id])
    
class ChangeLogs(Base):
    __tablename__ = "change_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)

    entity_type = Column(String(100), nullable=False)
    entity_id = Column(Integer, nullable=False)
    action = Column(String(10), nullable=False)
    old_value = Column(Text)
    new_value = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)