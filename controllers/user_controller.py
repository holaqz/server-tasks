from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.config import User, Role, UsersAndRoles, ChangeLogs
from core.database import get_db
from core.security import require_permission, get_current_user
from schemas.user_schemas import UserDTO, UserCollectionDTO, UserUpdateRequest, UserCreateRequest
from typing import List
from datetime import datetime
import json
from schemas.exception_schemas import UserNotFoundError
from schemas.log_schemas import ChangeLogResponse

router = APIRouter(prefix="/api/ref/user", tags=["users"])

def serialize_datetime(obj):
    """Преобразует datetime объекты в строки ISO формата"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj

def user_to_dict(user):
    """Преобразует объект пользователя в словарь с нужными полями"""
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'full_name': user.full_name,
        'birth_date': user.birth_date,
        'created_at': user.created_at,
        'updated_at': user.updated_at
    }

def has_changes(old_data: dict, new_data: dict) -> bool:
    """Проверяет, есть ли изменения между старыми и новыми данными"""
    for key, value in new_data.items():
        if key not in ['updated_at'] and old_data.get(key) != value:
            return True
    return False

@router.get("/", response_model=UserCollectionDTO, dependencies=[Depends(require_permission("get-list_user"))])
def get_users(db: Session = Depends(get_db)):
    """Получение списка пользователей"""
    users = db.query(User).filter(User.is_active == True).all()
    return UserCollectionDTO(users=users)

@router.get("/{id}/role", response_model=List[str], dependencies=[Depends(require_permission("get_roles_user"))])
def get_user_roles(id: int, db: Session = Depends(get_db)):
    """Получение ролей пользователя"""
    user = db.query(User).filter(User.id == id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return [role.code for role in user.roles]

@router.post("/{id}/role", dependencies=[Depends(require_permission("assign_role_user"))])
def assign_role(id: int, role_id: int, db: Session = Depends(get_db)):
    """Присвоение роли пользователю"""
    from core.config import UsersAndRoles
    user = db.query(User).filter(User.id == id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    existing = db.query(UsersAndRoles).filter_by(user_id=id, role_id=role_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Роль уже присвоена пользователю")
    
    user_role = UsersAndRoles(user_id=id, role_id=role_id)
    db.add(user_role)
    db.commit()
    return {"status": "success"}

@router.delete("/{id}/role/{role_id}", dependencies=[Depends(require_permission("hard_delete_role_user"))])
def delete_role(id: int, role_id: int, db: Session = Depends(get_db)):
    """Жесткое удаление роли у пользователя"""
    from core.config import UsersAndRoles
    user_role = db.query(UsersAndRoles).filter_by(user_id=id, role_id=role_id).first()
    if not user_role:
        raise HTTPException(status_code=404, detail="Связь пользователь-роль не найдена")
    
    db.delete(user_role)
    db.commit()
    return {"status": "success"}

@router.delete("/{id}/role/{role_id}/soft", dependencies=[Depends(require_permission("soft_delete_role_user"))])
def soft_delete_role(id: int, role_id: int, db: Session = Depends(get_db)):
    """Мягкое удаление роли у пользователя"""
    from core.config import UsersAndRoles
    user_role = db.query(UsersAndRoles).filter_by(user_id=id, role_id=role_id).first()
    if not user_role:
        raise HTTPException(status_code=404, detail="Связь пользователь-роль не найдена")
    
    user_role.is_deleted = True
    db.commit()
    return {"status": "success"}

@router.post("/{id}/role/{role_id}/restore", dependencies=[Depends(require_permission("restore_role_user"))])
def restore_role(id: int, role_id: int, db: Session = Depends(get_db)):
    """Восстановление мягко удаленной роли у пользователя"""
    from core.config import UsersAndRoles
    user_role = db.query(UsersAndRoles).filter_by(user_id=id, role_id=role_id, is_deleted=True).first()
    if not user_role:
        raise HTTPException(status_code=404, detail="Удаленная связь пользователь-роль не найдена")
    
    user_role.is_deleted = False
    db.commit()
    return {"status": "success"}

@router.post("/", response_model=UserDTO)
def create_user(user: UserCreateRequest, db: Session = Depends(get_db)):
    try:
        # Создаем нового пользователя
        new_user = User(
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            birth_date=user.birth_date
        )
        db.add(new_user)
        db.flush()  # Получаем ID нового пользователя
        
        # Создаем лог создания
        log = ChangeLogs(
            entity_type="User",
            entity_id=new_user.id,
            action="Create",
            old_value=None,
            new_value=json.dumps(user_to_dict(new_user), default=serialize_datetime)
        )
        db.add(log)
        
        db.commit()
        db.refresh(new_user)
        return new_user
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/{user_id}", response_model=UserDTO)
def update_user(user_id: int, user_update: UserUpdateRequest, db: Session = Depends(get_db)):
    try:
        # Получаем пользователя
        print(f"Ищем пользователя с ID: {user_id}")
        user = db.query(User).filter(User.id == user_id).first()
        
        # Проверяем всех пользователей в базе
        all_users = db.query(User).all()
        print(f"Всего пользователей в базе: {len(all_users)}")
        for u in all_users:
            print(f"Пользователь: id={u.id}, username={u.username}")
        
        if not user:
            raise HTTPException(status_code=404, detail=f"Пользователь с ID {user_id} не найден")
        
        # Сохраняем старые значения
        old_values = user_to_dict(user)
        
        # Обновляем поля
        update_data = user_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            if hasattr(user, field):  # Проверяем, существует ли поле
                setattr(user, field, value)
        
        # Проверяем, есть ли изменения
        new_values = user_to_dict(user)
        if not has_changes(old_values, new_values):
            return user  # Возвращаем пользователя без создания лога, если изменений нет
        
        # Создаем лог обновления
        log = ChangeLogs(
            entity_type="User",
            entity_id=user.id,
            action="Update",
            old_value=json.dumps(old_values, default=serialize_datetime),
            new_value=json.dumps(new_values, default=serialize_datetime)
        )
        db.add(log)
        
        db.commit()
        db.refresh(user)
        return user
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/{user_id}/hard", response_model=UserDTO)
def delete_user(user_id: int, db: Session = Depends(get_db)):
    try:
        # Получаем пользователя
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Пользователь не найден")
        
        # Сохраняем данные пользователя перед удалением
        user_data = user_to_dict(user)
        
        # Создаем лог удаления
        log = ChangeLogs(
            entity_type="User",
            entity_id=user.id,
            action="Delete",
            old_value=json.dumps(user_data, default=serialize_datetime),
            new_value=None
        )
        db.add(log)
        
        # Удаляем пользователя
        db.delete(user)
        db.commit()
        
        return user
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e)) 