from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.config import User
from core.database import get_db
from core.security import require_permission, get_current_user
from schemas.user_schemas import UserDTO, UserCollectionDTO
from typing import List

router = APIRouter(prefix="/api/ref/user", tags=["users"])

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