from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.config import User, Role, Base
from schemas.role_schemas import RoleCreateRequest, RoleUpdateRequest, RoleDTO, RoleCollectionDTO
from typing import List
from core.security import require_permission
from core.database import get_db
from datetime import datetime

router = APIRouter(prefix="/roles", tags=["roles"])

# Заглушка для получения сессии БД
# def get_db(): ...
# Заглушка для проверки авторизации
# def get_current_user(): ...

def get_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user():
    # Заглушка для авторизации
    return User(id=1, username="admin", email="admin@test.com", hashed_password="hash")

@router.post("/", response_model=RoleDTO, dependencies=[Depends(require_permission("create_role"))])
def create_role(request: RoleCreateRequest, db: Session = Depends(get_db)):
    # Проверка уникальности
    if db.query(Role).filter((Role.name == request.name) | (Role.code == request.code)).first():
        raise HTTPException(status_code=400, detail="Role name or code must be unique")
    role = Role(name=request.name, description=request.description, code=request.code)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role

@router.get("/", response_model=RoleCollectionDTO, dependencies=[Depends(require_permission("get-list_role"))])
def list_roles(db: Session = Depends(get_db)):
    roles = db.query(Role).filter(Role.is_deleted == False).all()
    return RoleCollectionDTO(roles=roles)

@router.get("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("read_role"))])
def get_role(role_id: int, db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id, Role.is_deleted == False).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role

@router.put("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("update_role"))])
def update_role(role_id: int, request: RoleUpdateRequest, db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id, Role.is_deleted == False).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if request.name and db.query(Role).filter(Role.name == request.name, Role.id != role_id).first():
        raise HTTPException(status_code=400, detail="Role name must be unique")
    if request.code and db.query(Role).filter(Role.code == request.code, Role.id != role_id).first():
        raise HTTPException(status_code=400, detail="Role code must be unique")
    for field, value in request.dict(exclude_unset=True).items():
        setattr(role, field, value)
    db.commit()
    db.refresh(role)
    return role

@router.delete("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("soft_delete_role"))])
def soft_delete_role(
    role_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Мягкое удаление роли (установка флага is_deleted)
    """
    try:
        # Проверяем существование роли
        role = db.query(Role).filter(Role.id == role_id, Role.is_deleted == False).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена или уже удалена")

        # Проверяем, не является ли роль системной
        if role.code in ["ADMIN", "USER", "GUEST"]:
            raise HTTPException(
                status_code=400, 
                detail="Невозможно удалить системную роль"
            )

        # Помечаем роль как удаленную
        role.is_deleted = True
        role.deleted_by = current_user.id
        role.deleted_at = datetime.utcnow()

        db.commit()
        db.refresh(role)
        return role
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Ошибка при удалении роли: {str(e)}"
        )

@router.delete("/{role_id}/hard", response_model=RoleDTO, dependencies=[Depends(require_permission("hard_delete_role"))])
def hard_delete_role(
    role_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Жесткое удаление роли (физическое удаление из БД)
    """
    try:
        # Проверяем существование роли
        role = db.query(Role).filter(Role.id == role_id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена")

        # Проверяем, не является ли роль системной
        if role.code in ["ADMIN", "USER", "GUEST"]:
            raise HTTPException(
                status_code=400, 
                detail="Невозможно удалить системную роль"
            )

        # Проверяем, есть ли связанные пользователи
        if role.users and len(role.users) > 0:
            raise HTTPException(
                status_code=400,
                detail="Невозможно удалить роль, пока она назначена пользователям"
            )

        # Физически удаляем роль
        db.delete(role)
        db.commit()
        return role
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Ошибка при физическом удалении роли: {str(e)}"
        )

@router.post("/{role_id}/restore", response_model=RoleDTO, dependencies=[Depends(require_permission("restore_role"))])
def restore_role(
    role_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Восстановление мягко удаленной роли
    """
    try:
        role = db.query(Role).filter(Role.id == role_id, Role.is_deleted == True).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена или не была удалена")
        
        role.is_deleted = False
        role.deleted_by = None
        role.deleted_at = None
        
        db.commit()
        db.refresh(role)
        return role
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Ошибка при восстановлении роли: {str(e)}"
        ) 