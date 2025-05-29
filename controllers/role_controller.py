from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.config import User, Role, Base, Permission, RolesAndPermissions
from schemas.role_schemas import RoleCreateRequest, RoleUpdateRequest, RoleDTO, RoleCollectionDTO
from typing import List
from core.security import require_permission
from core.database import get_db
from datetime import datetime

router = APIRouter(prefix="/roles", tags=["roles"])

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
    return User(id=1, username="admin", email="admin@test.com", hashed_password="hash")

@router.post("/", response_model=RoleDTO, dependencies=[Depends(require_permission("create_role"))])
def create_role(request: RoleCreateRequest, db: Session = Depends(get_db)):
    # Проверка уникальности
    if db.query(Role).filter((Role.name == request.name) | (Role.code == request.code)).first():
        raise HTTPException(status_code=400, detail="Имя или код роли должны быть уникальными")
    
    now = datetime.utcnow()
    role = Role(
        name=request.name,
        description=request.description,
        code=request.code,
        created_at=now,
        updated_at=now
    )
    db.add(role)
    db.commit()
    db.refresh(role)
    return role

@router.get("/", response_model=RoleCollectionDTO, dependencies=[Depends(require_permission("get-list_role"))])
def list_roles(db: Session = Depends(get_db)):
    roles = db.query(Role).filter(Role.deleted_at == None).all()
    return RoleCollectionDTO(roles=roles)

@router.get("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("read_role"))])
def get_role(role_id: int, db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id, Role.deleted_at == None).first()
    if not role:
        raise HTTPException(status_code=404, detail="Роль не найдена")
    return role

@router.put("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("update_role"))])
def update_role(role_id: int, request: RoleUpdateRequest, db: Session = Depends(get_db)):
    try:
        # Проверяем существование роли
        role = db.query(Role).filter(Role.id == role_id, Role.deleted_at == None).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена")

        # Проверяем уникальность имени и кода
        if request.name and db.query(Role).filter(Role.name == request.name, Role.id != role_id).first():
            raise HTTPException(status_code=400, detail="Имя роли должно быть уникальным")
        if request.code and db.query(Role).filter(Role.code == request.code, Role.id != role_id).first():
            raise HTTPException(status_code=400, detail="Код роли должен быть уникальным")

        # Обновляем основные поля роли
        update_data = request.dict(exclude_unset=True)
        permission_ids = update_data.pop('permission_ids', None)
        
        for field, value in update_data.items():
            setattr(role, field, value)

        role.updated_at = datetime.utcnow()

        # Если предоставлен список разрешений, обновляем их
        if permission_ids is not None:
            # Проверяем существование всех разрешений
            permissions = db.query(Permission).filter(
                Permission.id.in_(permission_ids),
                Permission.deleted_at == None
            ).all()
            
            if len(permissions) != len(permission_ids):
                raise HTTPException(
                    status_code=400,
                    detail="Одно или несколько разрешений не найдены"
                )

            # Удаляем все текущие связи
            db.query(RolesAndPermissions).filter(
                RolesAndPermissions.role_id == role_id
            ).delete()

            # Создаем новые связи
            for permission_id in permission_ids:
                role_permission = RolesAndPermissions(
                    role_id=role_id,
                    permission_id=permission_id
                )
                db.add(role_permission)

        db.commit()
        db.refresh(role)
        return role
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при обновлении роли: {str(e)}"
        )

@router.delete("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("soft_delete_role"))])
def soft_delete_role(
    role_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Мягкое удаление роли
    """
    try:
        # Проверяем существование роли
        role = db.query(Role).filter(Role.id == role_id, Role.deleted_at == None).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена или уже удалена")

        # Проверяем, не является ли роль системной
        if role.code in ["ADMIN", "USER", "GUEST"]:
            raise HTTPException(
                status_code=400, 
                detail="Невозможно удалить системную роль"
            )

        # Помечаем роль как удаленную
        now = datetime.utcnow()
        role.deleted_by = current_user.id
        role.deleted_at = now
        role.updated_at = now

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
        role = db.query(Role).filter(Role.id == role_id, Role.deleted_at != None).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена или не была удалена")
        
        role.deleted_by = None
        role.deleted_at = None
        role.updated_at = datetime.utcnow()
        
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