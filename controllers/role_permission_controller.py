from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.config import Role, Permission, RolesAndPermissions, User
from schemas.role_permission_schemas import RolePermissionDTO, RolePermissionCreateRequest
from core.security import require_permission
from core.database import get_db
from typing import List

router = APIRouter(prefix="/role-permissions", tags=["role-permissions"])

def get_current_user():
    return User(id=1, username="admin", email="admin@test.com", hashed_password="hash")

@router.post("/", response_model=RolePermissionDTO, dependencies=[Depends(require_permission("assign_permission"))])
def assign_permission_to_role(
    request: RolePermissionCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Назначает разрешение роли
    """
    try:
        # Проверяем существование роли
        role = db.query(Role).filter(
            Role.id == request.role_id,
            Role.is_deleted == False
        ).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена")

        # Проверяем существование разрешения
        permission = db.query(Permission).filter(
            Permission.id == request.permission_id,
            Permission.is_deleted == False
        ).first()
        if not permission:
            raise HTTPException(status_code=404, detail="Разрешение не найдено")

        # Проверяем, не существует ли уже такая связь
        existing = db.query(RolesAndPermissions).filter(
            RolesAndPermissions.role_id == request.role_id,
            RolesAndPermissions.permission_id == request.permission_id
        ).first()
        if existing:
            raise HTTPException(
                status_code=400,
                detail="Это разрешение уже назначено данной роли"
            )

        # Создаем связь
        role_permission = RolesAndPermissions(
            role_id=request.role_id,
            permission_id=request.permission_id
        )
        db.add(role_permission)
        db.commit()
        db.refresh(role_permission)

        return RolePermissionDTO(
            role_id=role.id,
            permission_id=permission.id,
            role_name=role.name,
            permission_name=permission.name
        )

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при назначении разрешения роли: {str(e)}"
        )

@router.delete("/{role_id}/{permission_id}", dependencies=[Depends(require_permission("revoke_permission"))])
def revoke_permission_from_role(
    role_id: int,
    permission_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Отзывает разрешение у роли
    """
    try:
        # Проверяем существование связи
        role_permission = db.query(RolesAndPermissions).filter(
            RolesAndPermissions.role_id == role_id,
            RolesAndPermissions.permission_id == permission_id
        ).first()
        
        if not role_permission:
            raise HTTPException(
                status_code=404,
                detail="Связь между ролью и разрешением не найдена"
            )

        # Удаляем связь
        db.delete(role_permission)
        db.commit()

        return {"message": "Разрешение успешно отозвано у роли"}

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при отзыве разрешения у роли: {str(e)}"
        )

@router.get("/role/{role_id}/permissions", response_model=List[RolePermissionDTO], dependencies=[Depends(require_permission("read_role_permissions"))])
def get_role_permissions(
    role_id: int,
    db: Session = Depends(get_db)
):
    """
    Получает список всех разрешений роли
    """
    try:
        # Проверяем существование роли
        role = db.query(Role).filter(
            Role.id == role_id,
            Role.is_deleted == False
        ).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена")

        # Получаем все разрешения роли
        role_permissions = db.query(RolesAndPermissions, Role, Permission).join(
            Role, RolesAndPermissions.role_id == Role.id
        ).join(
            Permission, RolesAndPermissions.permission_id == Permission.id
        ).filter(
            RolesAndPermissions.role_id == role_id,
            Permission.is_deleted == False
        ).all()

        return [
            RolePermissionDTO(
                role_id=rp[1].id,
                permission_id=rp[2].id,
                role_name=rp[1].name,
                permission_name=rp[2].name
            )
            for rp in role_permissions
        ]

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при получении разрешений роли: {str(e)}"
        ) 