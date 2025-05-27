from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.config import Permission, User, RolesAndPermissions
from schemas.permission_schemas import PermissionCreateRequest, PermissionUpdateRequest, PermissionDTO, PermissionCollectionDTO
from core.security import require_permission
from core.database import get_db
from datetime import datetime

router = APIRouter(prefix="/permissions", tags=["permissions"])

def get_current_user():
    return User(id=1, username="admin", email="admin@test.com", hashed_password="hash")

@router.post("/", response_model=PermissionDTO, dependencies=[Depends(require_permission("create_permission"))])
def create_permission(request: PermissionCreateRequest, db: Session = Depends(get_db)):
    # Проверка уникальности
    if db.query(Permission).filter((Permission.name == request.name) | (Permission.code == request.code)).first():
        raise HTTPException(status_code=400, detail="Permission name or code must be unique")
    perm = Permission(name=request.name, description=request.description, code=request.code)
    db.add(perm)
    db.commit()
    db.refresh(perm)
    return perm

@router.get("/", response_model=PermissionCollectionDTO, dependencies=[Depends(require_permission("get-list_permission"))])
def list_permissions(db: Session = Depends(get_db)):
    perms = db.query(Permission).filter(Permission.is_deleted == False).all()
    return PermissionCollectionDTO(permissions=perms)

@router.get("/{permission_id}", response_model=PermissionDTO, dependencies=[Depends(require_permission("read_permission"))])
def get_permission(permission_id: int, db: Session = Depends(get_db)):
    perm = db.query(Permission).filter(Permission.id == permission_id, Permission.is_deleted == False).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    return perm

@router.put("/{permission_id}", response_model=PermissionDTO, dependencies=[Depends(require_permission("update_permission"))])
def update_permission(permission_id: int, request: PermissionUpdateRequest, db: Session = Depends(get_db)):
    perm = db.query(Permission).filter(Permission.id == permission_id, Permission.is_deleted == False).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    if request.name and db.query(Permission).filter(Permission.name == request.name, Permission.id != permission_id).first():
        raise HTTPException(status_code=400, detail="Permission name must be unique")
    if request.code and db.query(Permission).filter(Permission.code == request.code, Permission.id != permission_id).first():
        raise HTTPException(status_code=400, detail="Permission code must be unique")
    for field, value in request.dict(exclude_unset=True).items():
        setattr(perm, field, value)
    db.commit()
    db.refresh(perm)
    return perm

@router.delete("/{permission_id}", response_model=PermissionDTO, dependencies=[Depends(require_permission("soft_delete_permission"))])
def soft_delete_permission(
    permission_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Мягкое удаление разрешения (установка флага is_deleted)
    """
    try:
        # Проверяем существование разрешения
        perm = db.query(Permission).filter(Permission.id == permission_id, Permission.is_deleted == False).first()
        if not perm:
            raise HTTPException(status_code=404, detail="Разрешение не найдено или уже удалено")

        # Проверяем, не является ли разрешение системным
        if any(perm.code.startswith(prefix) for prefix in ["create_", "read_", "update_", "delete_", "get-list_", "restore_"]):
            raise HTTPException(
                status_code=400, 
                detail="Невозможно удалить системное разрешение"
            )

        # Помечаем разрешение как удаленное
        perm.is_deleted = True
        perm.deleted_by = current_user.id
        perm.deleted_at = datetime.utcnow()

        db.commit()
        db.refresh(perm)
        return perm
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Ошибка при удалении разрешения: {str(e)}"
        )

@router.delete("/{permission_id}/hard", response_model=PermissionDTO, dependencies=[Depends(require_permission("hard_delete_permission"))])
def hard_delete_permission(
    permission_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Жесткое удаление разрешения (физическое удаление из БД)
    """
    try:
        # Проверяем существование разрешения
        perm = db.query(Permission).filter(Permission.id == permission_id).first()
        if not perm:
            raise HTTPException(status_code=404, detail="Разрешение не найдено")

        # Проверяем, не является ли разрешение системным
        if any(perm.code.startswith(prefix) for prefix in ["create_", "read_", "update_", "delete_", "get-list_", "restore_"]):
            raise HTTPException(
                status_code=400, 
                detail="Невозможно удалить системное разрешение"
            )

        # Проверяем, есть ли связанные роли через таблицу RolesAndPermissions
        role_links = db.query(RolesAndPermissions).filter(
            RolesAndPermissions.permission_id == permission_id
        ).count()

        if role_links > 0:
            raise HTTPException(
                status_code=400,
                detail="Невозможно удалить разрешение, пока оно назначено ролям. Сначала удалите все связи с ролями."
            )

        # Физически удаляем разрешение
        db.delete(perm)
        db.commit()
        return perm
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Ошибка при физическом удалении разрешения: {str(e)}"
        )

@router.post("/{permission_id}/restore", response_model=PermissionDTO, dependencies=[Depends(require_permission("restore_permission"))])
def restore_permission(
    permission_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Восстановление мягко удаленного разрешения
    """
    try:
        perm = db.query(Permission).filter(Permission.id == permission_id, Permission.is_deleted == True).first()
        if not perm:
            raise HTTPException(status_code=404, detail="Разрешение не найдено или не было удалено")
        
        perm.is_deleted = False
        perm.deleted_by = None
        perm.deleted_at = None
        
        db.commit()
        db.refresh(perm)
        return perm
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Ошибка при восстановлении разрешения: {str(e)}"
        ) 