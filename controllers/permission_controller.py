from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from core.config import Permission, User, RolesAndPermissions, ChangeLogs
from schemas.permission_schemas import PermissionCreateRequest, PermissionUpdateRequest, PermissionDTO, PermissionCollectionDTO
from core.security import require_permission
from core.database import get_db
from datetime import datetime
from core.log import get_all_permission
from schemas.log_schemas import ChangeLogResponse
from schemas.exception_schemas import PermissionNotFoundError


router = APIRouter(prefix="/permissions", tags=["permissions"])

def get_current_user():
    return User(id=1, username="admin", email="admin@test.com", hashed_password="hash")

@router.post("/", response_model=PermissionDTO, dependencies=[Depends(require_permission("create_permission"))])
def create_permission(request: PermissionCreateRequest, db: Session = Depends(get_db)):
    if db.query(Permission).filter((Permission.name == request.name) | (Permission.code == request.code)).first():
        raise HTTPException(status_code=400, detail="Имя или код разрешения должны быть уникальными")
    
    now = datetime.utcnow()
    perm = Permission(
        name=request.name,
        description=request.description,
        code=request.code,
        created_at=now,
        updated_at=now
    )
    db.add(perm)
    db.commit()
    db.refresh(perm)
    
    log = ChangeLogs(entity_type="Permission",
                     entity_id=perm.id,
                     action="Create",
                     old_value="",
                     new_value=str({
                         "name": perm.name,
                         "description": perm.description,
                         "code": perm.code,
                         "is_delited": perm.is_deleted,
                         "created_at": perm.created_at,
                         "updaated_at": perm.updated_at,
                         "delitedd_at": perm.deleted_at
                     }),
                     created_at=datetime.now())

    db.add(log)
    db.commit()
    db.refresh(log)

    return perm

@router.get("/", response_model=PermissionCollectionDTO, dependencies=[Depends(require_permission("get-list_permission"))])
def list_permissions(db: Session = Depends(get_db)):
    perms = db.query(Permission).filter(Permission.deleted_at == None).all()
    return PermissionCollectionDTO(permissions=perms)

@router.get("/{permission_id}", response_model=PermissionDTO, dependencies=[Depends(require_permission("read_permission"))])
def get_permission(permission_id: int, db: Session = Depends(get_db)):
    perm = db.query(Permission).filter(Permission.id == permission_id, Permission.deleted_at == None).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Разрешение не найдено")
    return perm

@router.put("/{permission_id}", response_model=PermissionDTO, dependencies=[Depends(require_permission("update_permission"))])
def update_permission(permission_id: int, request: PermissionUpdateRequest, db: Session = Depends(get_db)):
    try:
        perm = db.query(Permission).filter(Permission.id == permission_id, Permission.deleted_at == None).first()
        if not perm:
            raise HTTPException(status_code=404, detail="Разрешение не найдено")

        old_perm = {
            "id" : perm.id,
            "name": perm.name,
            "description": perm.description,
            "code": perm.code,
            "is_deleted": perm.is_deleted,
            "created_at": perm.created_at,
            "updated_at": perm.updated_at,
            "deleted_at": perm.deleted_at
        }
        
        if request.name and db.query(Permission).filter(Permission.name == request.name, Permission.id != permission_id).first():
            raise HTTPException(status_code=400, detail="Имя разрешения должно быть уникальным")
        if request.code and db.query(Permission).filter(Permission.code == request.code, Permission.id != permission_id).first():
            raise HTTPException(status_code=400, detail="Код разрешения должен быть уникальным")

        for field, value in request.dict(exclude_unset=True).items():
            setattr(perm, field, value)
        
        perm.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(perm)
        
        log = ChangeLogs(entity_type="Permission",
                         entity_id=perm.id,
                         action="Delete_soft",
                         old_value=str(old_perm),
                         new_value=str({
                             "id": perm.id,
                             "name": perm.name,
                             "description": perm.description,
                             "code": perm.code,
                             "is_deleted": perm.is_deleted,
                             "created_at": perm.created_at,
                             "updated_at": perm.updated_at,
                             "deleted_at": perm.deleted_at
                         }),
                         created_at=datetime.now())

        db.add(log)
        db.commit()
        db.refresh(log)
    
        return perm
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при обновлении разрешения: {str(e)}"
        )

@router.delete("/{permission_id}", response_model=PermissionDTO, dependencies=[Depends(require_permission("soft_delete_permission"))])
def soft_delete_permission(
    permission_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Мягкое удаление разрешения
    """
    try:
        perm = db.query(Permission).filter(Permission.id == permission_id, Permission.deleted_at == None).first()
        if not perm:
            raise HTTPException(status_code=404, detail="Разрешение не найдено или уже удалено")

        if any(perm.code.startswith(prefix) for prefix in ["create_", "read_", "update_", "delete_", "get-list_", "restore_"]):
            raise HTTPException(
                status_code=400, 
                detail="Невозможно удалить системное разрешение"
            )
            
        old_perm = {
            "id": perm.id,
            "name": perm.name,
            "description": perm.description,
            "code": perm.code,
            "is_deleted": perm.is_deleted,
            "created_at": perm.created_at,
            "updated_at": perm.updated_at,
            "deleted_at": perm.deleted_at
        }

        now = datetime.utcnow()
        perm.deleted_by = current_user.id
        perm.deleted_at = now
        perm.updated_at = now

        db.commit()
        db.refresh(perm)
        
        log = ChangeLogs(entity_type="Permission",
                         entity_id=perm.id,
                         action="Delete_soft",
                         old_value=str(old_perm),
                         new_value=str({
                             "id": perm.id,
                             "name": perm.name,
                             "description": perm.description,
                             "code": perm.code,
                             "is_deleted": perm.is_deleted,
                             "created_at": perm.created_at,
                             "updated_at": perm.updated_at,
                             "deleted_at": perm.deleted_at
                         }),
                         created_at=datetime.now())

        db.add(log)
        db.commit()
        db.refresh(log)

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
        perm = db.query(Permission).filter(Permission.id == permission_id).first()
        if not perm:
            raise HTTPException(status_code=404, detail="Разрешение не найдено")

        if any(perm.code.startswith(prefix) for prefix in ["create_", "read_", "update_", "delete_", "get-list_", "restore_"]):
            raise HTTPException(
                status_code=400, 
                detail="Невозможно удалить системное разрешение"
            )

        role_links = db.query(RolesAndPermissions).filter(
            RolesAndPermissions.permission_id == permission_id
        ).count()

        if role_links > 0:
            raise HTTPException(
                status_code=400,
                detail="Невозможно удалить разрешение, пока оно назначено ролям. Сначала удалите все связи с ролями."
            )

        log = ChangeLogs(entity_type="Permission",
                         entity_id=perm.id,
                         action="Delete_soft",
                         old_value=str({
                             "id": perm.id,
                             "name": perm.name,
                             "description": perm.description,
                             "code": perm.code,
                             "is_deleted": perm.is_deleted,
                             "created_at": perm.created_at,
                             "updated_at": perm.updated_at,
                             "deleted_at": perm.deleted_at
                         }),
                         new_value="",
                         created_at=datetime.now())

        db.add(log)
        db.commit()
        db.refresh(log)

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
        perm = db.query(Permission).filter(Permission.id == permission_id, Permission.deleted_at != None).first()
        old_perm = {
            "id": perm.id,
            "name": perm.name,
            "description": perm.description,
            "code": perm.code,
            "is_deleted": perm.is_deleted,
            "created_at": perm.created_at,
            "updated_at": perm.updated_at,
            "deleted_at": perm.deleted_at
        }
        if not perm:
            raise HTTPException(status_code=404, detail="Разрешение не найдено или не было удалено")
        
        perm.deleted_by = None
        perm.deleted_at = None
        perm.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(perm)
        log = ChangeLogs(entity_type="Permission",
                         entity_id=perm.id,
                         action="Restore_soft",
                         old_value=str(old_perm),
                         new_value=str({
                             "id": perm.id,
                             "name": perm.name,
                             "description": perm.description,
                             "code": perm.code,
                             "is_deleted": perm.is_deleted,
                             "created_at": perm.created_at,
                             "updated_at": perm.updated_at,
                             "deleted_at": perm.deleted_at
                         }),
                         created_at=datetime.now())
        
        db.add(log)
        db.commit()
        db.refresh(log)
        
        return perm
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Ошибка при восстановлении разрешения: {str(e)}"
        ) 

@router.get("/{permissions_id}/logs", response_model=List[ChangeLogResponse],
           dependencies=[Depends(require_permission("get_story_permission")), Depends(get_current_user)])
def get_permission_logs(
    permissions_id: int,
    db: Session = Depends(get_db)
):
    try:
        logs = db.query(ChangeLogs).filter(
            ChangeLogs.entity_type == "Permission",
            ChangeLogs.entity_id == permissions_id
        ).order_by(ChangeLogs.created_at.desc()).all()

        if not logs:
            raise HTTPException(
                status_code=404,
                detail="Логи для данного разрешения не найдены"
            )

        return [ChangeLogResponse.from_orm(log) for log in logs]

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при получении логов разрешения: {str(e)}"
        )