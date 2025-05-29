from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import and_
from datetime import datetime
from typing import List

from core.database import get_db
from core.config import RolesAndPermissions
from core.security import get_current_user, require_permission
from schemas.user_schemas import UserDTO

router = APIRouter(
    prefix="/api/role-permissions",
    tags=["role-permissions"]
)

@router.delete("/{role_id}/{permission_id}", status_code=status.HTTP_200_OK)
async def soft_delete_role_permission(
    role_id: int,
    permission_id: int,
    current_user: UserDTO = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_permission("role_permission.delete")
    
    role_permission = db.query(RolesAndPermissions).filter(
        and_(
            RolesAndPermissions.role_id == role_id,
            RolesAndPermissions.permission_id == permission_id,
            RolesAndPermissions.is_deleted == None
        )
    ).first()
    
    if not role_permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role-permission relationship not found"
        )
    
    role_permission.is_deleted = True
    role_permission.deleted_at = datetime.utcnow()
    role_permission.deleted_by = current_user.id
    
    db.commit()
    
    return None