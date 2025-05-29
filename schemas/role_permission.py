from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class RolePermissionBase(BaseModel):
    role_id: int
    permission_id: int

class RolePermissionCreate(RolePermissionBase):
    pass

class RolePermissionResponse(RolePermissionBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    is_deleted: bool
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[int] = None
    created_by: Optional[int] = None

    class Config:
        from_attributes = True 