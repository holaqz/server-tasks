from pydantic import BaseModel
from typing import List

class RolePermissionCreateRequest(BaseModel):
    role_id: int
    permission_id: int

class RolePermissionDTO(BaseModel):
    role_id: int
    permission_id: int
    role_name: str
    permission_name: str

    class Config:
        from_attributes = True

class RolePermissionCollectionDTO(BaseModel):
    role_permissions: List[RolePermissionDTO] 