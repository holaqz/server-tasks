from pydantic import BaseModel, ConfigDict
from typing import List

class RolePermissionBase(BaseModel):
    role_id: int
    permission_id: int

    model_config = ConfigDict(from_attributes=True)

class RolePermissionCreateRequest(RolePermissionBase):
    pass

class RolePermissionDeleteRequest(RolePermissionBase):
    pass

class RolePermissionDTO(RolePermissionBase):
    id: int
    model_config = ConfigDict(from_attributes=True)

class RolePermissionCollectionDTO(BaseModel):
    role_permissions: List[RolePermissionDTO]
    model_config = ConfigDict(from_attributes=True) 