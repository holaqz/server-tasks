from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List

class PermissionBase(BaseModel):
    name: str = Field(..., max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    code: str = Field(..., max_length=100)

    model_config = ConfigDict(from_attributes=True)

class PermissionCreateRequest(PermissionBase):
    pass

class PermissionUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    code: Optional[str] = Field(None, max_length=100)

    model_config = ConfigDict(from_attributes=True)

class PermissionDTO(PermissionBase):
    id: int
    is_deleted: bool
    model_config = ConfigDict(from_attributes=True)

class PermissionCollectionDTO(BaseModel):
    permissions: List[PermissionDTO]
    model_config = ConfigDict(from_attributes=True) 