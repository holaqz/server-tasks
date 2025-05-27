from pydantic import BaseModel, ConfigDict
from typing import List

class UserRoleBase(BaseModel):
    user_id: int
    role_id: int

    model_config = ConfigDict(from_attributes=True)

class UserRoleCreateRequest(UserRoleBase):
    pass

class UserRoleDeleteRequest(UserRoleBase):
    pass

class UserRoleDTO(UserRoleBase):
    id: int
    model_config = ConfigDict(from_attributes=True)

class UserRoleCollectionDTO(BaseModel):
    user_roles: List[UserRoleDTO]
    model_config = ConfigDict(from_attributes=True) 