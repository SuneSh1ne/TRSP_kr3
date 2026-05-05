from pydantic import BaseModel
from enum import Enum

class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"

class ResourceCreate(BaseModel):
    name: str
    data: str

class ResourceUpdate(BaseModel):
    name: str | None = None
    data: str | None = None

class ResourceResponse(BaseModel):
    id: int
    name: str
    data: str
    owner: str