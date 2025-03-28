from pydantic import BaseModel
from typing import Tuple, Optional

class VPNCreateSchema(BaseModel):
    '''Создание нового конфига.'''
    telegram_id: int

    class Config:
        json_schema_extra = {
            "example": {
                "telegram_id": 1999999999
            }
        }


class VPNConfigResponse(BaseModel):
    config_name: str

    class Config:
        from_attributes = True  # Позволяет Pydantic работать с объектами ORM

from pydantic import AnyUrl

class VPNCreateResponseSchema(BaseModel):
    config_name: str
    config: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "config_name": "4323432343",
                "config": "config data"
            }
        }


class VPNRemoveSchema(BaseModel):
    '''Удаление конфига.'''
    config_name: str
    status: bool
    msg: str

    class Config:
        json_schema_extra = {
            "example": {
                "config_name": "4323432343",
                "status": True,
                "msg": "OK"
            }
        }


class VPNListSchema(BaseModel):
    '''Список конфигов.'''
    config_name: str

    class Config:
        json_schema_extra = {
            "example": {
                "config_name": "4323432343",
            }
        }

class APIKeySchema(BaseModel):
    api_key: str


class SSHAuthMethodsSchema(BaseModel):
    password_auth: bool
    pubkey_auth: bool
    permit_root_login: str
    permit_empty_passwords: bool
    new_password_for_user: Optional[Tuple[str, str]] = None


class SSHKeySchema(BaseModel):
    username: str
    public_key: str

class SSHKeysRequest(BaseModel):
    username: str