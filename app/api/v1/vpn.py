import time
from typing import List
from fastapi import APIRouter, Depends, Header, HTTPException, FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.status import HTTP_401_UNAUTHORIZED
import os
import json
from pydantic import BaseModel

from app.schemas.schemas_config import *
from app.utils.wg_manager import WireGuardManager
from app.utils.ssh_manager import SSHAccessManager  # Предполагается, что этот класс реализован
from logger_setup import logger

app = FastAPI()
router = APIRouter()

# Путь к файлу, в котором будут храниться API токены
API_TOKEN_FILE = "api_tokens.json"

def load_api_tokens() -> list:
    """
    Загружает список API токенов из файла.
    Если файл не существует или данные некорректны, возвращает пустой список.
    """
    try:
        with open(API_TOKEN_FILE, "r") as f:
            tokens = json.load(f)
            if not isinstance(tokens, list):
                tokens = []
    except FileNotFoundError:
        tokens = []
    return tokens

def save_api_tokens(tokens: list) -> None:
    """
    Сохраняет список API токенов в файл.
    """
    with open(API_TOKEN_FILE, "w") as f:
        json.dump(tokens, f)

class ClientExistsException(Exception):
    def __init__(self, name: str):
        self.name = name

@app.exception_handler(ClientExistsException)
async def client_exists_exception_handler(request: Request, exc: ClientExistsException):
    return JSONResponse(
        status_code=400,
        content={"message": f"Config for client {exc.name} already exists."},
    )

def verify_token(auth_token: str = Header(..., alias="Authorization")):
    """
    Проверяет, что переданный токен присутствует в списке токенов, загруженном из файла.
    """
    tokens = load_api_tokens()
    if not auth_token or auth_token not in tokens:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token"
        )

# Эндпоинты для управления VPN (WireGuard)
@router.get("/get-vpn-list", response_model=list[VPNConfigResponse], tags=["VPN"], summary="Возвращает список VPN-конфигураций")
async def get_vpn_list(token: str = Depends(verify_token)):
    wg_manager = WireGuardManager()
    wg_clients = wg_manager.get_clients_list()
    return JSONResponse(
        status_code=200,
        content=wg_clients,
    )

@router.post("/create-vpn", response_model=VPNCreateResponseSchema, tags=["VPN"], summary="Создание нового конфига")
async def create_vpn(token: str = Depends(verify_token)):
    config_name = f"{int(time.time())}"
    wg_manager = WireGuardManager()
    try:
        result = wg_manager.new_client_setup(config_name)
    except Exception as e:
        raise ClientExistsException(name=config_name)
    return JSONResponse(
        status_code=200,
        content={
            "config_name": config_name,
            "config": result,
        }
    )

@router.post("/delete", response_model=List[VPNRemoveSchema], tags=["VPN"], summary="Удаление конфигов")
async def post_delete_vpn(data: List[VPNListSchema], token: str = Depends(verify_token)):
    result = []
    logger.info(f"{data=}")
    for item in data:
        config_name = item.config_name
        logger.info(f"Deleting config: {config_name}")
        wg_manager = WireGuardManager()
        status = None
        msg = ""
        try:
            result_remove_config = wg_manager.remove_client(config_name)
            if result_remove_config is True:
                status = True
                msg = "OK"
            elif result_remove_config == "NOT_FOUND":
                status = True
                msg = "NOT_FOUND"
        except Exception as e:
            status = False
            msg = str(e)
        result.append({
            "config_name": config_name,
            "status": status,
            "msg": msg
        })
    return JSONResponse(
        status_code=200,
        content=result,
    )

@router.get("/get-peers-info", response_model=list[VPNConfigResponse], tags=["VPN"], summary="Возвращает информацию о пирах")
async def get_peers_info(token: str = Depends(verify_token)):
    wg_manager = WireGuardManager()
    peers = wg_manager.get_peers_info()
    return JSONResponse(
        status_code=200,
        content=peers,
    )

@router.post("/add-api-key", tags=["API Keys"], summary="Добавить новый API ключ")
async def add_api_key(api_key: APIKeySchema, token: str = Depends(verify_token)):
    tokens = load_api_tokens()
    if api_key.api_key in tokens:
        return JSONResponse(
            status_code=200,
            content={"message": "API ключ уже существует", "api_tokens": tokens}
        )
    tokens.append(api_key.api_key)
    save_api_tokens(tokens)
    return JSONResponse(
        status_code=200,
        content={"message": "API ключ успешно добавлен", "api_tokens": tokens}
    )

@router.delete("/delete-api-key", tags=["API Keys"], summary="Удалить API ключ")
async def delete_api_key(api_key: APIKeySchema, token: str = Depends(verify_token)):
    tokens = load_api_tokens()
    if api_key.api_key not in tokens:
        raise HTTPException(status_code=404, detail="API ключ не найден")
    tokens.remove(api_key.api_key)
    save_api_tokens(tokens)
    return JSONResponse(
        status_code=200,
        content={"message": "API ключ успешно удален", "api_tokens": tokens}
    )


# Новые Pydantic-схемы для управления SSH доступом


# Эндпоинт для включения/выключения доступа по паролю
@router.post("/ssh/set-password-auth", tags=["SSH"], summary="Включение/выключение доступа по паролю")
async def set_password_auth(request_data: SSHAuthToggleSchema, token: str = Depends(verify_token)):
    ssh_manager = SSHAccessManager()
    ssh_manager.set_password_auth(request_data.enable)
    message = "Доступ по паролю включён." if request_data.enable else "Доступ по паролю выключен."
    logger.info(message)
    return JSONResponse(
        status_code=200,
        content={"message": message}
    )

# Эндпоинт для включения/выключения доступа по SSH ключу
@router.post("/ssh/set-pubkey-auth", tags=["SSH"], summary="Включение/выключения доступа по SSH ключу")
async def set_pubkey_auth(request_data: SSHAuthToggleSchema, token: str = Depends(verify_token)):
    ssh_manager = SSHAccessManager()
    ssh_manager.set_pubkey_auth(request_data.enable)
    message = "Доступ по SSH ключу включён." if request_data.enable else "Доступ по SSH ключу выключен."
    logger.info(message)
    return JSONResponse(
        status_code=200,
        content={"message": message}
    )

# Эндпоинт для добавления SSH ключа
@router.post("/ssh/add-key", tags=["SSH"], summary="Добавление SSH ключа")
async def add_ssh_key(request_data: SSHKeySchema, token: str = Depends(verify_token)):
    ssh_manager = SSHAccessManager()
    ssh_manager.add_ssh_key(request_data.username, request_data.public_key)
    message = f"SSH ключ для пользователя {request_data.username} успешно добавлен."
    logger.info(message)
    return JSONResponse(
        status_code=200,
        content={"message": message}
    )

# Эндпоинт для удаления SSH ключа
@router.post("/ssh/remove-key", tags=["SSH"], summary="Удаление SSH ключа")
async def remove_ssh_key(request_data: SSHKeySchema, token: str = Depends(verify_token)):
    ssh_manager = SSHAccessManager()
    ssh_manager.remove_ssh_key(request_data.username, request_data.public_key)
    message = f"SSH ключ для пользователя {request_data.username} успешно удалён."
    logger.info(message)
    return JSONResponse(
        status_code=200,
        content={"message": message}
    )

@router.get("/ssh/get-keys", tags=["SSH"], summary="Получение SSH ключей для пользователя")
async def get_ssh_keys(username: str, token: str = Depends(verify_token)):
    ssh_manager = SSHAccessManager()
    keys = ssh_manager.get_ssh_keys(username)
    return JSONResponse(
        status_code=200,
        content={"username": username, "keys": keys}
    )

# Регистрация роутера в приложении
app.include_router(router)
