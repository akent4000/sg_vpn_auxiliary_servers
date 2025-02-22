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

@router.get("/get-vpn-list", response_model=list[VPNConfigResponse], tags=["VPN"], summary="Возвращает список VPN-конфигураций")
async def get_vpn_list(token: str = Depends(verify_token)):
    """
    Возвращает список VPN-конфигураций.
    """
    wg_manager = WireGuardManager()
    wg_clients = wg_manager.get_clients_list()
    return JSONResponse(
        status_code=200,
        content=wg_clients,
    )

@router.post("/create-vpn/", response_model=VPNCreateResponseSchema, tags=["VPN"], summary="Создание нового конфига")
async def create_vpn(token: str = Depends(verify_token)):
    config_name = f"{int(time.time())}"
    wg_manager = WireGuardManager()
    try:
        result = wg_manager.new_client_setup(config_name)
    except Exception as e:
        raise ClientExistsException(name=config_name)
    return VPNCreateResponseSchema(
        config_name=config_name,
        config=result,
    )

@router.post("/delete", response_model=List[VPNRemoveSchema], tags=["VPN"], summary="Удаление конфигов")
async def post_delete_vpn(data: List[VPNListSchema], token: str = Depends(verify_token)):
    """Удаление конфигов."""
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
        result.append(VPNRemoveSchema(
            config_name=config_name,
            status=status,
            msg=msg
        ))
    return result

@router.get("/get-peers-info", response_model=list[VPNConfigResponse], tags=["VPN"], summary="Возвращает информацию о пирах")
async def get_peers_info(token: str = Depends(verify_token)):
    """
    Возвращает информацию о пирах.
    """
    wg_manager = WireGuardManager()
    peers = wg_manager.get_peers_info()
    return JSONResponse(
        status_code=200,
        content=peers,
    )



@router.post("/add-api-key", tags=["API Keys"], summary="Добавить новый API ключ")
async def add_api_key(api_key: APIKeySchema, token: str = Depends(verify_token)):
    """
    Добавляет новый API ключ в список и сохраняет изменения в файл.
    """
    tokens = load_api_tokens()
    if api_key.api_key in tokens:
        return {"message": "API ключ уже существует", "api_tokens": tokens}
    tokens.append(api_key.api_key)
    save_api_tokens(tokens)
    return {"message": "API ключ успешно добавлен", "api_tokens": tokens}

@router.delete("/delete-api-key", tags=["API Keys"], summary="Удалить API ключ")
async def delete_api_key(api_key: APIKeySchema, token: str = Depends(verify_token)):
    """
    Удаляет указанный API ключ из списка и сохраняет изменения в файл.
    """
    tokens = load_api_tokens()
    if api_key.api_key not in tokens:
        raise HTTPException(status_code=404, detail="API ключ не найден")
    tokens.remove(api_key.api_key)
    save_api_tokens(tokens)
    return {"message": "API ключ успешно удален", "api_tokens": tokens}
