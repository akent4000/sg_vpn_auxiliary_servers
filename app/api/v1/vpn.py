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
from app.utils.ssh_manager import SSHAccessManager
from logger_setup import logger

app = FastAPI()
router = APIRouter()

# Path to the file where API tokens will be stored
API_TOKEN_FILE = "api_tokens.json"

def load_api_tokens() -> list:
    '''
    Loads the list of API tokens from a file.
    If the file does not exist or the data is incorrect, returns an empty list.
    '''
    try:
        with open(API_TOKEN_FILE, "r") as f:
            tokens = json.load(f)
            if not isinstance(tokens, list):
                tokens = []
    except FileNotFoundError:
        tokens = []
    return tokens

def save_api_tokens(tokens: list) -> None:
    '''
    Saves the list of API tokens to a file.
    '''
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
    '''
    Verifies that the provided token is present in the list of tokens loaded from the file.
    '''
    tokens = load_api_tokens()
    if not auth_token or auth_token not in tokens:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token"
        )

# Endpoints for VPN (WireGuard) management
@router.get("/get-vpn-list", response_model=list[VPNConfigResponse], tags=["VPN"], summary="Returns a list of VPN configurations")
async def get_vpn_list(token: str = Depends(verify_token)):
    wg_manager = WireGuardManager()
    wg_clients = wg_manager.get_clients_list()
    return JSONResponse(
        status_code=200,
        content=wg_clients,
    )

@router.post("/create-vpn", response_model=VPNCreateResponseSchema, tags=["VPN"], summary="Create a new config")
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

@router.post("/delete", response_model=List[VPNRemoveSchema], tags=["VPN"], summary="Delete configurations")
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

@router.get("/get-peers-info", response_model=list[VPNConfigResponse], tags=["VPN"], summary="Returns information about peers")
async def get_peers_info(token: str = Depends(verify_token)):
    wg_manager = WireGuardManager()
    peers = wg_manager.get_peers_info()
    return JSONResponse(
        status_code=200,
        content=peers,
    )

@router.post("/add-api-key", tags=["API Keys"], summary="Add a new API key")
async def add_api_key(api_key: APIKeySchema, token: str = Depends(verify_token)):
    tokens = load_api_tokens()
    if api_key.api_key in tokens:
        return JSONResponse(
            status_code=200,
            content={"message": "API key already exists", "api_tokens": tokens}
        )
    tokens.append(api_key.api_key)
    save_api_tokens(tokens)
    return JSONResponse(
        status_code=200,
        content={"message": "API key successfully added", "api_tokens": tokens}
    )

@router.delete("/delete-api-key", tags=["API Keys"], summary="Delete API key")
async def delete_api_key(api_key: APIKeySchema, token: str = Depends(verify_token)):
    tokens = load_api_tokens()
    if api_key.api_key not in tokens:
        raise HTTPException(status_code=404, detail="API key not found")
    tokens.remove(api_key.api_key)
    save_api_tokens(tokens)
    return JSONResponse(
        status_code=200,
        content={"message": "API key successfully deleted", "api_tokens": tokens}
    )


# New Pydantic schemas for managing SSH access


# Endpoint for change authentication methods
@router.post("/ssh/set-auth-methods", tags=["SSH"], summary="Set SSH authentication methods")
async def set_auth_methods(request_data: SSHAuthMethodsSchema, token: str = Depends(verify_token)):
    ssh_manager = SSHAccessManager()
    try:
        results = ssh_manager.set_auth_methods(
            password_auth=request_data.password_auth,
            pubkey_auth=request_data.pubkey_auth,
            permit_root_login=request_data.permit_root_login,
            permit_empty_passwords=request_data.permit_empty_passwords,
            new_password_for_user=request_data.new_password_for_user
        )
    except Exception as e:
        logger.error(f"Error updating SSH authentication settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to update SSH authentication settings.")
    
    # Check the result dictionary for any errors.
    error_messages = []
    for key, result in results.items():
        if isinstance(result, str) and result.startswith("error"):
            error_messages.append(f"{key}: {result}")
    
    if error_messages:
        error_detail = " ".join(error_messages)
        logger.error(error_detail)
        raise HTTPException(status_code=500, detail=error_detail)
    
    message = (
        f"Password authentication {'enabled' if request_data.password_auth else 'disabled'}, "
        f"SSH key authentication {'enabled' if request_data.pubkey_auth else 'disabled'}, "
        f"PermitRootLogin set to {request_data.permit_root_login}, "
        f"PermitEmptyPasswords {'enabled' if request_data.permit_empty_passwords else 'disabled'}."
    )
    if request_data.new_password_for_user:
        user, _ = request_data.new_password_for_user
        message += f" Password for user {user} updated."
    
    logger.info(message)
    return JSONResponse(
        status_code=200,
        content={"message": message}
    )

# Endpoint for adding an SSH key
@router.post("/ssh/add-key", tags=["SSH"], summary="Add SSH key")
async def add_ssh_key(request_data: SSHKeySchema, token: str = Depends(verify_token)):
    ssh_manager = SSHAccessManager()
    ssh_manager.add_ssh_key(request_data.username, request_data.public_key)
    message = f"SSH key for user {request_data.username} successfully added."
    logger.info(message)
    return JSONResponse(
        status_code=200,
        content={"message": message}
    )

# Endpoint for removing an SSH key
@router.post("/ssh/remove-key", tags=["SSH"], summary="Remove SSH key")
async def remove_ssh_key(request_data: SSHKeySchema, token: str = Depends(verify_token)):
    ssh_manager = SSHAccessManager()
    ssh_manager.remove_ssh_key(request_data.username, request_data.public_key)
    message = f"SSH key for user {request_data.username} successfully removed."
    logger.info(message)
    return JSONResponse(
        status_code=200,
        content={"message": message}
    )

@router.post("/ssh/get-keys", tags=["SSH"], summary="Retrieve SSH keys for a user")
async def get_ssh_keys(request: SSHKeysRequest, token: str = Depends(verify_token)):
    ssh_manager = SSHAccessManager()
    keys = ssh_manager.get_ssh_keys(request.username)
    return JSONResponse(
        status_code=200,
        content={"username": request.username, "keys": keys}
    )

# Register the router with the application
app.include_router(router)
