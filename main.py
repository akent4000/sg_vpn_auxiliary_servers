from fastapi import FastAPI
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import logger_setup
from app.api.v1.vpn import router

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Контекстный менеджер для обработки событий старта и завершения приложения."""
    logger_setup.logger.info("Приложение успешно запущено.")
    yield
    logger_setup.logger.info("Приложение завершено.")

app = FastAPI(lifespan=lifespan)

# Подключение маршрутов
app.include_router(router, prefix="/vpn", tags=["VPN Config"])