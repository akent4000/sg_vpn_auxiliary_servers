from loguru import logger
import sys
import os

# Путь к лог-файлу
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "bot.log")

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logger.remove()

# Лог в файл
logger.add(
    LOG_FILE,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} - {message}",
    level="DEBUG",
    rotation="10 MB",
    compression="zip",
)

# Лог в консоль с цветами
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
           "<level>{level: <8}</level> | "
           "<cyan>{name}:{function}:{line}</cyan> - "
           "<level>{message}</level>",
    level="DEBUG",
    colorize=True,  # Принудительное включение цветов
    backtrace=True,
    diagnose=True,
)


def get_logger():
    return logger
