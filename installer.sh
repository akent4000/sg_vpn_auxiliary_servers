#!/bin/bash
set -e

# Функция для вывода сообщений с цветом
function info() {
    echo -e "\e[32m[INFO]\e[0m $1"
}
function error() {
    echo -e "\e[31m[ERROR]\e[0m $1"
}

########################################
# 0. Обновление системы
########################################
info "Обновление списка пакетов и установка обновлений..."
apt update && apt upgrade -y

########################################
# 1. Клонирование репозитория
########################################
REPO_URL="https://github.com/akent4000/sg_vpn_auxiliary_servers.git"
INSTALL_DIR="/root/sg_vpn_auxiliary_servers"
info "Клонирование репозитория ${REPO_URL} в ${INSTALL_DIR}..."
if [ -d "$INSTALL_DIR" ]; then
    info "Директория уже существует, выполняется обновление..."
    cd "$INSTALL_DIR"
    git pull
else
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

########################################
# 2. Ввод параметров и проверка API ключа
########################################

# 2.1 Запрос у пользователя API ключа и нового имени сервера
read -p "Введите API ключ: " API_KEY
read -p "Введите новое имя сервера: " SERVER_NAME

# 2.2 Получение IP адреса с основного сервера
while true; do
    info "Проверка API ключа и получение IP адреса..."
    # Отправляем GET запрос, добавляя API ключ в заголовок
    IP_RESPONSE=$(curl -s -H "Authorization: ${API_KEY}" https://silkgroup.su/api/get_ip/)
    # Предполагается, что ответ имеет формат {"ip": "91.197.0.34"}
    SERVER_IP=$(echo "$IP_RESPONSE" | grep -oP '(?<="ip": ")[^"]+')
    if [ -z "$SERVER_IP" ]; then
        error "Не удалось получить IP адрес. Возможно, неверный API ключ."
        read -p "Введите API ключ повторно: " API_KEY
    else
        info "Получен IP адрес: $SERVER_IP"
        break
    fi
done

# Записываем введённый API ключ в файл api_tokens.json в виде JSON-массива
echo "[\"${API_KEY}\"]" > "$INSTALL_DIR/api_tokens.json"

# Выводим сообщение об успешном сохранении
echo "API ключ сохранён в файл api_tokens.json"

# 2.3 Генерация самоподписанного SSL сертификата
info "Генерация самоподписанного SSL сертификата..."
SSL_DIR="/root/ssl"
mkdir -p "$SSL_DIR"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -subj "/C=RU/ST=Moscow/L=Moscow/O=MyCompany/OU=IT/CN=${SERVER_IP}" \
    -keyout "$SSL_DIR/privkey.pem" -out "$SSL_DIR/fullchain.pem"
info "SSL сертификаты сгенерированы и сохранены в ${SSL_DIR}"

########################################
# 3. Основной процесс установки
########################################

########################################
# 3.1 Установка Python и настройка виртуального окружения
########################################
info "Установка Python3, python3-venv и pip..."
apt install -y python3 python3-venv python3-pip

info "Создание виртуального окружения..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
info "Установка Python зависимостей из requirements.txt..."
pip install -r requirements.txt

########################################
# 3.2 Установка и настройка nginx
########################################
info "Установка nginx..."
apt install -y nginx

info "Настройка nginx..."
# 3.2.1 Замена {server_ip} в файле nginx.conf на актуальный IP
sed -i "s/{server_ip}/${SERVER_IP}/g" nginx.conf

# 3.2.2 Замена системного файла nginx.conf
cp nginx.conf /etc/nginx/nginx.conf

# 3.2.3 Добавление nginx в автозапуск и перезапуск
systemctl enable nginx
systemctl restart nginx

########################################
# 3.3 Установка WireGuard
########################################
info "Настройка WireGuard..."
chmod +x wireguard-install.sh

info "Запуск первого этапа wireguard-install.sh (автоматически нажимаем Enter для всех запросов)..."
# Передаём 5 пустых строк, чтобы "нажать Enter" для каждого запроса:
sudo ./wireguard-install.sh <<EOF
       
       
       
       
       
EOF

info "Первый этап завершён. Запуск второго этапа для удаления клиента..."
# Автоматизация ввода для второго этапа:
sudo ./wireguard-install.sh <<EOF
2
1
y
EOF

########################################
# 3.4 Создание systemd-сервиса для FastAPI
########################################
SERVICE_FILE="/etc/systemd/system/fastapi.service"
info "Настройка systemd сервиса FastAPI..."
cat <<EOL > "$SERVICE_FILE"
[Unit]
Description=FastAPI Application
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable fastapi

########################################
# 3.5 Запуск сервисов nginx и fastapi
########################################
info "Запуск nginx и FastAPI..."
systemctl restart nginx
systemctl start fastapi

########################################
# 3.6 Регистрация сервера (POST запрос)
########################################
info "Регистрация сервера на основном сервере..."
REGISTER_RESPONSE=$(curl -s -X POST https://silkgroup.su/api/register_server/ \
    -H "Authorization: ${API_KEY}" \
    -F "name=${SERVER_NAME}" \
    -F "ssl_certificate=@${SSL_DIR}/fullchain.pem")

info "Ответ от основного сервера:"
echo "$REGISTER_RESPONSE"

info "Установка завершена."
