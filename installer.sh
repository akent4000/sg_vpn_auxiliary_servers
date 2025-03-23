#!/bin/bash
set -e

# Function to display messages in color
function info() {
    echo -e "\e[32m[INFO]\e[0m $1"
}
function error() {
    echo -e "\e[31m[ERROR]\e[0m $1"
}

########################################
# 0. System update
########################################
info "Updating package list and installing updates..."
sudo apt update && sudo apt upgrade -y

########################################
# 1. Cloning the repository
########################################
REPO_URL="https://github.com/akent4000/sg_vpn_auxiliary_servers.git"
INSTALL_DIR="/opt/sg_vpn_auxiliary_servers"
info "Cloning repository ${REPO_URL} into ${INSTALL_DIR}..."
if [ -d "$INSTALL_DIR" ]; then
    info "Directory already exists, performing update..."
    cd "$INSTALL_DIR"
    git pull
else
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

########################################
# 2. Input parameters and API key validation
########################################

# 2.1 Request API key and new server name from the user
read -p "Enter API key: " API_KEY
read -p "Enter new server name: " SERVER_NAME

# 2.2 Get IP address from the main server
while true; do
    info "Validating API key and obtaining IP address..."
    # Send GET request with API key in the header
    IP_RESPONSE=$(curl -s -H "Authorization: ${API_KEY}" https://silkgroup.su/api/get_ip/)
    # Expected response format: {"ip": "91.197.0.34"}
    SERVER_IP=$(echo "$IP_RESPONSE" | grep -oP '(?<="ip": ")[^"]+')
    if [ -z "$SERVER_IP" ]; then
        error "Failed to obtain IP address. Possibly incorrect API key."
        read -p "Enter API key again: " API_KEY
    else
        info "Obtained IP address: $SERVER_IP"
        break
    fi
done

# Save the API key as a JSON array in api_tokens.json
echo "[\"${API_KEY}\"]" > "$INSTALL_DIR/api_tokens.json"

echo "API key saved to file api_tokens.json"

# 2.3 Generate a self-signed SSL certificate
info "Generating self-signed SSL certificate..."
SSL_DIR="/opt/ssl"
sudo mkdir -p "$SSL_DIR"
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -subj "/C=RU/ST=Moscow/L=Moscow/O=MyCompany/OU=IT/CN=${SERVER_IP}" \
    -keyout "$SSL_DIR/privkey.pem" -out "$SSL_DIR/fullchain.pem"
info "SSL certificates generated and saved in ${SSL_DIR}"

########################################
# 3. Main installation process
########################################

########################################
# 3.1 Install Python and set up virtual environment
########################################
info "Installing Python3, python3-venv and pip..."
sudo apt install -y python3 python3-venv python3-pip

info "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
info "Installing Python dependencies from requirements.txt..."
pip install --break-system-packages -r requirements.txt

########################################
# 3.2 Install and configure nginx
########################################
info "Installing nginx..."
sudo apt install -y nginx

info "Configuring nginx..."
# 3.2.1 Replace {server_ip} in nginx.conf with the actual IP
sed -i "s/{server_ip}/${SERVER_IP}/g" nginx.conf

# 3.2.2 Replace system's nginx.conf file
sudo cp nginx.conf /etc/nginx/nginx.conf

# 3.2.3 Add nginx to autostart and restart
sudo systemctl enable nginx
sudo systemctl restart nginx

########################################
# 3.3 Install WireGuard
########################################
info "Configuring WireGuard..."
sudo chmod +x wireguard-install.sh

info "Starting the first phase of wireguard-install.sh (automatically sending Enter for all prompts)..."
# Send 5 empty lines to simulate pressing Enter for each prompt:
sudo ./wireguard-install.sh <<EOF
       
       
       
       
       
EOF

info "First phase completed. Starting second phase for client removal..."
# Automate input for the second phase:
sudo ./wireguard-install.sh <<EOF
2
1
y
EOF

########################################
# 3.4 Create systemd service for FastAPI
########################################
SERVICE_FILE="/etc/systemd/system/fastapi.service"
info "Configuring systemd service for FastAPI..."
sudo bash -c "cat <<EOL > \"$SERVICE_FILE\"
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
EOL"

sudo systemctl daemon-reload
sudo systemctl enable fastapi

########################################
# 3.5 Start nginx and FastAPI services
########################################
info "Starting nginx and FastAPI services..."
sudo systemctl restart nginx
sudo systemctl start fastapi

########################################
# 3.6 Register the server (POST request)
########################################
info "Registering server with the main server..."
REGISTER_RESPONSE=$(curl -s -X POST https://silkgroup.su/api/register_server/ \
    -H "Authorization: ${API_KEY}" \
    -F "name=${SERVER_NAME}" \
    -F "ssl_certificate=@${SSL_DIR}/fullchain.pem")

info "Response from the main server:"
echo "$REGISTER_RESPONSE"

########################################
# 3.7 Automatically enable root login
########################################
info "Enabling root login..."
sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sudo systemctl reload sshd
info "Root login enabled."

info "Installation completed."
