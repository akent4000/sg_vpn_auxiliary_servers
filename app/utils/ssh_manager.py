import os
import subprocess
import pwd
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)


class SSHAccessManager:
    def __init__(self, sshd_config_path='/etc/ssh/sshd_config'):
        self.sshd_config_path = sshd_config_path

    def _update_config_option(self, option, value):
        """
        Updates (or adds, if not found) an option in the SSH configuration file.
        """
        found = False
        lines = []
        try:
            with open(self.sshd_config_path, 'r') as f:
                for line in f:
                    if line.strip().startswith(option):
                        lines.append(f"{option} {value}\n")
                        found = True
                    else:
                        lines.append(line)
        except Exception as e:
            logger.error(f"Error reading configuration file {self.sshd_config_path}: {e}")
            return

        if not found:
            lines.append(f"\n{option} {value}\n")
        try:
            with open(self.sshd_config_path, 'w') as f:
                f.writelines(lines)
            logger.info(f"Option {option} set to value: {value}")
        except Exception as e:
            logger.error(f"Error writing configuration file {self.sshd_config_path}: {e}")

    def set_password_auth(self, enable: bool):
        """
        Enables (True) or disables (False) password authentication.
        """
        value = 'yes' if enable else 'no'
        self._update_config_option("PasswordAuthentication", value)
        self.reload_ssh_service()

    def set_pubkey_auth(self, enable: bool):
        """
        Enables (True) or disables (False) SSH key authentication.
        """
        value = 'yes' if enable else 'no'
        self._update_config_option("PubkeyAuthentication", value)
        self.reload_ssh_service()

    def reload_ssh_service(self):
        """
        Reloads the SSH service to apply changes.
        """
        try:
            subprocess.check_call(['systemctl', 'reload', 'sshd'])
            logger.info("SSH service reloaded successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error reloading SSH service: {e}")

    def add_ssh_key(self, username: str, public_key: str):
        """
        Adds a public SSH key to the authorized_keys file of the specified user.
        If the file or .ssh directory does not exist, they will be created.
        """
        try:
            user_info = pwd.getpwnam(username)
        except KeyError:
            logger.error(f"User {username} not found.")
            return

        home_dir = user_info.pw_dir
        ssh_dir = os.path.join(home_dir, '.ssh')
        auth_keys = os.path.join(ssh_dir, 'authorized_keys')

        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)

        if not os.path.exists(auth_keys):
            open(auth_keys, 'a').close()
            os.chmod(auth_keys, 0o600)

        with open(auth_keys, 'r') as f:
            keys = f.read().splitlines()

        if public_key.strip() in keys:
            logger.info("Key already added.")
        else:
            with open(auth_keys, 'a') as f:
                f.write(public_key.strip() + "\n")
            logger.info("Key successfully added.")

    def remove_ssh_key(self, username: str, public_key: str):
        """
        Removes a public SSH key from the authorized_keys file of the specified user.
        """
        try:
            user_info = pwd.getpwnam(username)
        except KeyError:
            logger.error(f"User {username} not found.")
            return

        home_dir = user_info.pw_dir
        auth_keys = os.path.join(home_dir, '.ssh', 'authorized_keys')

        if not os.path.exists(auth_keys):
            logger.info("authorized_keys file not found.")
            return

        with open(auth_keys, 'r') as f:
            keys = f.read().splitlines()

        new_keys = [k for k in keys if k.strip() != public_key.strip()]

        if len(new_keys) == len(keys):
            logger.info("Specified key not found in authorized_keys.")
        else:
            with open(auth_keys, 'w') as f:
                f.write("\n".join(new_keys) + "\n")
            logger.info("Key successfully removed.")
