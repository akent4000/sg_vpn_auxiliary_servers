﻿import os
import subprocess
import pwd
import glob
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
        It searches for the option in the main configuration file as well as in the included files
        specified by the Include directive.
        """
        found = False

        # Read the main configuration file
        try:
            with open(self.sshd_config_path, 'r') as f:
                main_lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading configuration file {self.sshd_config_path}: {e}")
            return

        new_main_lines = []
        for line in main_lines:
            if line.strip().startswith(option):
                new_main_lines.append(f"{option} {value}\n")
                found = True
            else:
                new_main_lines.append(line)

        # Search for Include directives and update the found files
        include_files = []
        for line in main_lines:
            stripped = line.strip()
            if stripped.startswith("Include"):
                parts = stripped.split()
                if len(parts) >= 2:
                    pattern = parts[1]
                    # Expand pattern, e.g., /etc/ssh/sshd_config.d/*.conf
                    include_files.extend(glob.glob(pattern))
        for inc_file in include_files:
            try:
                with open(inc_file, 'r') as f:
                    inc_lines = f.readlines()
            except Exception as e:
                logger.error(f"Error reading file {inc_file}: {e}")
                continue
            new_inc_lines = []
            updated = False
            for line in inc_lines:
                if line.strip().startswith(option):
                    new_inc_lines.append(f"{option} {value}\n")
                    found = True
                    updated = True
                else:
                    new_inc_lines.append(line)
            if updated:
                try:
                    with open(inc_file, 'w') as f:
                        f.writelines(new_inc_lines)
                    logger.info(f"Option {option} updated in {inc_file} with value: {value}")
                except Exception as e:
                    logger.error(f"Error writing file {inc_file}: {e}")

        # If the option was not found in either the main file or included files, add it to the end of the main file
        if not found:
            new_main_lines.append(f"\n{option} {value}\n")

        try:
            with open(self.sshd_config_path, 'w') as f:
                f.writelines(new_main_lines)
            logger.info(f"Option {option} set to: {value} in the main file {self.sshd_config_path}")
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
        Reloads the SSH service to apply configuration changes.
        """
        try:
            subprocess.check_call(['systemctl', 'reload', 'sshd'])
            logger.info("SSH service reloaded successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error reloading SSH service: {e}")

    def add_ssh_key(self, username: str, public_key: str):
        """
        Adds a public SSH key to the specified user's authorized_keys file.
        If the .ssh directory or the authorized_keys file does not exist, they will be created.
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
            logger.info("Key is already added.")
        else:
            with open(auth_keys, 'a') as f:
                f.write(public_key.strip() + "\n")
            logger.info("Key added successfully.")
            self.reload_ssh_service()

    def remove_ssh_key(self, username: str, public_key: str):
        """
        Removes the specified public SSH key from the user's authorized_keys file.
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
            logger.info("The specified key was not found in authorized_keys.")
        else:
            with open(auth_keys, 'w') as f:
                f.write("\n".join(new_keys) + "\n")
            logger.info("Key removed successfully.")
            self.reload_ssh_service()

    def get_ssh_keys(self, username: str):
        """
        Returns a list of all SSH keys for the specified user, read from the authorized_keys file.
        If the file or the .ssh directory does not exist, an empty list is returned.
        """
        try:
            user_info = pwd.getpwnam(username)
        except KeyError:
            logger.error(f"User {username} not found.")
            return []

        auth_keys_path = os.path.join(user_info.pw_dir, '.ssh', 'authorized_keys')

        if not os.path.exists(auth_keys_path):
            logger.info("authorized_keys file not found.")
            return []

        try:
            with open(auth_keys_path, 'r') as f:
                keys = [line.strip() for line in f if line.strip()]
            logger.info(f"Found {len(keys)} SSH key(s) for user {username}.")
            return keys
        except Exception as e:
            logger.error(f"Error reading file {auth_keys_path}: {e}")
            return []
