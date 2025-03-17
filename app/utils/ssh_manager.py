import os
import subprocess
import pwd
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ��������� �����������
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
        ��������� (��� ���������, ���� �� �������) ����� � ����� ������������ SSH.
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
            logger.error(f"������ ������ ����� ������������ {self.sshd_config_path}: {e}")
            return

        if not found:
            lines.append(f"\n{option} {value}\n")
        try:
            with open(self.sshd_config_path, 'w') as f:
                f.writelines(lines)
            logger.info(f"����� {option} ����������� � ��������: {value}")
        except Exception as e:
            logger.error(f"������ ������ ����� ������������ {self.sshd_config_path}: {e}")

    def set_password_auth(self, enable: bool):
        """
        ��������� (True) ��� ��������� (False) �������������� �� ������.
        """
        value = 'yes' if enable else 'no'
        self._update_config_option("PasswordAuthentication", value)
        self.reload_ssh_service()

    def set_pubkey_auth(self, enable: bool):
        """
        �������� (True) ��� ��������� (False) �������������� �� SSH-�����.
        """
        value = 'yes' if enable else 'no'
        self._update_config_option("PubkeyAuthentication", value)
        self.reload_ssh_service()

    def reload_ssh_service(self):
        """
        ������������� SSH-������ ��� ���������� ���������.
        """
        try:
            subprocess.check_call(['systemctl', 'reload', 'sshd'])
            logger.info("SSH-������ ������� ������������.")
        except subprocess.CalledProcessError as e:
            logger.error(f"������ ��� ������������ SSH-�������: {e}")

    def add_ssh_key(self, username: str, public_key: str):
        """
        ��������� ��������� SSH-���� � ���� authorized_keys ���������� ������������.
        ���� ���� ��� ������� .ssh �� ����������, ��� ����� �������.
        """
        try:
            user_info = pwd.getpwnam(username)
        except KeyError:
            logger.error(f"������������ {username} �� ������.")
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
            logger.info("���� ��� ��������.")
        else:
            with open(auth_keys, 'a') as f:
                f.write(public_key.strip() + "\n")
            logger.info("���� ������� ��������.")

    def remove_ssh_key(self, username: str, public_key: str):
        """
        ������� ��������� SSH-���� �� ����� authorized_keys ���������� ������������.
        """
        try:
            user_info = pwd.getpwnam(username)
        except KeyError:
            logger.error(f"������������ {username} �� ������.")
            return

        home_dir = user_info.pw_dir
        auth_keys = os.path.join(home_dir, '.ssh', 'authorized_keys')

        if not os.path.exists(auth_keys):
            logger.info("���� authorized_keys �� ������.")
            return

        with open(auth_keys, 'r') as f:
            keys = f.read().splitlines()

        new_keys = [k for k in keys if k.strip() != public_key.strip()]

        if len(new_keys) == len(keys):
            logger.info("��������� ���� �� ������ � authorized_keys.")
        else:
            with open(auth_keys, 'w') as f:
                f.write("\n".join(new_keys) + "\n")
            logger.info("���� ������� �����.")

    def generate_ssh_key(self, key_path: str, comment: str = "", passphrase: str = "", key_type: str = "rsa", bits: int = 2048):
        """
        ���������� SSH ����� (��������� � ���������) � �������������� ���������� cryptography.
        
        :param key_path: ���� ��� ���������� ���������� ����� (��������, /home/user/.ssh/id_rsa).
        :param comment: ����������� � �����, ������� ����� �������� � ��������� ����.
        :param passphrase: ������ ��� ������ ���������� �����. ���� ������ ������, ������������ NoEncryption.
        :param key_type: ��� ����� ('rsa' ��� 'ed25519'). �� ��������� 'rsa'.
        :param bits: ������ ����� ��� RSA. �� ������������ ��� ed25519.
        """
        try:
            if key_type.lower() == 'rsa':
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=bits,
                    backend=default_backend()
                )
            elif key_type.lower() == 'ed25519':
                private_key = ed25519.Ed25519PrivateKey.generate()
            else:
                raise ValueError("Unsupported key type. Use 'rsa' or 'ed25519'.")

            if passphrase:
                encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode())
            else:
                encryption_algorithm = serialization.NoEncryption()

            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption_algorithm
            )

            with open(key_path, "wb") as f:
                f.write(private_bytes)
            os.chmod(key_path, 0o600)
            logger.info(f"��������� ���� ������� �� ����: {key_path}")

            public_key = private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            )
            public_key_str = public_bytes.decode('utf-8')
            if comment:
                public_key_str += " " + comment

            pub_key_path = key_path + ".pub"
            with open(pub_key_path, "w") as f:
                f.write(public_key_str)
            os.chmod(pub_key_path, 0o644)
            logger.info(f"��������� ���� ������� �� ����: {pub_key_path}")
        except Exception as e:
            logger.error(f"������ ��� ��������� SSH �����: {e}")