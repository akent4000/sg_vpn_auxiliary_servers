#!/usr/bin/env python3
import re
import subprocess
import logging
from pathlib import Path
from typing import List, Optional, Tuple

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

class WireGuardManager:
    WG_CONF_PATH = Path("/etc/wireguard/wg0.conf")
    WG_SERVICE = "wg-quick@wg0"

    def __init__(self) -> None:
        if not self.WG_CONF_PATH.exists():
            logger.error(f"Конфигурационный файл {self.WG_CONF_PATH} не найден.")
            raise FileNotFoundError(f"Конфигурационный файл {self.WG_CONF_PATH} не найден.")
        try:
            self.wg_conf = self.WG_CONF_PATH.read_text()
            logger.info(f"Конфигурация прочитана из {self.WG_CONF_PATH}")
        except Exception as e:
            logger.exception(f"Ошибка чтения конфигурационного файла {self.WG_CONF_PATH}: {e}")
            raise

    @staticmethod
    def run_command(cmd: List[str], input_data: Optional[bytes] = None) -> str:
        """
        Запускает команду и возвращает результат в виде строки.
        При ошибке выбрасывает исключение RuntimeError.
        """
        logger.debug(f"Выполнение команды: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, input=input_data, capture_output=True, check=True)
            output = result.stdout.decode().strip()
            logger.debug(f"Результат команды: {output}")
            return output
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode().strip() if e.stderr else ""
            logger.error(f"Команда {' '.join(cmd)} завершилась с ошибкой: {error_msg}")
            raise RuntimeError(f"Команда {' '.join(cmd)} завершилась с ошибкой: {error_msg}") from e

    def get_assigned_octets(self) -> set[int]:
        """Возвращает множество уже назначенных октетов из конфигурации сервера."""
        matches = re.findall(r"AllowedIPs\s*=\s*10\.7\.0\.(\d+)/32", self.wg_conf)
        assigned = {int(x) for x in matches}
        logger.debug(f"Назначенные октеты: {assigned}")
        return assigned

    @staticmethod
    def get_first_free_octet(assigned: set[int], start: int = 2, end: int = 254) -> int:
        """Возвращает первый свободный октет для клиента."""
        for octet in range(start, end + 1):
            if octet not in assigned:
                logger.debug(f"Найден свободный октет: {octet}")
                return octet
        logger.error("Внутренняя подсеть WireGuard заполнена: нет свободных октетов.")
        raise ValueError("Внутренняя подсеть WireGuard заполнена: нет свободных октетов.")

    def get_server_public_key(self) -> str:
        """
        Извлекает приватный ключ сервера из конфигурации и возвращает соответствующий публичный ключ.
        Если ключ не найден или произошла ошибка, возвращает 'UNKNOWN'.
        """
        match = re.search(r"PrivateKey\s*=\s*([\w+/=]+)", self.wg_conf)
        if match:
            server_priv = match.group(1)
            try:
                pub_key = self.run_command(["wg", "pubkey"], input_data=server_priv.encode())
                logger.debug(f"Публичный ключ сервера получен: {pub_key}")
                return pub_key
            except RuntimeError as e:
                logger.error(f"Ошибка при получении публичного ключа сервера: {e}")
                return "UNKNOWN"
        logger.warning("Приватный ключ сервера не найден в конфигурации.")
        return "UNKNOWN"

    @staticmethod
    def get_endpoint(conf: str) -> str:
        """
        Извлекает Endpoint из комментария в конфигурации (например, '# ENDPOINT <ip>').
        Если не найден, возвращает 'SERVER_IP'.
        """
        match = re.search(r"^# ENDPOINT\s+(\S+)", conf, re.MULTILINE)
        endpoint = match.group(1) if match else "SERVER_IP"
        logger.debug(f"Получен endpoint: {endpoint}")
        return endpoint

    @staticmethod
    def get_listen_port(conf: str) -> str:
        """
        Извлекает ListenPort из конфигурации.
        Если не найден, возвращает порт по умолчанию '51820'.
        """
        match = re.search(r"ListenPort\s+(\d+)", conf)
        port = match.group(1) if match else "51820"
        logger.debug(f"Получен порт прослушивания: {port}")
        return port

    @staticmethod
    def generate_client_keys() -> Tuple[str, str, str]:
        """
        Генерирует ключи для клиента:
          - приватный ключ (client_key),
          - предварительно разделённый ключ (psk),
          - публичный ключ (client_pub) на основе приватного.
        """
        try:
            client_key = WireGuardManager.run_command(["wg", "genkey"])
            psk = WireGuardManager.run_command(["wg", "genpsk"])
            client_pub = WireGuardManager.run_command(["wg", "pubkey"], input_data=client_key.encode())
            logger.info("Ключи для клиента успешно сгенерированы.")
            return client_key, psk, client_pub
        except RuntimeError as e:
            logger.exception("Ошибка при генерации ключей для клиента.")
            raise

    def update_server_config(self, new_content: str) -> None:
        """
        Записывает новое содержимое конфигурационного файла сервера.
        """
        try:
            with self.WG_CONF_PATH.open("w") as conf_file:
                conf_file.write(new_content)
            self.wg_conf = self.WG_CONF_PATH.read_text()
            logger.info(f"Конфигурация сервера обновлена в файле {self.WG_CONF_PATH}")
        except Exception as e:
            logger.exception(f"Ошибка при обновлении конфигурационного файла {self.WG_CONF_PATH}: {e}")
            raise

    def restart_wireguard(self) -> None:
        """
        Перезапускает сервис WireGuard.
        """
        try:
            self.run_command(["systemctl", "restart", self.WG_SERVICE])
            logger.info("Сервис WireGuard перезапущен.")
        except RuntimeError as e:
            logger.exception("Ошибка при перезапуске сервиса WireGuard.")
            raise

    def new_client_setup(self, client: str, dns: str = "8.8.8.8, 8.8.4.4") -> str:
        """
        Настраивает нового клиента WireGuard:
          - обновляет конфигурационный файл сервера wg0.conf,
          - перезапускает WireGuard,
          - возвращает текст конфигурации для клиента.
          
        :param client: Имя клиента (используется как метка в конфигурации).
        :param dns: DNS-сервер для клиента.
        :return: Текст конфигурации клиента.
        """
        logger.info(f"Начинается настройка нового клиента: {client}")
        try:
            # Определяем уже назначенные октеты и находим первый свободный
            assigned_octets = self.get_assigned_octets()
            octet = self.get_first_free_octet(assigned_octets)

            # Генерация ключей для клиента
            client_priv, psk, client_pub = self.generate_client_keys()

            # Определяем, используется ли IPv6
            has_ipv6 = bool(re.search(r"fddd:2c4:2c4:2c4::1", self.wg_conf))
            logger.debug(f"IPv6 {'используется' if has_ipv6 else 'не используется'}.")

            # Формирование AllowedIPs для блока Peer (на сервере)
            allowed_ips_peer = f"10.7.0.{octet}/32"
            if has_ipv6:
                allowed_ips_peer += f", fddd:2c4:2c4:2c4::{octet}/128"

            # Формирование блока для нового Peer
            peer_block = (
                f"# BEGIN_PEER {client}\n"
                "[Peer]\n"
                f"PublicKey = {client_pub}\n"
                f"PresharedKey = {psk}\n"
                f"AllowedIPs = {allowed_ips_peer}\n"
                f"# END_PEER {client}\n"
            )
            logger.debug("Новый блок Peer сформирован.")

            # Добавляем новый блок к существующей конфигурации сервера
            new_config = self.wg_conf.strip() + "\n" + peer_block + "\n"
            self.update_server_config(new_config)

            # Формирование адресов для клиента
            client_address = f"10.7.0.{octet}/24"
            if has_ipv6:
                client_address += f", fddd:2c4:2c4:2c4::{octet}/64"

            # Получение дополнительных параметров из конфигурации сервера
            server_pub = self.get_server_public_key()
            endpoint_ip = self.get_endpoint(self.wg_conf)
            listen_port = self.get_listen_port(self.wg_conf)

            # Формирование конфигурации для клиента
            client_config = (
                "[Interface]\n"
                f"Address = {client_address}\n"
                f"DNS = {dns}\n"
                f"PrivateKey = {client_priv}\n\n"
                "[Peer]\n"
                f"PublicKey = {server_pub}\n"
                f"PresharedKey = {psk}\n"
                "AllowedIPs = 0.0.0.0/0, ::/0\n"
                f"Endpoint = {endpoint_ip}:{listen_port}\n"
                "PersistentKeepalive = 25\n"
            )
            logger.info(f"Конфигурация для клиента {client} успешно сформирована.")

            # Перезапускаем WireGuard, чтобы изменения вступили в силу
            self.restart_wireguard()

            return client_config
        except Exception as e:
            logger.exception(f"Ошибка при настройке клиента {client}: {e}")
            raise

    def get_clients_list(self) -> List[str]:
        """
        Возвращает список имен клиентов, найденных в конфигурационном файле (по меткам BEGIN_PEER).
        """
        clients = re.findall(r"^# BEGIN_PEER\s+(.+)$", self.wg_conf, re.MULTILINE)
        logger.info(f"Найдено клиентов: {clients}")
        return clients

    def remove_client(self, client: str) -> bool | str:
        """
        Удаляет клиента WireGuard из live-интерфейса и из конфигурационного файла сервера.
        
        :param client: Имя клиента для удаления.
        :return True: Если клиент удален.
        :return ValueError: Если клиент не найден
        :return str: Если не удалось удалить, то текст ошибки
        """
        logger.info(f"Начинается удаление клиента: {client}")
        try:
            # Извлекаем блок клиента из конфигурации
            pattern = rf"^# BEGIN_PEER {re.escape(client)}$\n.*?\n# END_PEER {re.escape(client)}$\n?"
            match = re.search(pattern, self.wg_conf, re.DOTALL | re.MULTILINE)
            if not match:
                logger.error(f"Клиент {client} не найден в конфигурации.")
                return "NOT_FOUND"

            client_block = match.group(0)

            # Извлекаем публичный ключ клиента из блока
            pubkey_match = re.search(r"PublicKey\s*=\s*(\S+)", client_block)
            if pubkey_match:
                client_pub = pubkey_match.group(1)
                # Удаляем клиента из live-интерфейса
                self.run_command(["wg", "set", "wg0", "peer", client_pub, "remove"])
                logger.info(f"Клиент {client} успешно удален из live-интерфейса.")
            else:
                logger.warning(f"Публичный ключ для клиента {client} не найден, удаление из live-интерфейса пропущено.")

            # Удаляем блок клиента из конфигурационного файла
            new_config = re.sub(pattern, "", self.wg_conf, flags=re.DOTALL | re.MULTILINE)
            self.update_server_config(new_config)
            self.restart_wireguard()
            logger.info(f"Клиент {client} успешно удален из конфигурационного файла.")
            return True
        except Exception as e:
            logger.exception(f"Ошибка при удалении клиента {client}: {e}")
            return f"Ошибка при удалении клиента {client}: {e}"

    def get_peers_info(self) -> List[dict]:
        """
        Выполняет команду 'wg show' и извлекает информацию о пирах (peers) из её вывода.
        Возвращает список словарей с информацией по каждому peer.
        """
        try:
            result = subprocess.run(['wg', 'show'], capture_output=True, text=True, check=True)
            output = result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to execute 'wg show': {e}")
            return []

        peers = []
        peer_data = {}
        for line in output.splitlines():
            if line.startswith("peer:"):
                if peer_data:
                    peers.append(peer_data)
                    peer_data = {}
                tokens = line.split()
                if len(tokens) > 1:
                    peer_data['peer'] = tokens[1]
            elif "latest handshake" in line:
                # Обработка различных временных единиц (seconds, minutes, hours, days)
                match = re.search(r"latest handshake: (\d+)\s+(\w+)", line, re.IGNORECASE)
                if match:
                    value = int(match.group(1))
                    unit = match.group(2).lower()
                    if unit.startswith("second"):
                        seconds = value
                    elif unit.startswith("minute"):
                        seconds = value * 60
                    elif unit.startswith("hour"):
                        seconds = value * 3600
                    elif unit.startswith("day"):
                        seconds = value * 86400
                    else:
                        seconds = value  # На случай неизвестной единицы
                    peer_data['last_handshake'] = seconds
            elif "transfer" in line:
                match = re.search(r"transfer: ([\d.]+\s+\w+) received, ([\d.]+\s+\w+) sent", line)
                if match:
                    peer_data['data_received'] = match.group(1)
                    peer_data['data_sent'] = match.group(2)
            elif "allowed ips" in line:
                match = re.search(r"allowed ips: ([\d./]+),\s*([\S]+)", line)
                if match:
                    peer_data['ipv4'] = match.group(1)
                    peer_data['ipv6'] = match.group(2)
            elif "endpoint" in line:
                match = re.search(r"endpoint: ([\d.]+:\d+)", line)
                if match:
                    peer_data['endpoint'] = match.group(1)
        if peer_data:
            peers.append(peer_data)
        return peers
