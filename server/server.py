import socket
import json
import hashlib
import hmac
import secrets
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# =========================
# Настройки сервера
# =========================

@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 9000
    subscribers_db_path: str = "subscribers.json"
    backlog: int = 5


# =========================
# Сетевые функции
# =========================

def recv_line(sock: socket.socket) -> str:
    data = bytearray()

    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Клиент закрыл соединение")
        if chunk == b"\n":
            break
        data.extend(chunk)

    return data.decode("utf-8")


def send_json(sock: socket.socket, obj: dict) -> None:
    payload = json.dumps(obj, ensure_ascii=False) + "\n"
    sock.sendall(payload.encode("utf-8"))


def recv_json(sock: socket.socket) -> dict:
    return json.loads(recv_line(sock))


# =========================
# Учебная реализация A3/A8
# =========================

def a3_a8_demo(ki_hex: str, rand_hex: str) -> tuple[str, str]:
    """
    Учебная имитация A3/A8.
    Вход:
      ki_hex   - 128 бит (16 байт)
      rand_hex - 128 бит (16 байт)

    Выход:
      sres_hex - 32 бита (4 байта)
      kc_hex   - 64 бита (8 байт)
    """
    ki = bytes.fromhex(ki_hex)
    rand = bytes.fromhex(rand_hex)

    if len(ki) != 16:
        raise ValueError("Ki должен быть длиной 16 байт")
    if len(rand) != 16:
        raise ValueError("RAND должен быть длиной 16 байт")

    mac = hmac.new(ki, rand, hashlib.sha256).digest()
    sres = mac[:4]
    kc = mac[4:12]

    return sres.hex(), kc.hex()


# =========================
# База абонентов
# =========================

class SubscriberDB:
    def __init__(self, path: str):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.subscribers = self._load()

    def _load(self) -> list[dict]:
        if not self.path.exists():
            raise FileNotFoundError(
                f"Файл базы абонентов не найден: {self.path}"
            )

        with self.path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError("Файл subscribers.json должен содержать список абонентов")

        for sub in data:
            self._validate_subscriber(sub)

        return data

    def _validate_subscriber(self, sub: dict) -> None:
        if "imsi" not in sub:
            raise ValueError("У абонента отсутствует поле imsi")
        if "ki_hex" not in sub:
            raise ValueError("У абонента отсутствует поле ki_hex")

        imsi = sub["imsi"]
        ki_hex = sub["ki_hex"]
        tmsi = sub.get("tmsi")

        if not isinstance(imsi, str) or not imsi.isdigit() or len(imsi) > 15:
            raise ValueError(f"Некорректный IMSI: {imsi}")

        try:
            ki = bytes.fromhex(ki_hex)
        except ValueError as e:
            raise ValueError(f"Некорректный ki_hex у IMSI={imsi}") from e

        if len(ki) != 16:
            raise ValueError(f"Ki у IMSI={imsi} должен быть длиной 16 байт")

        if tmsi is not None and not isinstance(tmsi, str):
            raise ValueError(f"TMSI у IMSI={imsi} должен быть строкой или null")

    def save(self) -> None:
        with self.path.open("w", encoding="utf-8") as f:
            json.dump(self.subscribers, f, ensure_ascii=False, indent=4)

    def find_by_imsi(self, imsi: str) -> Optional[dict]:
        for sub in self.subscribers:
            if sub["imsi"] == imsi:
                return sub
        return None

    def find_by_tmsi(self, tmsi: str) -> Optional[dict]:
        for sub in self.subscribers:
            if sub.get("tmsi") == tmsi:
                return sub
        return None

    def generate_unique_tmsi(self) -> str:
        while True:
            # 32 бита = 8 hex-символов
            tmsi = secrets.token_hex(4).upper()
            if self.find_by_tmsi(tmsi) is None:
                return tmsi

    def assign_new_tmsi(self, subscriber: dict) -> str:
        with self.lock:
            new_tmsi = self.generate_unique_tmsi()
            subscriber["tmsi"] = new_tmsi
            self.save()
            return new_tmsi


# =========================
# GSM сервер
# =========================

class GSMAuthServer:
    def __init__(self, config: ServerConfig):
        self.config = config
        self.db = SubscriberDB(config.subscribers_db_path)

        # session_id -> session_data
        self.sessions: dict[str, dict] = {}
        self.sessions_lock = threading.Lock()

    def start(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.config.host, self.config.port))
            server_sock.listen(self.config.backlog)

            print(f"[+] Сервер запущен на {self.config.host}:{self.config.port}")
            print(f"[+] База абонентов: {self.config.subscribers_db_path}")

            while True:
                client_sock, client_addr = server_sock.accept()
                print(f"[+] Новое подключение: {client_addr[0]}:{client_addr[1]}")

                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                thread.start()

    def handle_client(self, sock: socket.socket, addr) -> None:
        try:
            with sock:
                request = recv_json(sock)
                print(f"[{addr[0]}:{addr[1]}] [<] {request}")

                req_type = request.get("type")

                if req_type != "auth_start":
                    send_json(sock, {
                        "type": "auth_result",
                        "status": "error",
                        "message": "Ожидался запрос auth_start"
                    })
                    return

                session = self.process_auth_start(request)
                send_json(sock, {
                    "type": "auth_challenge",
                    "session_id": session["session_id"],
                    "rand": session["rand_hex"]
                })
                print(
                    f"[{addr[0]}:{addr[1]}] [>] auth_challenge "
                    f"session_id={session['session_id']} rand={session['rand_hex']}"
                )

                response = recv_json(sock)
                print(f"[{addr[0]}:{addr[1]}] [<] {response}")

                if response.get("type") != "auth_response":
                    send_json(sock, {
                        "type": "auth_result",
                        "status": "error",
                        "message": "Ожидался запрос auth_response"
                    })
                    return

                result = self.process_auth_response(response)

                send_json(sock, result)
                print(f"[{addr[0]}:{addr[1]}] [>] {result}")

        except Exception as e:
            print(f"[!] Ошибка при работе с клиентом {addr}: {e}")

    def process_auth_start(self, request: dict) -> dict:
        id_type = request.get("id_type")

        if id_type == "imsi":
            imsi = request.get("imsi")
            if not imsi:
                raise ValueError("В запросе отсутствует IMSI")

            subscriber = self.db.find_by_imsi(imsi)
            if subscriber is None:
                raise ValueError(f"Абонент с IMSI={imsi} не найден")

        elif id_type == "tmsi":
            tmsi = request.get("tmsi")
            if not tmsi:
                raise ValueError("В запросе отсутствует TMSI")

            subscriber = self.db.find_by_tmsi(tmsi)
            if subscriber is None:
                raise ValueError(f"Абонент с TMSI={tmsi} не найден")

        else:
            raise ValueError("id_type должен быть 'imsi' или 'tmsi'")

        rand_hex = secrets.token_hex(16)
        session_id = str(uuid.uuid4())

        sres_expected, kc_hex = a3_a8_demo(subscriber["ki_hex"], rand_hex)

        session_data = {
            "session_id": session_id,
            "subscriber_imsi": subscriber["imsi"],
            "rand_hex": rand_hex,
            "sres_expected": sres_expected,
            "kc_hex": kc_hex
        }

        with self.sessions_lock:
            self.sessions[session_id] = session_data

        print(
            f"[+] Создана сессия {session_id} для IMSI={subscriber['imsi']} "
            f"SRES_expected={sres_expected} Kc={kc_hex}"
        )

        return session_data

    def process_auth_response(self, request: dict) -> dict:
        session_id = request.get("session_id")
        sres_received = request.get("sres")

        if not session_id:
            return {
                "type": "auth_result",
                "status": "error",
                "message": "Отсутствует session_id"
            }

        if not sres_received:
            return {
                "type": "auth_result",
                "status": "error",
                "message": "Отсутствует SRES"
            }

        with self.sessions_lock:
            session = self.sessions.pop(session_id, None)

        if session is None:
            return {
                "type": "auth_result",
                "status": "error",
                "message": "Сессия не найдена или уже завершена"
            }

        sres_expected = session["sres_expected"]
        imsi = session["subscriber_imsi"]

        if sres_received.lower() != sres_expected.lower():
            return {
                "type": "auth_result",
                "status": "fail",
                "message": "Неверный SRES. Аутентификация не пройдена."
            }

        subscriber = self.db.find_by_imsi(imsi)
        if subscriber is None:
            return {
                "type": "auth_result",
                "status": "error",
                "message": "Абонент не найден в базе на этапе завершения аутентификации"
            }

        new_tmsi = self.db.assign_new_tmsi(subscriber)

        return {
            "type": "auth_result",
            "status": "ok",
            "message": "Authentication successful",
            "new_tmsi": new_tmsi
        }


# =========================
# Точка входа
# =========================

if __name__ == "__main__":
    config = ServerConfig(
        host="0.0.0.0",
        port=9000,
        subscribers_db_path="subscribers.json"
    )

    server = GSMAuthServer(config)

    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[+] Сервер остановлен")
    except Exception as e:
        print(f"[!] Критическая ошибка сервера: {e}")