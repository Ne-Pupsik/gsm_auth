import socket
import json
import hashlib
import hmac
import sys
import threading
from client_config import ClientConfig
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

sys.path.append(str(Path(__file__).resolve().parent.parent))
from A5 import encrypt_text


class SIMCard:
    def __init__(self, imsi: str, ki_hex: str, tmsi: Optional[str] = None):
        self.imsi = imsi
        self.ki_hex = ki_hex.lower()
        self.tmsi = tmsi
        self._validate()

    def _validate(self) -> None:
        if not self.imsi.isdigit():
            raise ValueError("IMSI должен содержать только цифры")

        if len(self.imsi) > 15:
            raise ValueError("IMSI не должен быть длиннее 15 цифр")

        try:
            ki = bytes.fromhex(self.ki_hex)
        except ValueError as e:
            raise ValueError("ki_hex должен быть корректной hex-строкой") from e

        if len(ki) != 16:
            raise ValueError("Ki должен быть длиной 16 байт (128 бит)")

        if self.tmsi is not None and not isinstance(self.tmsi, str):
            raise ValueError("TMSI должен быть строкой или null")

    @classmethod
    def load_from_file(cls, path: str) -> "SIMCard":
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Файл SIM-конфигурации не найден: {path}")

        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        return cls(
            imsi=data["imsi"],
            ki_hex=data["ki_hex"],
            tmsi=data.get("tmsi")
        )

    def save_to_file(self, path: str) -> None:
        data = {
            "imsi": self.imsi,
            "ki_hex": self.ki_hex,
            "tmsi": self.tmsi
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)

    def has_tmsi(self) -> bool:
        return self.tmsi is not None and self.tmsi != ""

    def run_gsm_algorithm(self, rand_hex: str) -> tuple[str, str]:
        ki = bytes.fromhex(self.ki_hex)
        rand = bytes.fromhex(rand_hex)

        if len(rand) != 16:
            raise ValueError("RAND должен быть длиной 16 байт (128 бит)")

        mac = hmac.new(ki, rand, hashlib.sha256).digest()
        sres = mac[:4]
        kc = mac[4:12]

        return sres.hex(), kc.hex()


def recv_line(sock: socket.socket) -> str:
    data = bytearray()

    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Соединение закрыто удаленной стороной")
        if chunk == b"\n":
            break
        data.extend(chunk)

    return data.decode("utf-8")


def send_json(sock: socket.socket, obj: dict) -> None:
    payload = json.dumps(obj, ensure_ascii=False) + "\n"
    sock.sendall(payload.encode("utf-8"))


def recv_json(sock: socket.socket) -> dict:
    return json.loads(recv_line(sock))


class GSMClient:
    def __init__(self, config: ClientConfig):
        self.config = config
        self.sim = SIMCard.load_from_file(config.sim_config_path)

        self.session_id: Optional[str] = None
        self.rand_hex: Optional[str] = None
        self.kc_hex: Optional[str] = None

    def run(self) -> None:
        print(self.config.sim_config_path)
        print(f"[+] Загружена SIM-карта из файла: {self.config.sim_config_path}")
        print(f"[+] IMSI: {self.sim.imsi}")
        print(f"[+] TMSI: {self.sim.tmsi if self.sim.tmsi else 'отсутствует'}")
        print(f"[+] Подключение к {self.config.server_host}:{self.config.server_port}")

        with socket.create_connection(
            (self.config.server_host, self.config.server_port),
            timeout=self.config.timeout_sec
        ) as sock:
            sock.settimeout(None)

            self.start_auth(sock)
            self.process_challenge(sock)
            self.send_auth_response(sock)

            auth_ok = self.process_auth_result(sock)
            if not auth_ok:
                return

            self.message_loop(sock)

    def start_auth(self, sock: socket.socket) -> None:
        if self.sim.has_tmsi():
            request = {
                "type": "auth_start",
                "id_type": "tmsi",
                "tmsi": self.sim.tmsi
            }
            print(f"[>] Отправлен auth_start по TMSI={self.sim.tmsi}")
        else:
            request = {
                "type": "auth_start",
                "id_type": "imsi",
                "imsi": self.sim.imsi
            }
            print(f"[>] Отправлен auth_start по IMSI={self.sim.imsi}")

        send_json(sock, request)

    def process_challenge(self, sock: socket.socket) -> None:
        response = recv_json(sock)
        print(f"[<] Получено: {response}")

        if response.get("type") != "auth_challenge":
            raise RuntimeError(f"Ожидался auth_challenge, получено: {response}")

        self.session_id = response.get("session_id")
        self.rand_hex = response.get("rand")

        if not self.session_id:
            raise RuntimeError("Сервер не прислал session_id")
        if not self.rand_hex:
            raise RuntimeError("Сервер не прислал RAND")

        rand_bytes = bytes.fromhex(self.rand_hex)
        if len(rand_bytes) != 16:
            raise RuntimeError("RAND должен быть длиной 16 байт (128 бит)")

        print(f"[+] session_id = {self.session_id}")
        print(f"[+] RAND       = {self.rand_hex}")

    def send_auth_response(self, sock: socket.socket) -> None:
        if self.session_id is None or self.rand_hex is None:
            raise RuntimeError("Нет данных для завершения аутентификации")

        sres_hex, kc_hex = self.sim.run_gsm_algorithm(self.rand_hex)
        self.kc_hex = kc_hex

        request = {
            "type": "auth_response",
            "session_id": self.session_id,
            "sres": sres_hex
        }

        send_json(sock, request)

        print(f"[+] Вычислен SRES = {sres_hex}")
        print(f"[+] Вычислен Kc   = {kc_hex}")
        print("[>] Отправлен auth_response")

    def process_auth_result(self, sock: socket.socket) -> bool:
        response = recv_json(sock)
        print(f"[<] Получено: {response}")

        if response.get("type") != "auth_result":
            raise RuntimeError(f"Ожидался auth_result, получено: {response}")

        status = response.get("status")
        message = response.get("message", "")

        if status != "ok":
            print("[-] Аутентификация не пройдена")
            if message:
                print(f"[-] Причина: {message}")
            return False

        print("[+] Аутентификация прошла успешно")
        if message:
            print(f"[+] Сообщение сервера: {message}")

        print(f"[+] Локальный Kc: {self.kc_hex}")

        new_tmsi = response.get("new_tmsi")
        if new_tmsi:
            old_tmsi = self.sim.tmsi
            self.sim.tmsi = new_tmsi
            self.sim.save_to_file(self.config.sim_config_path)
            print(f"[+] TMSI обновлен: {old_tmsi} -> {new_tmsi}")

        print("[+] Клиент готов к обмену данными")
        return True

    def receiver_loop(self, sock: socket.socket, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                response = recv_json(sock)
            except Exception:
                if not stop_event.is_set():
                    print("\n[!] Соединение с сервером потеряно")
                    stop_event.set()
                break

            msg_type = response.get("type")

            if msg_type == "data_ack":
                print("[<] Сервер принял сообщение")
            elif msg_type == "error":
                print(f"[<] Ошибка сервера: {response.get('message', 'unknown error')}")
            elif msg_type == "close_ack":
                print("[<] Сервер закрыл соединение")
                stop_event.set()
                break
            else:
                print(f"[<] Служебное сообщение: {response}")

    def message_loop(self, sock: socket.socket) -> None:
        if self.kc_hex is None:
            raise RuntimeError("Нет Kc для шифрования")

        print("Введите сообщения. Для выхода введите /exit")

        stop_event = threading.Event()
        receiver_thread = threading.Thread(
            target=self.receiver_loop,
            args=(sock, stop_event),
            daemon=True
        )
        receiver_thread.start()

        while not stop_event.is_set():
            try:
                text = input(">>> ")
            except (EOFError, KeyboardInterrupt):
                text = "/exit"

            if not text.strip():
                continue

            if text.strip() == "/exit":
                try:
                    send_json(sock, {"type": "close"})
                except Exception:
                    pass
                break

            nonce_hex, ciphertext_hex = encrypt_text(self.kc_hex, text)

            request = {
                "type": "data",
                "nonce": nonce_hex,
                "ciphertext": ciphertext_hex
            }

            try:
                send_json(sock, request)
            except Exception as e:
                print(f"[!] Не удалось отправить сообщение: {e}")
                break

        stop_event.set()
        receiver_thread.join(timeout=1.0)
        print("[+] Клиент завершен")


if __name__ == "__main__":
    config = ClientConfig(
        server_host="192.168.0.103",
        server_port=5050,
        sim_config_path="sim.json"
    )

    client = GSMClient(config)

    try:
        client.run()
    except Exception as e:
        print(f"[!] Ошибка: {e}")