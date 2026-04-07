import json
import secrets
import socket
from crypto_utils import derive_a3a8, A51


HOST = "0.0.0.0"
PORT = 5000


def recv_line(conn: socket.socket) -> str:
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            raise ConnectionError("Соединение закрыто")
        data += chunk
    return data.decode("utf-8").rstrip("\n")


def send_line(conn: socket.socket, msg: str):
    conn.sendall((msg + "\n").encode("utf-8"))


def load_subscribers(path="subscribers.json") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    subscribers = load_subscribers()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(5)

        print(f"[SERVER] GSM auth server started on {HOST}:{PORT}")

        while True:
            conn, addr = srv.accept()
            print(f"[SERVER] Connection from {addr}")

            try:
                with conn:
                    imsi_line = recv_line(conn)
                    if not imsi_line.startswith("IMSI:"):
                        send_line(conn, "ERROR: expected IMSI")
                        continue

                    imsi = imsi_line.split(":", 1)[1].strip()
                    print(f"[SERVER] IMSI received: {imsi}")

                    if imsi not in subscribers:
                        send_line(conn, "AUTH_FAIL: unknown subscriber")
                        print("[SERVER] Unknown IMSI")
                        continue

                    ki_hex = subscribers[imsi]
                    rand_hex = secrets.token_hex(16).upper()

                    expected_sres, kc_hex = derive_a3a8(ki_hex, rand_hex)

                    print(f"[SERVER] RAND = {rand_hex}")
                    print(f"[SERVER] expected SRES = {expected_sres}")
                    print(f"[SERVER] Kc = {kc_hex}")

                    send_line(conn, f"RAND:{rand_hex}")

                    sres_line = recv_line(conn)
                    if not sres_line.startswith("SRES:"):
                        send_line(conn, "AUTH_FAIL: expected SRES")
                        continue

                    client_sres = sres_line.split(":", 1)[1].strip().upper()
                    print(f"[SERVER] client SRES = {client_sres}")

                    if client_sres != expected_sres:
                        send_line(conn, "AUTH_FAIL: bad sres")
                        print("[SERVER] Authentication failed")
                        continue

                    send_line(conn, "AUTH_OK")
                    print("[SERVER] Authentication successful")

                    frame_number = 0
                    cipher = A51(kc_hex, frame_number)

                    enc_line = recv_line(conn)
                    if not enc_line.startswith("DATA:"):
                        send_line(conn, "ERROR: expected DATA")
                        continue

                    ciphertext_hex = enc_line.split(":", 1)[1].strip()
                    ciphertext = bytes.fromhex(ciphertext_hex)
                    plaintext = cipher.decrypt(ciphertext)

                    print(f"[SERVER] Ciphertext = {ciphertext_hex}")
                    print(f"[SERVER] Plaintext = {plaintext.decode('utf-8', errors='replace')}")

                    response_text = f"Server received: {plaintext.decode('utf-8', errors='replace')}"
                    response_cipher = A51(kc_hex, frame_number)
                    response_ct = response_cipher.encrypt(response_text.encode("utf-8"))
                    send_line(conn, f"DATA:{response_ct.hex().upper()}")

            except Exception as e:
                print(f"[SERVER] Error: {e}")


if __name__ == "__main__":
    main()