import hashlib
import hmac
import secrets


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _build_keystream(kc: bytes, nonce: bytes, length: int) -> bytes:
    """
    Генерирует псевдослучайный поток байт длины length
    на основе Kc и nonce.
    """
    stream = bytearray()
    counter = 0

    while len(stream) < length:
        counter_bytes = counter.to_bytes(8, byteorder="big")
        block = hmac.new(kc, nonce + counter_bytes, hashlib.sha256).digest()
        stream.extend(block)
        counter += 1

    return bytes(stream[:length])


def encrypt_text(kc_hex: str, plaintext: str) -> tuple[str, str]:
    """
    Шифрует строку plaintext.
    Возвращает:
      nonce_hex, ciphertext_hex
    """
    kc = bytes.fromhex(kc_hex)
    if len(kc) != 8:
        raise ValueError("Kc должен быть длиной 8 байт (64 бита)")

    plaintext_bytes = plaintext.encode("utf-8")
    nonce = secrets.token_bytes(8)
    keystream = _build_keystream(kc, nonce, len(plaintext_bytes))
    ciphertext = _xor_bytes(plaintext_bytes, keystream)

    return nonce.hex(), ciphertext.hex()


def decrypt_text(kc_hex: str, nonce_hex: str, ciphertext_hex: str) -> str:
    """
    Расшифровывает строку и возвращает plaintext.
    """
    kc = bytes.fromhex(kc_hex)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    if len(kc) != 8:
        raise ValueError("Kc должен быть длиной 8 байт (64 бита)")
    if len(nonce) != 8:
        raise ValueError("nonce должен быть длиной 8 байт")

    keystream = _build_keystream(kc, nonce, len(ciphertext))
    plaintext_bytes = _xor_bytes(ciphertext, keystream)

    return plaintext_bytes.decode("utf-8", errors="replace")