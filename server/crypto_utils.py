import hashlib


def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def derive_a3a8(ki_hex: str, rand_hex: str) -> tuple[str, str]:
    """
    Учебная модель A3/A8.
    Из Ki и RAND вычисляются:
    SRES (4 байта) и Kc (8 байт).
    """
    ki = bytes.fromhex(ki_hex)
    rand = bytes.fromhex(rand_hex)

    digest = hashlib.sha256(ki + rand).digest()
    sres = digest[:4].hex().upper()
    kc = digest[4:12].hex().upper()
    return sres, kc


class A51:
    """
    Учебная реализация A5/1:
    R1 = 19 бит
    R2 = 22 бита
    R3 = 23 бита
    """

    def __init__(self, kc_hex: str, frame_number: int = 0):
        self.r1 = 0
        self.r2 = 0
        self.r3 = 0
        self._keysetup(bytes.fromhex(kc_hex), frame_number)

    @staticmethod
    def _bit(value: int, index: int) -> int:
        return (value >> index) & 1

    @staticmethod
    def _majority(x: int, y: int, z: int) -> int:
        return 1 if (x + y + z) >= 2 else 0

    def _clock_r1(self):
        fb = self._bit(self.r1, 13) ^ self._bit(self.r1, 16) ^ self._bit(self.r1, 17) ^ self._bit(self.r1, 18)
        self.r1 = ((self.r1 << 1) & ((1 << 19) - 1)) | fb

    def _clock_r2(self):
        fb = self._bit(self.r2, 20) ^ self._bit(self.r2, 21)
        self.r2 = ((self.r2 << 1) & ((1 << 22) - 1)) | fb

    def _clock_r3(self):
        fb = self._bit(self.r3, 7) ^ self._bit(self.r3, 20) ^ self._bit(self.r3, 21) ^ self._bit(self.r3, 22)
        self.r3 = ((self.r3 << 1) & ((1 << 23) - 1)) | fb

    def _clock_all(self):
        self._clock_r1()
        self._clock_r2()
        self._clock_r3()

    def _clock_majority(self):
        c1 = self._bit(self.r1, 8)
        c2 = self._bit(self.r2, 10)
        c3 = self._bit(self.r3, 10)
        m = self._majority(c1, c2, c3)

        if c1 == m:
            self._clock_r1()
        if c2 == m:
            self._clock_r2()
        if c3 == m:
            self._clock_r3()

    def _keysetup(self, kc: bytes, frame_number: int):
        self.r1 = 0
        self.r2 = 0
        self.r3 = 0

        key_bits = []
        for b in kc:
            for i in range(8):
                key_bits.append((b >> i) & 1)

        frame_bits = []
        for i in range(22):
            frame_bits.append((frame_number >> i) & 1)

        for bit in key_bits:
            self._clock_all()
            self.r1 ^= bit
            self.r2 ^= bit
            self.r3 ^= bit

        for bit in frame_bits:
            self._clock_all()
            self.r1 ^= bit
            self.r2 ^= bit
            self.r3 ^= bit

        for _ in range(100):
            self._clock_majority()

    def get_keystream(self, nbytes: int) -> bytes:
        out = []
        for _ in range(nbytes * 8):
            self._clock_majority()
            ks_bit = self._bit(self.r1, 18) ^ self._bit(self.r2, 21) ^ self._bit(self.r3, 22)
            out.append(ks_bit)

        result = bytearray()
        for i in range(0, len(out), 8):
            value = 0
            for j in range(8):
                value |= (out[i + j] << j)
            result.append(value)
        return bytes(result)

    def encrypt(self, plaintext: bytes) -> bytes:
        keystream = self.get_keystream(len(plaintext))
        return bytes_xor(plaintext, keystream)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)