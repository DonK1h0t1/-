import hashlib
import hmac
import os
import tkinter as tk
from tkinter import messagebox, scrolledtext

# S-box из AES — источник нелинейности в раундовой функции F
AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# P-box для 32 бит: перестановка «транспонированием» таблицы 4x8
PBOX32 = [(i % 4) * 8 + (i // 4) for i in range(32)]

BLOCK_SIZE = 8            # 64-битный блок = две половины L и R по 32 бита
KEY_HEX_LEN = 32          # 128-битный ключ = 32 hex-символа
TAG_SIZE = 32             # длина HMAC-SHA256
MASK32 = 0xFFFFFFFF
MIN_ROUNDS, DEFAULT_ROUNDS, MAX_ROUNDS = 4, 16, 32

# Вспомогательные функции
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def rotl(value: int, n: int, bits: int) -> int:
    n %= bits
    return ((value << n) | (value >> (bits - n))) & ((1 << bits) - 1)

def substitute32(value: int) -> int:
    return int.from_bytes(bytes(AES_SBOX[b] for b in value.to_bytes(4, "big")), "big")

def permute32(value: int) -> int:
    out = 0
    for i, src in enumerate(PBOX32):
        out |= ((value >> (31 - src)) & 1) << (31 - i)
    return out

def random_key_hex() -> str:
    return os.urandom(KEY_HEX_LEN // 2).hex().upper()

# Раундовая функция F и ключи раундов
def round_function(half: int, key: int) -> int:
    x = permute32(substitute32(half ^ key))                 # слой 1
    x = permute32(substitute32(x ^ rotl(key, 16, 32)))      # слой 2 (другая «версия» ключа)
    return x

def generate_round_keys(master_key: bytes, rounds: int) -> list:
    state = int.from_bytes(master_key, "big")
    keys = []
    for i in range(1, rounds + 1):
        state = rotl(state, 29, 128) ^ ((i * 0x9E3779B9) & MASK32)   # сдвиг + константа раунда
        state = int.from_bytes(bytes(AES_SBOX[b] for b in state.to_bytes(16, "big")), "big")
        # сворачиваем 128 бит состояния в 32-битный ключ раунда
        keys.append((state ^ (state >> 32) ^ (state >> 64) ^ (state >> 96)) & MASK32)
    return keys

def derive_keys(key_hex: str):
    """Из мастер-ключа получаем два независимых ключа: для шифрования и для MAC."""
    master = bytes.fromhex(key_hex)
    enc_key = hashlib.sha256(b"enc" + master).digest()[:16]
    mac_key = hashlib.sha256(b"mac" + master).digest()
    return enc_key, mac_key

# Ядро сети Фейстеля
def feistel_core(left: int, right: int, keys: list, log=None, label="Раунд"):
    last = len(keys) - 1
    for i, k in enumerate(keys):
        fv = round_function(left, k)
        if i < last:
            new_left, new_right = right ^ fv, left
        else:
            new_left, new_right = left, right ^ fv
        if log is not None:
            log.append(f"{label} {i + 1:>2}: K={k:08X}  F={fv:08X}  ->  L={new_left:08X}  R={new_right:08X}")
        left, right = new_left, new_right
    return left, right

def process_block(block: bytes, round_keys: list, decrypt: bool = False, log=None) -> bytes:
    left, right = int.from_bytes(block[:4], "big"), int.from_bytes(block[4:], "big")
    keys = round_keys[::-1] if decrypt else round_keys
    if log is not None:
        log.append(f"Вход:  L={left:08X}  R={right:08X}")
    left, right = feistel_core(left, right, keys, log, "Расшифр. раунд" if decrypt else "Раунд")
    if log is not None:
        log.append(f"Выход: L={left:08X}  R={right:08X}")
    return left.to_bytes(4, "big") + right.to_bytes(4, "big")

# Padding ISO/IEC 7816-4
def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + b"\x80" + b"\x00" * (pad_len - 1)

def unpad(data: bytes) -> bytes:
    idx = len(data) - 1
    while idx >= 0 and data[idx] == 0x00:
        idx -= 1
    if idx < 0 or data[idx] != 0x80 or len(data) - idx > BLOCK_SIZE:
        raise ValueError("Некорректный padding")
    return data[:idx]

# Режимы ECB и CBC + проверка целостности (HMAC)
def compute_tag(mac_key: bytes, body: bytes, rounds: int, mode: str) -> bytes:
    # режим и число раундов входят в тег, чтобы их нельзя было подменить
    return hmac.new(mac_key, body + bytes([rounds]) + mode.encode(), hashlib.sha256).digest()

def encrypt_data(plaintext: bytes, key_hex: str, rounds: int, mode: str = "CBC") -> bytes:
    enc_key, mac_key = derive_keys(key_hex)
    round_keys = generate_round_keys(enc_key, rounds)
    padded = pad(plaintext)
    blocks = []

    if mode == "ECB":
        for i in range(0, len(padded), BLOCK_SIZE):
            blocks.append(process_block(padded[i:i + BLOCK_SIZE], round_keys))
    else:
        iv = os.urandom(BLOCK_SIZE)       # случайный IV: одинаковый текст шифруется по-разному
        prev = iv
        blocks.append(iv)
        for i in range(0, len(padded), BLOCK_SIZE):
            prev = process_block(xor_bytes(padded[i:i + BLOCK_SIZE], prev), round_keys)
            blocks.append(prev)

    body = b"".join(blocks)
    return body + compute_tag(mac_key, body, rounds, mode)

def decrypt_data(data: bytes, key_hex: str, rounds: int, mode: str = "CBC") -> bytes:
    min_blocks = 1 if mode == "ECB" else 2          # в CBC первый блок — IV
    if len(data) < min_blocks * BLOCK_SIZE + TAG_SIZE or (len(data) - TAG_SIZE) % BLOCK_SIZE != 0:
        raise ValueError("Некорректная длина шифротекста")

    enc_key, mac_key = derive_keys(key_hex)
    body, tag = data[:-TAG_SIZE], data[-TAG_SIZE:]

    # Сначала проверяем целостность — и только потом расшифровываем
    if not hmac.compare_digest(tag, compute_tag(mac_key, body, rounds, mode)):
        raise ValueError("Проверка целостности не пройдена: неверный ключ, число раундов, режим "
                         "или данные изменены")

    round_keys = generate_round_keys(enc_key, rounds)
    chunks = []

    if mode == "ECB":
        for i in range(0, len(body), BLOCK_SIZE):
            chunks.append(process_block(body[i:i + BLOCK_SIZE], round_keys, decrypt=True))
    else:
        prev = body[:BLOCK_SIZE]
        for i in range(BLOCK_SIZE, len(body), BLOCK_SIZE):
            block = body[i:i + BLOCK_SIZE]
            chunks.append(xor_bytes(process_block(block, round_keys, decrypt=True), prev))
            prev = block
    return unpad(b"".join(chunks))

# Графический интерфейс
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Сеть Фейстеля")
        root.geometry("640x730")

        tk.Label(root, text="Входной текст (для шифрования) или Hex-шифротекст (для расшифровки):").pack(pady=(10, 2))
        self.text_input = scrolledtext.ScrolledText(root, width=72, height=7)
        self.text_input.insert("1.0", "Пример текста любой длины для сети Фейстеля.")
        self.text_input.pack(padx=10)

        tk.Label(root, text=f"Ключ (HEX, {KEY_HEX_LEN} символов / 128 бит):").pack(pady=(10, 2))
        frame_key = tk.Frame(root)
        frame_key.pack()
        self.entry_key = tk.Entry(frame_key, width=38, font=("Consolas", 10))
        self.entry_key.insert(0, random_key_hex())
        self.entry_key.pack(side=tk.LEFT, padx=(0, 5))
        tk.Button(frame_key, text="Сгенерировать", command=self.generate_key).pack(side=tk.LEFT, padx=(0, 12))
        tk.Label(frame_key, text="Раундов:").pack(side=tk.LEFT)
        self.spin_rounds = tk.Spinbox(frame_key, from_=MIN_ROUNDS, to=MAX_ROUNDS, width=4)
        self.spin_rounds.delete(0, tk.END)
        self.spin_rounds.insert(0, str(DEFAULT_ROUNDS))
        self.spin_rounds.pack(side=tk.LEFT, padx=(5, 0))

        frame_mode = tk.Frame(root)
        frame_mode.pack(pady=(10, 0))
        tk.Label(frame_mode, text="Режим:").pack(side=tk.LEFT, padx=(0, 5))
        self.mode_var = tk.StringVar(value="CBC")
        tk.Radiobutton(frame_mode, text="CBC (со сцеплением, безопаснее)",
                       variable=self.mode_var, value="CBC").pack(side=tk.LEFT)
        tk.Radiobutton(frame_mode, text="ECB (каждый блок отдельно, слабее)",
                       variable=self.mode_var, value="ECB").pack(side=tk.LEFT)

        tk.Button(root, text="Показать раундовые ключи", command=self.show_round_keys).pack(pady=(10, 0))
        tk.Button(root, text="Показать процесс по раундам (1-й блок)", command=self.show_trace).pack(pady=(4, 0))

        frame_buttons = tk.Frame(root)
        frame_buttons.pack(pady=15)
        tk.Button(frame_buttons, text="Зашифровать", width=15, bg="#4CAF50", fg="white",
                  command=self.encrypt).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_buttons, text="Расшифровать", width=15, bg="#2196F3", fg="white",
                  command=self.decrypt).pack(side=tk.LEFT, padx=5)

        tk.Label(root, text="Результат:").pack(pady=(5, 2))
        self.text_result = scrolledtext.ScrolledText(root, width=72, height=9, font=("Consolas", 10))
        self.text_result.pack(padx=10)

        frame_res = tk.Frame(root)
        frame_res.pack(pady=10)
        tk.Button(frame_res, text="Копировать результат", command=self.copy_result).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_res, text="Перенести результат в поле ввода",
                  command=self.result_to_input).pack(side=tk.LEFT, padx=5)

    # чтение полей 
    def get_rounds(self) -> int:
        try:
            rounds = int(self.spin_rounds.get())
        except ValueError:
            rounds = DEFAULT_ROUNDS
        return max(MIN_ROUNDS, min(rounds, MAX_ROUNDS))

    def get_key(self):
        key_hex = self.entry_key.get().strip()
        try:
            if len(key_hex) != KEY_HEX_LEN:
                raise ValueError
            bytes.fromhex(key_hex)
        except ValueError:
            messagebox.showerror("Ошибка", f"Ключ должен состоять из {KEY_HEX_LEN} hex-символов (0-9, A-F)!")
            return None
        return key_hex

    # действия 
    def generate_key(self):
        self.entry_key.delete(0, tk.END)
        self.entry_key.insert(0, random_key_hex())

    def set_result(self, text: str):
        self.text_result.delete("1.0", tk.END)
        self.text_result.insert("1.0", text)

    def encrypt(self):
        key = self.get_key()
        if key is None:
            return
        text = self.text_input.get("1.0", tk.END).rstrip("\n")
        try:
            cipher = encrypt_data(text.encode("utf-8"), key, self.get_rounds(), self.mode_var.get())
            self.set_result(cipher.hex().upper())
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось зашифровать: {e}")

    def decrypt(self):
        key = self.get_key()
        if key is None:
            return
        cipher_hex = "".join(self.text_input.get("1.0", tk.END).split())
        try:
            plain = decrypt_data(bytes.fromhex(cipher_hex), key, self.get_rounds(), self.mode_var.get())
            self.set_result(plain.decode("utf-8"))
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось расшифровать: {e}")

    def show_round_keys(self):
        key = self.get_key()
        if key is None:
            return
        enc_key, _ = derive_keys(key)
        keys = generate_round_keys(enc_key, self.get_rounds())
        lines = [f"K{i:<2} (раунд {i:>2}): {k:08X}" for i, k in enumerate(keys, start=1)]
        lines += ["", "При расшифровке ключи используются в обратном порядке."]
        self.show_window("Раундовые ключи", "\n".join(lines), 60, 22)

    def show_trace(self):
        key = self.get_key()
        if key is None:
            return
        text = self.text_input.get("1.0", tk.END).rstrip("\n")
        if not text:
            messagebox.showerror("Ошибка", "Введите текст в верхнее поле!")
            return
        enc_key, _ = derive_keys(key)
        round_keys = generate_round_keys(enc_key, self.get_rounds())
        block = pad(text.encode("utf-8"))[:BLOCK_SIZE]

        log = [f"Первый блок (после padding): {block.hex().upper()}", "", "Шифрование"]
        encrypted = process_block(block, round_keys, log=log)
        log += ["", "Расшифровка"]
        decrypted = process_block(encrypted, round_keys, decrypt=True, log=log)
        log += ["", "Проверка: блок " + ("Совпадает с исходным" if decrypted == block else "Не совпадает")]
        self.show_window("Трассировка раундов (первый блок, без учёта режима)", "\n".join(log), 80, 30)

    def show_window(self, title: str, content: str, width: int, height: int):
        win = tk.Toplevel(self.root)
        win.title(title)
        box = scrolledtext.ScrolledText(win, width=width, height=height, font=("Consolas", 10))
        box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        box.insert("1.0", content)

    def copy_result(self):
        result = self.text_result.get("1.0", tk.END).rstrip("\n")
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)

    def result_to_input(self):
        result = self.text_result.get("1.0", tk.END).rstrip("\n")
        self.text_input.delete("1.0", tk.END)
        self.text_input.insert("1.0", result)


if __name__ == "__main__":
    window = tk.Tk()
    App(window)
    window.mainloop()
