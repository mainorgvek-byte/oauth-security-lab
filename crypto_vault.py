import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time


def derive_keys(commit_hash: str, salt: bytes) -> tuple[bytes, bytes]:
    """Виводить ключ шифрування та ключ автентифікації (HMAC) з хешу коміту."""
    clean_hash = commit_hash.strip().lower()
    master_key = hashlib.pbkdf2_hmac(
        "sha256",
        clean_hash.encode("utf-8"),
        salt,
        iterations=100_000,
        dklen=64,
    )
    return master_key[:32], master_key[32:]


def keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    """Генерує псевдовипадковий потік байтів потрібної довжини."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        block_input = nonce + counter.to_bytes(8, "big")
        block = hmac.new(enc_key, block_input, hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt_text(plaintext: str, commit_hash: str) -> dict:
    data = plaintext.encode("utf-8")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    enc_key, mac_key = derive_keys(commit_hash, salt)

    ks = keystream(enc_key, nonce, len(data))
    ciphertext = bytes(b ^ k for b, k in zip(data, ks))

    tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()

    return {
        "v": 1,
        "kdf": "PBKDF2-HMAC-SHA256",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "hmac": base64.b64encode(tag).decode("ascii"),
    }


def decrypt_text(payload: dict, commit_hash: str, animate: bool = True) -> str:
    salt = base64.b64decode(payload["salt"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    expected_tag = base64.b64decode(payload["hmac"])

    if animate:
        steps = [
            f"[*] Зчитуємо опорний хеш коміту: {commit_hash.strip()}",
            "[*] Виконуємо PBKDF2-HMAC-SHA256 (100 000 ітерацій)...",
            "[*] Перевіряємо цілісність шифротексту через HMAC-SHA256...",
        ]
        for line in steps:
            print(line)
            time.sleep(0.35)

    enc_key, mac_key = derive_keys(commit_hash, salt)
    actual_tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(actual_tag, expected_tag):
        raise ValueError(
            "Помилка автентифікації/цілісності! Невірний хеш коміту або дані пошкоджено."
        )

    ks = keystream(enc_key, nonce, len(ciphertext))
    plaintext_bytes = bytes(b ^ k for b, k in zip(ciphertext, ks))

    if animate:
        print("[+] Цілісність підтверджено. Розшифровуємо звіт...\n")
        time.sleep(0.3)

    return plaintext_bytes.decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Git-Commit-Keyed Vault: шифрування та розшифрування звіту за хешем коміту."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Зашифрувати текстовий файл або рядок")
    p_enc.add_argument("--hash", required=True, help="Хеш коміту Git (напр. bb9a226)")
    p_enc.add_argument("--in-file", required=True, help="Шлях до вхідного .txt файлу")
    p_enc.add_argument("--out-file", required=True, help="Куди зберегти JSON-контейнер")

    p_dec = sub.add_parser("decrypt", help="Розшифрувати контейнер за хешем коміту")
    p_dec.add_argument("--hash", required=True, help="Хеш коміту Git (напр. bb9a226)")
    p_dec.add_argument("--in-file", required=True, help="Шлях до зашифрованого JSON-файлу")
    p_dec.add_argument("--no-anim", action="store_true", help="Вимкнути затримки виводу")

    args = parser.parse_args()

    if args.cmd == "encrypt":
        with open(args.in_file, "r", encoding="utf-8") as f:
            text = f.read()
        bundle = encrypt_text(text, args.hash)
        with open(args.out_file, "w", encoding="utf-8") as f:
            json.dump(bundle, f, ensure_ascii=False, indent=2)
        print(f"[OK] Зашифровано у '{args.out_file}' на основі коміту {args.hash}")

    elif args.cmd == "decrypt":
        with open(args.in_file, "r", encoding="utf-8") as f:
            bundle = json.load(f)
        try:
            result = decrypt_text(bundle, args.hash, animate=not args.no_anim)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            sys.exit(1)
        print("=" * 60)
        print(result)
        print("=" * 60)


if __name__ == "__main__":
    main()