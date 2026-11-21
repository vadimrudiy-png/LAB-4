import os, json, time, hashlib
from typing import Dict, Tuple
from config import KEYSTORE_PATH, ITERATIONS, VALID_KEY_BITS, DEFAULT_KEY_BITS, HMAC_KEY_BYTES, MAX_KEY_USES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class KeyManager:
    def __init__(self, path: str = KEYSTORE_PATH):
        self.path = path
        self.db = {"keys": []}
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                self.db = json.load(f)

    def save(self):
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump(self.db, f, ensure_ascii=False, indent=2)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @staticmethod
    def validate_key_bits(key_bits: int) -> int:
        if key_bits not in VALID_KEY_BITS:
            raise ValueError(f"Invalid AES key length: {key_bits} bits. Allowed: {VALID_KEY_BITS}")
        return key_bits // 8

    @staticmethod
    def _derive(password: bytes, salt: bytes, length: int, iterations: int) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
        return kdf.derive(password)

    def new_key(self, label: str, password: str, key_bits: int = DEFAULT_KEY_BITS, iterations: int = ITERATIONS) -> Dict:
        if not label or not password or len(password) < 8:
            raise ValueError("Label must be non-empty and password must be at least 8 characters")
        if any(k['label'] == label for k in self.db['keys']):
            raise ValueError(f"Key reuse prohibited: label '{label}' already exists")
        enc_len = self.validate_key_bits(key_bits)
        salt = os.urandom(16)
        key_material = self._derive(password.encode('utf-8'), salt, enc_len + HMAC_KEY_BYTES, iterations)
        enc_key = key_material[:enc_len]
        key_id = hashlib.sha256(enc_key).hexdigest()[:16]
        if any(k['key_id'] == key_id for k in self.db['keys']):
            raise ValueError("Key reuse prohibited: identical cryptographic key material detected")
        meta = {
            "label": label,
            "key_id": key_id,
            "key_bits": key_bits,
            "salt": salt.hex(),
            "iterations": iterations,
            "kdf": "PBKDF2-HMAC-SHA256",
            "created_at": int(time.time()),
            "uses": 0,
            "max_uses": MAX_KEY_USES,
            "status": "ACTIVE"
        }
        self.db['keys'].append(meta)
        self.save()
        return meta

    def list_keys(self):
        return self.db['keys']

    def derive_keypair(self, label: str, password: str) -> Tuple[Dict, bytes, bytes]:
        meta = next((k for k in self.db['keys'] if k['label'] == label), None)
        if not meta:
            raise ValueError(f"Key label '{label}' not found")
        if meta.get('status') != 'ACTIVE' or meta.get('uses', 0) >= meta.get('max_uses', MAX_KEY_USES):
            raise ValueError(f"Key '{label}' expired or exceeded max uses; rotate key")
        enc_len = self.validate_key_bits(meta.get('key_bits', DEFAULT_KEY_BITS))
        salt = bytes.fromhex(meta['salt'])
        key_material = self._derive(password.encode('utf-8'), salt, enc_len + HMAC_KEY_BYTES, meta['iterations'])
        return meta, key_material[:enc_len], key_material[enc_len:]

    def inc_use(self, key_id: str):
        for k in self.db['keys']:
            if k['key_id'] == key_id:
                k['uses'] += 1
                if k['uses'] >= k.get('max_uses', MAX_KEY_USES):
                    k['status'] = 'ROTATION_REQUIRED'
                break
        self.save()
