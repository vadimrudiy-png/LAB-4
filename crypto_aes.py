import json, struct
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac as hmac_lib
from config import (
    MAGIC, VERSION, NONCE_BYTES_GCM, IV_BYTES_CBC, NONCE_BYTES_CTR,
    BLOCK_SIZE_BITS, CHUNK_SIZE
)
import os

SUPPORTED_MODES = ("gcm", "cbc", "ctr")
SUPPORTED_PADDINGS = ("pkcs7", "ansix923", "none")

def _pack_header(h: dict) -> bytes:
    blob = json.dumps(h, separators=(',', ':'), sort_keys=True).encode('utf-8')
    return MAGIC + struct.pack('>H', len(blob)) + blob

def _unpack_header(fp) -> tuple[dict, bytes]:
    magic = fp.read(4)
    if magic != MAGIC:
        raise ValueError('INVALID_CONTAINER: Bad magic bytes (file corrupted or wrong format)')
    len_bytes = fp.read(2)
    if len(len_bytes) < 2:
        raise ValueError('INVALID_CONTAINER: Truncated header length')
    (hdrlen,) = struct.unpack('>H', len_bytes)
    raw_hdr = fp.read(hdrlen)
    if len(raw_hdr) < hdrlen:
        raise ValueError('INVALID_CONTAINER: Truncated JSON header')
    try:
        hdr = json.loads(raw_hdr.decode('utf-8'))
    except Exception as e:
        raise ValueError(f'HEADER_TAMPERED: Corrupted JSON metadata ({e})')
    return hdr, magic + len_bytes + raw_hdr

def _get_padder(pad_scheme: str, block_bits: int = BLOCK_SIZE_BITS):
    if block_bits != 128:
        raise ValueError(f'Unsupported AES block size: {block_bits} bits (must be 128)')
    scheme = pad_scheme.lower()
    if scheme == 'pkcs7':
        return padding.PKCS7(block_bits).padder()
    elif scheme == 'ansix923':
        return padding.ANSIX923(block_bits).padder()
    raise ValueError(f'Unsupported padding scheme for block mode: {pad_scheme}')

def _get_unpadder(pad_scheme: str, block_bits: int = BLOCK_SIZE_BITS):
    scheme = pad_scheme.lower()
    if scheme == 'pkcs7':
        return padding.PKCS7(block_bits).unpadder()
    elif scheme == 'ansix923':
        return padding.ANSIX923(block_bits).unpadder()
    raise ValueError(f'Unsupported padding scheme: {pad_scheme}')

def _resolve_iv(iv_hex: Optional[str], expected_len: int) -> bytes:
    if iv_hex:
        iv = bytes.fromhex(iv_hex)
        if len(iv) != expected_len:
            raise ValueError(f'Invalid IV/Nonce length: got {len(iv)}B, expected {expected_len}B')
        return iv
    return os.urandom(expected_len)

def encrypt_file(
    in_path: str,
    out_path: str,
    enc_key: bytes,
    mac_key: Optional[bytes] = None,
    mode: str = 'gcm',
    pad_scheme: str = 'pkcs7',
    iv_hex: Optional[str] = None,
    aad: Optional[bytes] = None,
    block_bits: int = BLOCK_SIZE_BITS
) -> dict:
    mode = mode.lower()
    if mode not in SUPPORTED_MODES:
        raise ValueError(f'Unsupported mode: {mode}. Choose from {SUPPORTED_MODES}')
    if block_bits != 128:
        raise ValueError('AES block size must strictly be 128 bits')

    key_bits = len(enc_key) * 8

    if mode == 'gcm':
        nonce = _resolve_iv(iv_hex, NONCE_BYTES_GCM)
        cipher = Cipher(algorithms.AES(enc_key), modes.GCM(nonce))
        enc = cipher.encryptor()
        h = {
            "v": VERSION, "mode": "GCM", "alg": f"AES-{key_bits}-GCM",
            "block_bits": block_bits, "pad": "NONE", "nonce": nonce.hex(),
            "has_aad": bool(aad)
        }
        header = _pack_header(h)
        enc.authenticate_additional_data(header + (aad or b''))
        with open(in_path, 'rb') as fi, open(out_path, 'wb') as fo:
            fo.write(header)
            while True:
                chunk = fi.read(CHUNK_SIZE)
                if not chunk:
                    break
                fo.write(enc.update(chunk))
            fo.write(enc.finalize())
            fo.write(enc.tag)
        return {"mode": "GCM", "tag_len": len(enc.tag), "iv": nonce.hex(), "pad": "NONE"}

    if not mac_key:
        raise ValueError(f'mac_key is required for Encrypt-then-MAC in {mode.upper()} mode')

    if mode == 'cbc':
        iv = _resolve_iv(iv_hex, IV_BYTES_CBC)
        padder = _get_padder(pad_scheme, block_bits)
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        enc = cipher.encryptor()
        h = {
            "v": VERSION, "mode": "CBC-HMAC", "alg": f"AES-{key_bits}-CBC",
            "block_bits": block_bits, "pad": pad_scheme.upper(),
            "iv": iv.hex(), "mac": "HMAC-SHA256"
        }
        header = _pack_header(h)
        mac = hmac_lib.HMAC(mac_key, hashes.SHA256())
        mac.update(header)
        with open(in_path, 'rb') as fi, open(out_path, 'wb') as fo:
            fo.write(header)
            while True:
                chunk = fi.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = enc.update(padder.update(chunk))
                if ct:
                    fo.write(ct)
                    mac.update(ct)
            ct_final = enc.update(padder.finalize()) + enc.finalize()
            if ct_final:
                fo.write(ct_final)
                mac.update(ct_final)
            tag = mac.finalize()
            fo.write(tag)
        return {"mode": "CBC-HMAC", "tag_len": len(tag), "iv": iv.hex(), "pad": pad_scheme.upper()}

    # Extensible mode: AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC, stream mode without padding)
    nonce = _resolve_iv(iv_hex, NONCE_BYTES_CTR)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    enc = cipher.encryptor()
    h = {
        "v": VERSION, "mode": "CTR-HMAC", "alg": f"AES-{key_bits}-CTR",
        "block_bits": block_bits, "pad": "NONE",
        "nonce": nonce.hex(), "mac": "HMAC-SHA256"
    }
    header = _pack_header(h)
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256())
    mac.update(header)
    with open(in_path, 'rb') as fi, open(out_path, 'wb') as fo:
        fo.write(header)
        while True:
            chunk = fi.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = enc.update(chunk)
            if ct:
                fo.write(ct)
                mac.update(ct)
        ct_final = enc.finalize()
        if ct_final:
            fo.write(ct_final)
            mac.update(ct_final)
        tag = mac.finalize()
        fo.write(tag)
    return {"mode": "CTR-HMAC", "tag_len": len(tag), "iv": nonce.hex(), "pad": "NONE"}

def decrypt_file(
    in_path: str,
    out_path: str,
    enc_key: bytes,
    mac_key: Optional[bytes] = None,
    expected_mode: Optional[str] = None,
    aad: Optional[bytes] = None
) -> dict:
    with open(in_path, 'rb') as fi:
        hdr, raw_header = _unpack_header(fi)
        data = fi.read()

    actual_mode = hdr.get('mode', '')
    if expected_mode:
        norm = {"gcm": "GCM", "cbc": "CBC-HMAC", "ctr": "CTR-HMAC"}.get(expected_mode.lower(), expected_mode)
        if actual_mode != norm:
            raise ValueError(f'MODE_MISMATCH: Expected {norm}, container has {actual_mode}')

    if actual_mode == 'GCM':
        if len(data) < 16:
            raise ValueError('INVALID_AUTH_TAG: GCM ciphertext shorter than 16-byte tag')
        tag = data[-16:]
        ciphertext = data[:-16]
        nonce = bytes.fromhex(hdr['nonce'])
        cipher = Cipher(algorithms.AES(enc_key), modes.GCM(nonce, tag))
        dec = cipher.decryptor()
        dec.authenticate_additional_data(raw_header + (aad or b''))
        try:
            pt = dec.update(ciphertext) + dec.finalize()
        except Exception:
            raise ValueError('INVALID_AUTH_TAG: AES-GCM integrity/authenticity check failed (tampering or wrong key/AAD)')
        with open(out_path, 'wb') as fo:
            fo.write(pt)
        return {"mode": "GCM", "bytes": len(pt)}

    if not mac_key:
        raise ValueError(f'mac_key is required to verify HMAC in {actual_mode}')
    if len(data) < 32:
        raise ValueError('INVALID_AUTH_TAG: Ciphertext shorter than 32-byte HMAC-SHA256 tag')

    tag = data[-32:]
    ciphertext = data[:-32]
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256())
    mac.update(raw_header)
    mac.update(ciphertext)
    try:
        mac.verify(tag)
    except Exception:
        raise ValueError(f'INVALID_AUTH_TAG: HMAC-SHA256 verification failed in {actual_mode} (tampering detected)')

    if actual_mode == 'CBC-HMAC':
        iv = bytes.fromhex(hdr['iv'])
        pad_scheme = hdr.get('pad', 'PKCS7')
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        dec = cipher.decryptor()
        unpad = _get_unpadder(pad_scheme, hdr.get('block_bits', BLOCK_SIZE_BITS))
        pt = unpad.update(dec.update(ciphertext) + dec.finalize()) + unpad.finalize()
        with open(out_path, 'wb') as fo:
            fo.write(pt)
        return {"mode": "CBC-HMAC", "bytes": len(pt), "pad": pad_scheme}

    if actual_mode == 'CTR-HMAC':
        nonce = bytes.fromhex(hdr['nonce'])
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
        dec = cipher.decryptor()
        pt = dec.update(ciphertext) + dec.finalize()
        with open(out_path, 'wb') as fo:
            fo.write(pt)
        return {"mode": "CTR-HMAC", "bytes": len(pt)}

    raise ValueError(f'Unsupported container mode: {actual_mode}')
