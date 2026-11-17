"""Security features kept independent from Flask/DB for isolated testing."""
import base64
import hashlib
import re
import socket
import struct
from datetime import datetime, timezone

import pyotp
from cryptography.fernet import Fernet


def _fernet(configured_key: str):
    if not configured_key:
        raise RuntimeError("MFA_ENCRYPTION_KEY is required for admin TOTP.")
    return Fernet(configured_key.encode("ascii"))


def encrypt_totp(secret: str, key: str) -> bytes:
    return _fernet(key).encrypt(secret.encode("ascii"))


def decrypt_totp(ciphertext: bytes, key: str) -> str:
    return _fernet(key).decrypt(ciphertext).decode("ascii")


def match_totp_timecode(secret: str, code: str, last_timecode: int = -1, now=None):
    """Return next usable 30-second step or None; prevents TOTP replay."""
    if not re.fullmatch(r"[0-9]{6}", str(code)):
        return None
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    now = now or datetime.now(timezone.utc)
    step = totp.timecode(now)
    for candidate in (step - 1, step, step + 1):
        if candidate > last_timecode and candidate >= 0:
            if pyotp.utils.strings_equal(totp.at(candidate * 30), code):
                return candidate
    return None


def scan_upload_with_clamd(data: bytes, socket_path: str):
    """Scan a full upload through the local ClamAV INSTREAM UNIX protocol.

    Raises on missing scanner, malformed response, timeouts or protocol errors.
    Only the explicit 'stream: OK' response is considered clean.
    """
    if not socket_path:
        raise RuntimeError("ClamAV socket not configured")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(10)
        conn.connect(socket_path)
        conn.sendall(b"zINSTREAM\0")
        for pos in range(0, len(data), 64 * 1024):
            piece = data[pos:pos + 64 * 1024]
            conn.sendall(struct.pack(">I", len(piece)))
            conn.sendall(piece)
        conn.sendall(struct.pack(">I", 0))
        response = bytearray()
        while len(response) < 8192:
            block = conn.recv(min(2048, 8192 - len(response)))
            if not block:
                break
            response.extend(block)
            if b"\0" in block:
                break
    verdict = bytes(response).split(b"\0", 1)[0].decode("ascii", "replace").strip()
    return verdict == "stream: OK", verdict
