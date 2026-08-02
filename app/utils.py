import secrets
import string
import time

import httpx

_IP_CACHE: dict = {"ip": None, "ts": 0}
_IP_TTL = 300  # секунд
_IP_SOURCES = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]


async def get_external_ip() -> str:
    now = time.time()
    if _IP_CACHE["ip"] and now - _IP_CACHE["ts"] < _IP_TTL:
        return _IP_CACHE["ip"]

    async with httpx.AsyncClient(timeout=5) as client:
        for url in _IP_SOURCES:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                ip = resp.text.strip()
                if ip:
                    _IP_CACHE["ip"] = ip
                    _IP_CACHE["ts"] = now
                    return ip
            except Exception:
                continue

    return _IP_CACHE["ip"] or "unknown"


_ALPHABET = string.ascii_lowercase + string.digits


def gen_username(prefix: str = "user") -> str:
    return f"{prefix}_{''.join(secrets.choice(_ALPHABET) for _ in range(6))}"


def gen_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))
