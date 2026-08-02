"""
Управление доменом и SSL-сертификатами через Caddy (Let's Encrypt).
HTTPS-порты и строки подключения https:// доступны только при активном SSL.
"""
import asyncio
import os
import re
import signal
import socket
import subprocess
import threading
from pathlib import Path
from typing import Optional

from app.database import db_cursor, now

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)

CADDY_BIN = os.environ.get("CADDY_BIN", "/usr/local/bin/caddy")
CADDY_DATA = Path(os.environ.get("CADDY_DATA", "/app/data/caddy"))
CADDYFILE_PATH = Path(os.environ.get("CADDYFILE_PATH", "/app/data/Caddyfile"))
PANEL_PORT = int(os.environ.get("PANEL_PORT", "8000"))
ACME_EMAIL = os.environ.get("ACME_EMAIL", "").strip()

_proc_lock = threading.Lock()
_process: Optional[subprocess.Popen] = None

CADDY_DATA.mkdir(parents=True, exist_ok=True)


def _row_to_dict(row) -> dict:
    return dict(row) if row else {}


def get_settings() -> dict:
    with db_cursor() as cur:
        row = cur.execute("SELECT * FROM domain_settings WHERE id=1").fetchone()
    return _row_to_dict(row) or {
        "id": 1,
        "domain": None,
        "ssl_status": "none",
        "ssl_error": None,
        "verified_at": None,
        "ssl_issued_at": None,
        "updated_at": 0,
    }


def _update_settings(**fields):
    fields["updated_at"] = now()
    cols = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values())
    with db_cursor(write=True) as cur:
        cur.execute(f"UPDATE domain_settings SET {cols} WHERE id=1", vals)


def is_ssl_active() -> bool:
    s = get_settings()
    return s.get("ssl_status") == "active" and bool(s.get("domain"))


def get_connection_host(fallback_ip: str) -> str:
    s = get_settings()
    if s.get("ssl_status") == "active" and s.get("domain"):
        return s["domain"]
    return fallback_ip


def get_panel_url(fallback_ip: str) -> str:
    s = get_settings()
    if s.get("ssl_status") == "active" and s.get("domain"):
        return f"https://{s['domain']}"
    return f"http://{fallback_ip}:{PANEL_PORT}"


def validate_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        raise ValueError("Укажите домен")
    if not DOMAIN_RE.match(domain):
        raise ValueError("Некорректный формат домена")
    if len(domain) > 253:
        raise ValueError("Домен слишком длинный")
    return domain


def set_domain(domain: str) -> dict:
    domain = validate_domain(domain)
    current = get_settings()
    if current.get("domain") != domain:
        stop_caddy()
    _update_settings(
        domain=domain,
        ssl_status="pending",
        ssl_error=None,
        verified_at=None,
        ssl_issued_at=None,
    )
    return get_settings()


def remove_domain() -> dict:
    from app.proxy_manager import count_https_ports

    if count_https_ports() > 0:
        raise ValueError("Сначала удалите все HTTPS-порты")
    stop_caddy()
    _update_settings(
        domain=None,
        ssl_status="none",
        ssl_error=None,
        verified_at=None,
        ssl_issued_at=None,
    )
    return get_settings()


def verify_dns(expected_ip: str) -> dict:
    settings = get_settings()
    domain = settings.get("domain")
    if not domain:
        raise ValueError("Домен не задан")

    if expected_ip in ("unknown", "", None):
        raise ValueError("Не удалось определить IP сервера")

    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        resolved = {item[4][0] for item in results}
    except socket.gaierror:
        _update_settings(ssl_status="error", ssl_error="DNS-запись не найдена. Добавьте A-запись на IP сервера.")
        raise ValueError("DNS-запись не найдена. Добавьте A-запись, указывающую на IP сервера.")

    if expected_ip not in resolved:
        _update_settings(
            ssl_status="error",
            ssl_error=f"Домен указывает на {', '.join(sorted(resolved))}, ожидается {expected_ip}",
        )
        raise ValueError(
            f"Домен указывает на {', '.join(sorted(resolved))}, а IP сервера — {expected_ip}"
        )

    _update_settings(ssl_status="verified", ssl_error=None, verified_at=now())
    return get_settings()


def find_cert_paths(domain: str) -> Optional[tuple[str, str]]:
    for cert_dir in CADDY_DATA.glob(f"certificates/*/{domain}"):
        cert = cert_dir / f"{domain}.crt"
        key = cert_dir / f"{domain}.key"
        if cert.exists() and key.exists():
            return str(cert), str(key)
    return None


def _build_caddyfile(domain: str) -> str:
    email = ACME_EMAIL or f"admin@{domain}"
    return f"""{{
    email {email}
}}

{domain} {{
    reverse_proxy 127.0.0.1:{PANEL_PORT}
}}
"""


def write_caddyfile(domain: str) -> Path:
    CADDYFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CADDYFILE_PATH.write_text(_build_caddyfile(domain), encoding="utf-8")
    return CADDYFILE_PATH


def is_caddy_running() -> bool:
    with _proc_lock:
        return _process is not None and _process.poll() is None


def start_caddy(domain: str):
    global _process
    write_caddyfile(domain)
    env = os.environ.copy()
    env["XDG_DATA_HOME"] = str(CADDY_DATA.parent)

    with _proc_lock:
        if _process is not None and _process.poll() is None:
            try:
                subprocess.run(
                    [
                        CADDY_BIN, "reload",
                        "--config", str(CADDYFILE_PATH),
                        "--adapter", "caddyfile",
                        "--data", str(CADDY_DATA),
                    ],
                    check=True,
                    capture_output=True,
                    env=env,
                )
                return
            except (subprocess.CalledProcessError, FileNotFoundError):
                _process.terminate()
                _process = None

        _process = subprocess.Popen(
            [
                CADDY_BIN, "run",
                "--config", str(CADDYFILE_PATH),
                "--adapter", "caddyfile",
                "--data", str(CADDY_DATA),
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )


def stop_caddy():
    global _process
    with _proc_lock:
        if _process is not None and _process.poll() is None:
            _process.send_signal(signal.SIGTERM)
            try:
                _process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _process.kill()
        _process = None


async def activate_ssl() -> dict:
    settings = get_settings()
    domain = settings.get("domain")
    if not domain:
        raise ValueError("Сначала укажите домен")
    if settings.get("ssl_status") not in ("verified", "active", "error"):
        raise ValueError("Сначала проверьте DNS")

    _update_settings(ssl_status="issuing", ssl_error=None)
    start_caddy(domain)

    for _ in range(60):
        await asyncio.sleep(2)
        paths = find_cert_paths(domain)
        if paths:
            _update_settings(ssl_status="active", ssl_error=None, ssl_issued_at=now())
            return get_settings()
        if not is_caddy_running():
            break

    err = "Не удалось выпустить сертификат. Убедитесь, что порты 80 и 443 открыты и свободны."
    with _proc_lock:
        proc = _process
    if proc and proc.stdout:
        try:
            import select
            if select.select([proc.stdout], [], [], 0)[0]:
                log = proc.stdout.read(4096).decode("utf-8", errors="replace")
                if log.strip():
                    err = log.strip()[-500:]
        except Exception:
            pass
    _update_settings(ssl_status="error", ssl_error=err)
    raise ValueError(err)


def ensure_caddy():
    settings = get_settings()
    if settings.get("ssl_status") == "active" and settings.get("domain"):
        start_caddy(settings["domain"])


def require_https_allowed():
    if not is_ssl_active():
        raise ValueError(
            "HTTPS-порты доступны только после подключения домена и выпуска SSL-сертификата"
        )


def public_settings(fallback_ip: str) -> dict:
    s = get_settings()
    return {
        "domain": s.get("domain"),
        "ssl_status": s.get("ssl_status") or "none",
        "ssl_error": s.get("ssl_error"),
        "ssl_active": is_ssl_active(),
        "verified_at": s.get("verified_at"),
        "ssl_issued_at": s.get("ssl_issued_at"),
        "connection_host": get_connection_host(fallback_ip),
        "panel_url": get_panel_url(fallback_ip),
        "server_ip": fallback_ip,
        "https_allowed": is_ssl_active(),
    }
