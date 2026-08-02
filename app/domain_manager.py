"""
Управление доменом и SSL.

Режимы (ssl_mode):
  caddy    — автоматически через Caddy на 80/443 (если порты свободны)
  dns      — Let's Encrypt через DNS-01 (acme.sh + Cloudflare), 443 не нужен
  external — готовые сертификаты (например, от Xray/acme.sh), 443 не занимаем
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

SSL_MODES = ("caddy", "dns", "external")

CADDY_BIN = os.environ.get("CADDY_BIN", "/usr/local/bin/caddy")
CADDY_DATA = Path(os.environ.get("CADDY_DATA", "/app/data/caddy"))
CADDYFILE_PATH = Path(os.environ.get("CADDYFILE_PATH", "/app/data/Caddyfile"))
CERTS_DIR = Path(os.environ.get("CERTS_DIR", "/app/data/certs"))
ACME_SH = Path(os.environ.get("ACME_SH", "/root/.acme.sh/acme.sh"))
PANEL_PORT = int(os.environ.get("PANEL_PORT", "8000"))
ACME_EMAIL = os.environ.get("ACME_EMAIL", "").strip()

_proc_lock = threading.Lock()
_process: Optional[subprocess.Popen] = None

CADDY_DATA.mkdir(parents=True, exist_ok=True)
CERTS_DIR.mkdir(parents=True, exist_ok=True)


def _row_to_dict(row) -> dict:
    return dict(row) if row else {}


def get_settings() -> dict:
    with db_cursor() as cur:
        row = cur.execute("SELECT * FROM domain_settings WHERE id=1").fetchone()
    data = _row_to_dict(row) or {}
    if not data:
        return {
            "id": 1,
            "domain": None,
            "ssl_mode": "external",
            "ssl_status": "none",
            "ssl_error": None,
            "cert_path": None,
            "key_path": None,
            "verified_at": None,
            "ssl_issued_at": None,
            "updated_at": 0,
        }
    if not data.get("ssl_mode"):
        data["ssl_mode"] = "external"
    return data


def _update_settings(**fields):
    fields["updated_at"] = now()
    cols = ", ".join(f"{k}=?" for k in fields)
    vals = list(fields.values())
    with db_cursor(write=True) as cur:
        cur.execute(f"UPDATE domain_settings SET {cols} WHERE id=1", vals)


def is_https_ready() -> bool:
    """HTTPS-прокси порты доступны, если заданы рабочие пути к сертификату и ключу."""
    return get_tls_paths() is not None


def is_ssl_active() -> bool:
    s = get_settings()
    return s.get("ssl_status") == "active" and bool(s.get("domain"))


def _hostname_from_cert_path(cert_path: str) -> Optional[str]:
    m = re.search(r"/live/([^/]+)/", cert_path)
    return m.group(1) if m else None


def get_connection_host(fallback_ip: str) -> str:
    s = get_settings()
    if s.get("domain"):
        return s["domain"]
    cert = s.get("cert_path") or ""
    host = _hostname_from_cert_path(cert)
    if host:
        return host
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


def validate_ssl_mode(mode: str) -> str:
    mode = (mode or "external").strip().lower()
    if mode not in SSL_MODES:
        raise ValueError(f"Режим SSL должен быть один из: {', '.join(SSL_MODES)}")
    return mode


def validate_cert_path(path: str, label: str) -> str:
    path = path.strip()
    if not path:
        raise ValueError(f"Укажите путь к {label}")
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"Файл не найден: {path}")
    if not os.access(p, os.R_OK):
        raise ValueError(f"Нет доступа на чтение: {path}")
    # Не resolve(): Let's Encrypt live/*.pem — симлинки, resolve() «замораживает» archive-путь.
    return path


def set_domain(domain: str, ssl_mode: Optional[str] = None) -> dict:
    domain = validate_domain(domain)
    current = get_settings()
    mode = validate_ssl_mode(ssl_mode) if ssl_mode else current.get("ssl_mode", "external")

    if current.get("domain") != domain:
        stop_caddy()

    _update_settings(
        domain=domain,
        ssl_mode=mode,
        ssl_status="pending",
        ssl_error=None,
        verified_at=None,
        ssl_issued_at=None,
    )
    return get_settings()


def set_ssl_mode(ssl_mode: str, cert_path: Optional[str] = None, key_path: Optional[str] = None) -> dict:
    mode = validate_ssl_mode(ssl_mode)
    fields: dict = {"ssl_mode": mode}

    if mode == "external":
        if not cert_path or not key_path:
            raise ValueError("Для внешнего режима укажите пути к сертификату и ключу")
        fields["cert_path"] = validate_cert_path(cert_path, "сертификату")
        fields["key_path"] = validate_cert_path(key_path, "ключу")
    else:
        fields["cert_path"] = cert_path.strip() if cert_path else None
        fields["key_path"] = key_path.strip() if key_path else None

    if mode != "caddy":
        stop_caddy()

    if get_settings().get("ssl_status") == "active" and mode == "external":
        fields["ssl_status"] = "verified"

    _update_settings(**fields)
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
        cert_path=None,
        key_path=None,
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
        _update_settings(ssl_status="error", ssl_error="DNS-запись не найдена.")
        raise ValueError("DNS-запись не найдена. Добавьте A-запись, указывающую на IP сервера.")

    if expected_ip not in resolved:
        _update_settings(
            ssl_status="error",
            ssl_error=f"Домен → {', '.join(sorted(resolved))}, ожидается {expected_ip}",
        )
        raise ValueError(
            f"Домен указывает на {', '.join(sorted(resolved))}, а IP сервера — {expected_ip}"
        )

    _update_settings(ssl_status="verified", ssl_error=None, verified_at=now())
    return get_settings()


def _find_caddy_cert_paths(domain: str) -> Optional[tuple[str, str]]:
    for cert_dir in CADDY_DATA.glob(f"certificates/*/{domain}"):
        cert = cert_dir / f"{domain}.crt"
        key = cert_dir / f"{domain}.key"
        if cert.exists() and key.exists():
            return str(cert), str(key)
    return None


def _find_stored_cert_paths(domain: str) -> Optional[tuple[str, str]]:
    base = CERTS_DIR / domain
    fullchain = base / "fullchain.pem"
    key = base / "key.pem"
    if fullchain.exists() and key.exists():
        return str(fullchain), str(key)
    return None


def get_cert_sans(cert_path: str) -> list[str]:
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-ext", "subjectAltName"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        ).stdout
        return re.findall(r"DNS:([^,\s]+)", out)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return []


def validate_tls_pair(cert_path: str, key_path: str) -> tuple[bool, str]:
    """Проверка пары cert/key (RSA и ECDSA / Let's Encrypt)."""
    try:
        subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout"],
            capture_output=True,
            check=True,
            timeout=5,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", key_path, "-noout"],
            capture_output=True,
            check=True,
            timeout=5,
        )
        cert_pub = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-pubkey"],
            capture_output=True,
            check=True,
            timeout=5,
            text=True,
        ).stdout.strip()
        key_pub = subprocess.run(
            ["openssl", "pkey", "-in", key_path, "-pubout"],
            capture_output=True,
            check=True,
            timeout=5,
            text=True,
        ).stdout.strip()
        if cert_pub and cert_pub == key_pub:
            return True, ""
        return False, "Сертификат и ключ не совпадают"
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
        return False, f"Ошибка проверки TLS: {e}"


def tls_status() -> dict:
    paths = get_tls_paths()
    if not paths:
        return {
            "ready": False,
            "valid": False,
            "error": "Укажите tls-cert и tls-key",
            "sans": [],
        }
    cert, key = paths
    valid, err = validate_tls_pair(cert, key)
    sans = get_cert_sans(cert)
    domain = get_settings().get("domain")
    domain_ok = True
    if domain and sans:
        domain_ok = domain in sans or any(
            san.startswith("*.") and domain.endswith(san[1:]) for san in sans
        )
    return {
        "ready": True,
        "valid": valid,
        "error": err,
        "sans": sans,
        "domain_match": domain_ok,
        "cert_path": cert,
        "key_path": key,
    }


def get_tls_paths() -> Optional[tuple[str, str]]:
    """Пути tls-cert / tls-key для HTTPS-прокси (как https_port в Squid)."""
    s = get_settings()
    if s.get("cert_path") and s.get("key_path"):
        cp, kp = Path(s["cert_path"]), Path(s["key_path"])
        if cp.is_file() and kp.is_file():
            return str(cp), str(kp)

    domain = s.get("domain")
    if domain:
        stored = _find_stored_cert_paths(domain)
        if stored:
            return stored
        caddy = _find_caddy_cert_paths(domain)
        if caddy:
            return caddy
    return None


def get_cert_paths() -> Optional[tuple[str, str]]:
    return get_tls_paths()


def find_cert_paths(domain: str) -> Optional[tuple[str, str]]:
    """Совместимость с proxy_manager."""
    s = get_settings()
    if s.get("domain") == domain:
        return get_cert_paths()
    stored = _find_stored_cert_paths(domain)
    if stored:
        return stored
    return _find_caddy_cert_paths(domain)


def xray_hint(domain: str) -> dict:
    s = get_settings()
    cert, key = get_cert_paths() or (s.get("cert_path") or "/path/to/fullchain.pem", s.get("key_path") or "/path/to/key.pem")
    return {
        "title": "Xray уже слушает 443 — настройте проброс панели",
        "steps": [
            f"Сертификаты: {cert} и {key}",
            f"Панель слушает HTTP на 127.0.0.1:{PANEL_PORT} (не занимает 443)",
            "Добавьте fallback в TLS-inbound Xray на 443",
        ],
        "snippet": (
            "{\n"
            '  "fallbacks": [\n'
            "    {\n"
            '      "name": "panel",\n'
            f'      "dest": "127.0.0.1:{PANEL_PORT}",\n'
            '      "xver": 1\n'
            "    }\n"
            "  ]\n"
            "}\n"
            f"// Браузерный HTTPS на https://{domain} → fallback → панель\n"
            f"// TLS-сертификаты в inbound Xray: certificateFile={cert}, keyFile={key}"
        ),
    }


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


def _run_acme(args: list[str], env: Optional[dict] = None) -> subprocess.CompletedProcess:
    if not ACME_SH.is_file():
        raise ValueError("acme.sh не установлен в контейнере")
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    result = subprocess.run(
        [str(ACME_SH), *args],
        capture_output=True,
        text=True,
        env=run_env,
        timeout=300,
    )
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip()[-600:]
        raise ValueError(tail or "Ошибка acme.sh")
    return result


def is_cf_configured() -> bool:
    return bool(os.environ.get("CF_API_TOKEN", "").strip())


def get_ssl_guide(mode: str, domain: Optional[str], server_ip: str) -> dict:
    domain = domain or "proxy.example.com"
    ip = server_ip if server_ip not in ("unknown", "", None) else "IP_СЕРВЕРА"
    cf = is_cf_configured()

    guides = {
        "external": {
            "title": "443 занят Xray — подключение без Cloudflare",
            "badge": "Рекомендуется",
            "summary": "Используйте сертификаты, которые уже есть на сервере (Xray, acme.sh). Панель не занимает 443.",
            "steps": [
                f"В DNS добавьте A-запись: {domain} → {ip}",
                "Если сертификата ещё нет — выпустите на сервере (см. команду ниже) или используйте файлы Xray",
                "Откройте docker-compose.yml и добавьте volume (раскомментируйте строку):",
                "  - /etc/xray:/etc/xray:ro",
                "Пересоберите контейнер: docker-compose up -d --build",
                f"Введите пути к файлам внутри контейнера, например: /etc/xray/cert/fullchain.pem и /etc/xray/cert/key.pem",
                "Нажмите «Сохранить пути» → «Проверить DNS» → «Подключить SSL»",
                "В конфиге Xray на inbound :443 добавьте fallback на панель (127.0.0.1:8000) — пример появится ниже",
            ],
            "command": (
                "# Выпуск сертификата на сервере (если Xray ещё без TLS):\n"
                "curl -fsSL https://get.acme.sh | sh\n"
                "~/.acme.sh/acme.sh --issue -d "
                + domain
                + " --standalone\n"
                "# Затем укажите пути к fullchain.pem и key.pem в админке"
            ),
        },
        "dns": {
            "title": "DNS-режим — автоматический Let's Encrypt через Cloudflare",
            "badge": "Нужен CF_API_TOKEN" if not cf else "Готов к выпуску",
            "summary": (
                "Сертификат выпускается автоматически через DNS Cloudflare. Порт 443 не занимается."
                if cf
                else "Без CF_API_TOKEN этот режим недоступен. Используйте режим «Внешний» — он проще при Xray на 443."
            ),
            "steps": (
                [
                    "Создайте API Token в Cloudflare: My Profile → API Tokens → Create Token",
                    "Шаблон: Edit zone DNS (или Custom: Zone → DNS → Edit)",
                    "Скопируйте токен и добавьте в .env на сервере: CF_API_TOKEN=ваш_токен",
                    "Перезапустите контейнер: docker-compose up -d --build",
                    f"A-запись: {domain} → {ip} (можно через Cloudflare)",
                    "В админке: сохраните домен → Проверить DNS → Выпустить SSL",
                    "Настройте fallback Xray на 127.0.0.1:8000 для HTTPS-панели",
                ]
                if not cf
                else [
                    f"A-запись: {domain} → {ip}",
                    "CF_API_TOKEN уже задан в .env",
                    "Сохраните домен → Проверить DNS → Выпустить SSL",
                    "Настройте fallback Xray на 127.0.0.1:8000",
                ]
            ),
            "command": None,
        },
        "caddy": {
            "title": "Caddy — автоматический HTTPS на 80/443",
            "badge": "Только если 443 свободен",
            "summary": "Caddy сам получит сертификат и будет проксировать панель. Не используйте, если 443 занят Xray.",
            "steps": [
                "Остановите всё, что слушает 80 и 443 (включая Xray на 443)",
                f"A-запись: {domain} → {ip}",
                "Сохраните домен → Проверить DNS → Выпустить SSL",
                "Панель откроется по https://ваш-домен",
            ],
            "command": None,
        },
    }

    guide = guides.get(mode, guides["external"])
    return {
        **guide,
        "mode": mode,
        "cf_token_configured": cf,
        "can_activate_dns": cf,
        "recommended_mode": "external",
    }


def _dns_token_error() -> str:
    return (
        "DNS-режим недоступен: не задан CF_API_TOKEN. "
        "Выберите режим «Внешний» и укажите пути к сертификатам Xray — "
        "инструкция отображается на этой странице."
    )


def _issue_cert_dns(domain: str) -> tuple[str, str]:
    token = os.environ.get("CF_API_TOKEN", "").strip()
    if not token:
        raise ValueError(_dns_token_error())

    email = ACME_EMAIL or f"admin@{domain}"
    domain_dir = CERTS_DIR / domain
    domain_dir.mkdir(parents=True, exist_ok=True)

    acme_env = {
        "CF_Token": token,
        "CF_Account_ID": os.environ.get("CF_ACCOUNT_ID", "").strip(),
    }

    _run_acme(["--set-default-ca", "--server", "letsencrypt"], acme_env)
    _run_acme(
        [
            "--issue", "--dns", "dns_cf", "-d", domain,
            "--keylength", "ec-256",
            "--force",
            "--accountemail", email,
        ],
        acme_env,
    )
    _run_acme(
        [
            "--install-cert", "-d", domain,
            "--cert-file", str(domain_dir / "cert.pem"),
            "--key-file", str(domain_dir / "key.pem"),
            "--fullchain-file", str(domain_dir / "fullchain.pem"),
            "--reloadcmd", "true",
        ],
        acme_env,
    )

    fullchain = domain_dir / "fullchain.pem"
    key = domain_dir / "key.pem"
    if not fullchain.is_file() or not key.is_file():
        raise ValueError("Сертификат не был сохранён после выпуска")

    return str(fullchain), str(key)


def _activate_external() -> dict:
    s = get_settings()
    cert = validate_cert_path(s.get("cert_path") or "", "сертификату")
    key = validate_cert_path(s.get("key_path") or "", "ключу")
    _update_settings(
        cert_path=cert,
        key_path=key,
        ssl_status="active",
        ssl_error=None,
        ssl_issued_at=now(),
    )
    return get_settings()


async def _activate_caddy(domain: str) -> dict:
    _update_settings(ssl_status="issuing", ssl_error=None)
    start_caddy(domain)

    for _ in range(60):
        await asyncio.sleep(2)
        paths = _find_caddy_cert_paths(domain)
        if paths:
            _update_settings(
                cert_path=paths[0],
                key_path=paths[1],
                ssl_status="active",
                ssl_error=None,
                ssl_issued_at=now(),
            )
            return get_settings()
        if not is_caddy_running():
            break

    err = "Caddy не смог занять 80/443. Если 443 занят Xray — используйте режим DNS или Внешний."
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


async def activate_ssl() -> dict:
    settings = get_settings()
    domain = settings.get("domain")
    mode = settings.get("ssl_mode", "external")

    if not domain:
        raise ValueError("Сначала укажите домен")
    if settings.get("ssl_status") not in ("verified", "active", "error"):
        raise ValueError("Сначала проверьте DNS")

    if mode == "caddy":
        return await _activate_caddy(domain)

    if mode == "external":
        stop_caddy()
        return _activate_external()

    # dns — без занятия 443
    if not is_cf_configured():
        raise ValueError(_dns_token_error())
    stop_caddy()
    _update_settings(ssl_status="issuing", ssl_error=None)
    try:
        cert, key = await asyncio.to_thread(_issue_cert_dns, domain)
    except ValueError as e:
        _update_settings(ssl_status="error", ssl_error=str(e))
        raise

    _update_settings(
        cert_path=cert,
        key_path=key,
        ssl_status="active",
        ssl_error=None,
        ssl_issued_at=now(),
    )
    return get_settings()


def ensure_caddy():
    settings = get_settings()
    if (
        settings.get("ssl_mode") == "caddy"
        and settings.get("ssl_status") == "active"
        and settings.get("domain")
    ):
        start_caddy(settings["domain"])


def save_tls_config(
    cert_path: str,
    key_path: str,
    domain: Optional[str] = None,
) -> dict:
    """Сохранить tls-cert / tls-key — сразу включает HTTPS-прокси порты."""
    cert = validate_cert_path(cert_path, "tls-cert")
    key = validate_cert_path(key_path, "tls-key")
    fields: dict = {"cert_path": cert, "key_path": key, "ssl_error": None}
    if domain is not None:
        d = domain.strip().lower().rstrip(".")
        if d:
            fields["domain"] = validate_domain(d)
        else:
            fields["domain"] = _hostname_from_cert_path(cert)
    elif not get_settings().get("domain"):
        auto = _hostname_from_cert_path(cert)
        if auto:
            fields["domain"] = auto
    _update_settings(**fields)
    return get_settings()


def require_https_allowed():
    if not is_https_ready():
        raise ValueError(
            "Укажите пути tls-cert и tls-key в разделе «TLS» (как https_port в Squid)"
        )


def public_settings(fallback_ip: str) -> dict:
    s = get_settings()
    mode = s.get("ssl_mode", "external")
    active = is_ssl_active()
    hint = xray_hint(s["domain"]) if active and mode in ("dns", "external") and s.get("domain") else None

    guide = get_ssl_guide(mode, s.get("domain"), fallback_ip)
    tls = tls_status()

    return {
        "domain": s.get("domain"),
        "ssl_mode": mode,
        "ssl_status": s.get("ssl_status") or "none",
        "ssl_error": s.get("ssl_error"),
        "ssl_active": active,
        "cert_path": s.get("cert_path"),
        "key_path": s.get("key_path"),
        "verified_at": s.get("verified_at"),
        "ssl_issued_at": s.get("ssl_issued_at"),
        "connection_host": get_connection_host(fallback_ip),
        "panel_url": get_panel_url(fallback_ip),
        "server_ip": fallback_ip,
        "https_allowed": is_https_ready(),
        "tls_ready": is_https_ready(),
        "tls_valid": tls["valid"],
        "tls_error": tls["error"],
        "cert_sans": tls["sans"],
        "cert_domain_match": tls.get("domain_match", True),
        "xray_hint": hint,
        "cf_token_configured": is_cf_configured(),
        "ssl_guide": guide,
        "ssl_mode_labels": {
            "caddy": "Caddy (нужны свободные 80/443)",
            "dns": "DNS — Let's Encrypt через Cloudflare",
            "external": "Внешний — сертификаты Xray / acme.sh",
        },
    }
