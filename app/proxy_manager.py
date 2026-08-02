"""
Логика управления портами/пользователями и генерация/применение
конфига 3proxy.
"""
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from app import domain_manager
from app.database import db_cursor, now

CONFIG_PATH = Path(os.environ.get("PROXY_CONFIG_PATH", "/app/data/3proxy.cfg"))
LOG_DIR = Path(os.environ.get("PROXY_LOG_DIR", "/var/log/3proxy"))
THREEPROXY_BIN = os.environ.get("THREEPROXY_BIN", "/usr/local/bin/3proxy")
SSL_PLUGIN_PATH = os.environ.get("SSL_PLUGIN_PATH", "/usr/local/lib/3proxy/SSLPlugin.ld.so")

CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

_proc_lock = threading.Lock()
_process: Optional[subprocess.Popen] = None
_last_proxy_error: Optional[str] = None


# ---------------------------------------------------------------- Ports ----

def list_ports():
    with db_cursor() as cur:
        rows = cur.execute("SELECT * FROM ports ORDER BY port").fetchall()
        return [dict(r) for r in rows]


def count_https_ports() -> int:
    with db_cursor() as cur:
        row = cur.execute("SELECT COUNT(*) AS c FROM ports WHERE type='https'").fetchone()
        return row["c"] if row else 0


def create_port(port: int, ptype: str):
    if ptype not in ("http", "https"):
        raise ValueError("type must be 'http' or 'https'")
    if ptype == "https":
        domain_manager.require_https_allowed()
    if not (1 <= port <= 65535):
        raise ValueError("port must be in range 1-65535")
    with db_cursor(write=True) as cur:
        existing = cur.execute("SELECT 1 FROM ports WHERE port=?", (port,)).fetchone()
        if existing:
            raise ValueError(f"Порт {port} уже используется")
        cur.execute(
            "INSERT INTO ports (port, type, created_at) VALUES (?, ?, ?)",
            (port, ptype, now()),
        )
        return cur.lastrowid


def delete_port(port_id: int):
    with db_cursor(write=True) as cur:
        cur.execute("DELETE FROM ports WHERE id=?", (port_id,))


# ---------------------------------------------------------------- Users ----

def list_users():
    with db_cursor() as cur:
        users = [dict(r) for r in cur.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()]
        for u in users:
            ports = cur.execute(
                """
                SELECT p.id, p.port, p.type FROM ports p
                JOIN user_ports up ON up.port_id = p.id
                WHERE up.user_id = ?
                ORDER BY p.port
                """,
                (u["id"],),
            ).fetchall()
            u["ports"] = [dict(p) for p in ports]
        return users


def create_user(username: str, password: str, port_ids: list[int]):
    with db_cursor(write=True) as cur:
        existing = cur.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            raise ValueError(f"Пользователь {username} уже существует")
        cur.execute(
            "INSERT INTO users (username, password, blocked, created_at) VALUES (?, ?, 0, ?)",
            (username, password, now()),
        )
        user_id = cur.lastrowid
        for pid in port_ids:
            cur.execute(
                "INSERT OR IGNORE INTO user_ports (user_id, port_id) VALUES (?, ?)",
                (user_id, pid),
            )
        return user_id


def set_user_ports(user_id: int, port_ids: list[int]):
    with db_cursor(write=True) as cur:
        cur.execute("DELETE FROM user_ports WHERE user_id=?", (user_id,))
        for pid in port_ids:
            cur.execute(
                "INSERT OR IGNORE INTO user_ports (user_id, port_id) VALUES (?, ?)",
                (user_id, pid),
            )


def set_user_blocked(user_id: int, blocked: bool):
    with db_cursor(write=True) as cur:
        cur.execute("UPDATE users SET blocked=? WHERE id=?", (1 if blocked else 0, user_id))


def delete_user(user_id: int):
    with db_cursor(write=True) as cur:
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))


# ------------------------------------------------------- Config / process --

def _build_config_text() -> str:
    with db_cursor() as cur:
        ports = cur.execute("SELECT * FROM ports ORDER BY port").fetchall()
        users = cur.execute("SELECT * FROM users WHERE blocked=0").fetchall()
        user_ports_rows = cur.execute(
            """
            SELECT up.user_id, up.port_id FROM user_ports up
            JOIN users u ON u.id = up.user_id
            WHERE u.blocked = 0
            """
        ).fetchall()

    port_to_users: dict[int, list[str]] = {}
    for row in user_ports_rows:
        port_to_users.setdefault(row["port_id"], []).append(row["user_id"])

    users_by_id = {u["id"]: u for u in users}

    lines = [
        "# Управляется OneClick Proxy Admin — не daemon, процесс держит Python",
        "maxconn 500",
        "nserver 8.8.8.8",
        "nserver 1.1.1.1",
        "nscache 65536",
        "timeouts 1 5 30 60 180 1800 15 60",
        f'log {LOG_DIR}/3proxy.log D',
        'logformat "- +_L%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"',
        "rotate 5",
        "",
    ]

    cert_paths = domain_manager.get_tls_paths()
    has_https = any(p["type"] == "https" for p in ports)
    use_ssl_plugin = bool(
        has_https and cert_paths and Path(SSL_PLUGIN_PATH).is_file()
    )

    if use_ssl_plugin:
        lines.append(f"plugin {SSL_PLUGIN_PATH} ssl_plugin")
        lines.append("")

    if users:
        # Все активные (не заблокированные) пользователи объявляются одной
        # строкой формата login:CL:password (CL = хранение в открытом виде,
        # что упрощает управление из БД).
        user_defs = " ".join(f"{u['username']}:CL:{u['password']}" for u in users)
        lines.append(f"users {user_defs}")
    else:
        lines.append("users dummy:CL:dummy")

    lines.append("")
    lines.append("auth strong")
    lines.append("")

    if not ports:
        lines.append("# Портов пока нет — 3proxy запущен без активных прокси-сервисов")

    for p in ports:
        allowed = [users_by_id[uid]["username"] for uid in port_to_users.get(p["id"], []) if uid in users_by_id]
        lines.append(f"# Порт {p['port']} ({p['type']})")
        lines.append("flush")
        if allowed:
            lines.append(f"allow {','.join(allowed)}")
        else:
            lines.append("deny *")
        if p["type"] == "https":
            if not cert_paths:
                lines.append(f"# HTTPS {p['port']} — задайте tls-cert и tls-key в админке")
                lines.append("deny *")
            elif not use_ssl_plugin:
                lines.append(f"# HTTPS {p['port']} — SSL plugin недоступен, выполните ./deploy.sh")
                lines.append("deny *")
            else:
                lines.append(f"# tls-cert={cert_paths[0]} tls-key={cert_paths[1]}")
                lines.append(f"ssl_server_cert {cert_paths[0]}")
                lines.append(f"ssl_server_key {cert_paths[1]}")
                lines.append("ssl_serv")
                lines.append(f"proxy -p{p['port']}")
        else:
            if use_ssl_plugin:
                lines.append("ssl_noserv")
            lines.append(f"proxy -p{p['port']}")
        lines.append("")

    return "\n".join(lines) + "\n"


def write_config() -> Path:
    text = _build_config_text()
    CONFIG_PATH.write_text(text)
    return CONFIG_PATH


def is_running() -> bool:
    with _proc_lock:
        return _process is not None and _process.poll() is None


def last_error() -> Optional[str]:
    return _last_proxy_error


def start():
    """Запускает 3proxy, если ещё не запущен."""
    global _process, _last_proxy_error
    write_config()
    with _proc_lock:
        if _process is not None and _process.poll() is None:
            return
        try:
            _process = subprocess.Popen(
                [THREEPROXY_BIN, str(CONFIG_PATH)],
                stderr=subprocess.PIPE,
            )
        except Exception as e:
            _last_proxy_error = str(e)
            _process = None
            return

    # 3proxy с неверным конфигом может завершиться сразу после старта.
    time.sleep(0.3)
    with _proc_lock:
        if _process is not None and _process.poll() is not None:
            err = ""
            if _process.stderr:
                err = _process.stderr.read().decode("utf-8", errors="replace").strip()
            code = _process.returncode
            _last_proxy_error = err or f"3proxy завершился с кодом {code}"
            _process = None
        else:
            _last_proxy_error = None


def restart():
    """Полный перезапуск 3proxy (нужен при смене TLS / plugin)."""
    stop()
    start()


def reload():
    """
    Перегенерирует конфиг и пытается применить его без обрыва сессий.
    3proxy умеет перечитывать конфигурацию по сигналу SIGUSR1 (некоторые
    сборки используют SIGHUP) без разрыва уже установленных соединений.
    Если по какой-то причине процесс не отвечает или не запущен —
    происходит обычный (быстрый) перезапуск.
    """
    write_config()
    with _proc_lock:
        proc = _process

    if proc is not None and proc.poll() is None:
        try:
            proc.send_signal(signal.SIGUSR1)
            time.sleep(0.25)
            with _proc_lock:
                if _process is not None and _process.poll() is None:
                    return
        except Exception:
            pass

    restart()


def stop():
    global _process
    with _proc_lock:
        if _process is not None and _process.poll() is None:
            _process.terminate()
            try:
                _process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _process.kill()
        _process = None
