"""
Слой работы с SQLite. Одно синхронное соединение + лок на запись —
для админ-панели с низкой нагрузкой этого более чем достаточно и
избавляет от лишних зависимостей (ORM, async-драйверов и т.д.).
"""
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "app.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

_lock = threading.Lock()
_conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
_conn.execute("PRAGMA journal_mode=WAL;")
_conn.execute("PRAGMA foreign_keys=ON;")
_conn.row_factory = sqlite3.Row


@contextmanager
def db_cursor(write: bool = False):
    """Контекстный менеджер для получения курсора. write=True берёт лок."""
    if write:
        with _lock:
            cur = _conn.cursor()
            try:
                yield cur
                _conn.commit()
            except Exception:
                _conn.rollback()
                raise
            finally:
                cur.close()
    else:
        cur = _conn.cursor()
        try:
            yield cur
        finally:
            cur.close()


def init_db():
    with db_cursor(write=True) as cur:
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port INTEGER NOT NULL UNIQUE,
                type TEXT NOT NULL CHECK(type IN ('http', 'https')),
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                blocked INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_ports (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                port_id INTEGER NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
                PRIMARY KEY (user_id, port_id)
            );

            CREATE TABLE IF NOT EXISTS domain_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                domain TEXT,
                ssl_status TEXT NOT NULL DEFAULT 'none',
                ssl_error TEXT,
                verified_at INTEGER,
                ssl_issued_at INTEGER,
                updated_at INTEGER NOT NULL DEFAULT 0
            );

            INSERT OR IGNORE INTO domain_settings (id, domain, ssl_status, updated_at)
            VALUES (1, NULL, 'none', 0);
            """
        )
        _migrate_domain_settings(cur)


def _migrate_domain_settings(cur):
    cols = {row[1] for row in cur.execute("PRAGMA table_info(domain_settings)")}
    if "ssl_mode" not in cols:
        cur.execute(
            "ALTER TABLE domain_settings ADD COLUMN ssl_mode TEXT NOT NULL DEFAULT 'external'"
        )
    if "cert_path" not in cols:
        cur.execute("ALTER TABLE domain_settings ADD COLUMN cert_path TEXT")
    if "key_path" not in cols:
        cur.execute("ALTER TABLE domain_settings ADD COLUMN key_path TEXT")


def now() -> int:
    return int(time.time())
