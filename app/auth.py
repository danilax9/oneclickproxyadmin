"""
Простая авторизация по паролю из переменной окружения ADMIN_PASSWORD.
Сессии — подписанные (itsdangerous) токены в httponly cookie,
без необходимости хранить состояние в БД.
"""
import os
import secrets

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

SECRET_KEY_FILE = os.environ.get("SECRET_KEY_FILE", "/app/data/.secret_key")


def _load_secret_key() -> str:
    env = (os.environ.get("SECRET_KEY") or "").strip()
    if env:
        return env
    try:
        with open(SECRET_KEY_FILE, encoding="utf-8") as f:
            stored = f.read().strip()
            if stored:
                return stored
    except FileNotFoundError:
        pass
    key = secrets.token_hex(32)
    os.makedirs(os.path.dirname(SECRET_KEY_FILE) or ".", exist_ok=True)
    with open(SECRET_KEY_FILE, "w", encoding="utf-8") as f:
        f.write(key)
    return key


SECRET_KEY = _load_secret_key()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme").strip()
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 дней
COOKIE_NAME = "proxy_panel_session"

_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="proxy-panel-auth")


def check_password(password: str) -> bool:
    return secrets.compare_digest(password.strip(), ADMIN_PASSWORD)


def create_session_token() -> str:
    return _serializer.dumps({"ok": True})


def verify_session_token(token: str | None) -> bool:
    if not token:
        return False
    try:
        _serializer.loads(token, max_age=SESSION_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False
