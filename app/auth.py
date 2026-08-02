"""
Простая авторизация по паролю из переменной окружения ADMIN_PASSWORD.
Сессии — подписанные (itsdangerous) токены в httponly cookie,
без необходимости хранить состояние в БД.
"""
import os
import secrets

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
SESSION_MAX_AGE = 60 * 60 * 24 * 7  # 7 дней
COOKIE_NAME = "proxy_panel_session"

_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="proxy-panel-auth")


def check_password(password: str) -> bool:
    return secrets.compare_digest(password, ADMIN_PASSWORD)


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
