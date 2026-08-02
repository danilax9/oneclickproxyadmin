from pathlib import Path
from typing import Optional
import asyncio
import logging
import os

from fastapi import BackgroundTasks, Cookie, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import auth, domain_manager, proxy_manager, utils
from app.database import init_db

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Proxy Panel")
log = logging.getLogger("uvicorn.error")


# --------------------------------------------------------------- Startup ---

@app.on_event("startup")
def on_startup():
    init_db()
    domain_manager.ensure_caddy()
    proxy_manager.ensure_running()


@app.on_event("shutdown")
def on_shutdown():
    proxy_manager.stop()
    domain_manager.stop_caddy()


# ----------------------------------------------------------------- Auth ----

def require_auth(session: Optional[str] = Cookie(default=None, alias=auth.COOKIE_NAME)):
    if not auth.verify_session_token(session):
        raise HTTPException(status_code=401, detail="Не авторизован")
    return True


class LoginBody(BaseModel):
    password: str


@app.post("/api/login")
def login(body: LoginBody):
    if not auth.check_password(body.password):
        raise HTTPException(status_code=401, detail="Неверный пароль")
    token = auth.create_session_token()
    response = JSONResponse(content={"ok": True})
    response.set_cookie(
        key=auth.COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=auth.SESSION_MAX_AGE,
    )
    return response


@app.post("/api/logout")
def logout():
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(key=auth.COOKIE_NAME, path="/")
    return response


@app.get("/api/me")
def me(_: bool = Depends(require_auth)):
    return {"ok": True}


# ------------------------------------------------------------ Server info --

@app.get("/api/server-info")
async def server_info(_: bool = Depends(require_auth)):
    ip = await utils.get_external_ip()
    loop = asyncio.get_running_loop()
    domain = await loop.run_in_executor(None, domain_manager.public_settings, ip)
    return {
        "ip": ip,
        "proxy_running": proxy_manager.is_running(),
        "proxy_error": proxy_manager.last_error(),
        "caddy_running": domain_manager.is_caddy_running(),
        **domain,
    }


@app.get("/api/proxy/diagnostics")
async def proxy_diagnostics(_: bool = Depends(require_auth)):
    return proxy_manager.diagnostics()


@app.post("/api/proxy/restart")
async def proxy_restart(_: bool = Depends(require_auth)):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, proxy_manager.restart)
    return {
        "ok": True,
        "proxy_running": proxy_manager.is_running(),
        "proxy_error": proxy_manager.last_error(),
    }


@app.post("/api/proxy/test-https")
async def proxy_test_https(_: bool = Depends(require_auth)):
    ip = await utils.get_external_ip()
    host = domain_manager.get_connection_host(ip)
    ports = [p for p in proxy_manager.list_ports() if p["type"] == "https"]
    if not ports:
        raise HTTPException(status_code=400, detail="Нет HTTPS-портов")
    port = ports[0]["port"]
    users = proxy_manager.list_users()
    candidate = None
    port_id = ports[0]["id"]
    for u in users:
        if u.get("blocked"):
            continue
        if any(p["id"] == port_id for p in u.get("ports") or []):
            candidate = u
            break
    if not candidate and users:
        candidate = next((u for u in users if not u.get("blocked")), None)
    if not candidate:
        raise HTTPException(status_code=400, detail="Нет пользователя для теста")
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(
                None,
                proxy_manager.test_https_proxy,
                host,
                port,
                candidate["username"],
                candidate["password"],
            ),
            timeout=60.0,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Таймаут проверки HTTPS-прокси")


@app.get("/api/tls/suggest")
async def tls_suggest(domain: str, _: bool = Depends(require_auth)):
    try:
        d = domain_manager.validate_domain(domain)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return domain_manager.default_letsencrypt_paths(d)


# ----------------------------------------------------------------- Domain --

class DomainBody(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    ssl_mode: Optional[str] = Field(default=None, pattern="^(caddy|dns|external)$")


class DomainSslBody(BaseModel):
    ssl_mode: str = Field(pattern="^(caddy|dns|external)$")
    cert_path: Optional[str] = None
    key_path: Optional[str] = None


class TlsBody(BaseModel):
    cert_path: str = Field(min_length=1)
    key_path: str = Field(min_length=1)
    domain: Optional[str] = None


@app.get("/api/domain")
async def get_domain(_: bool = Depends(require_auth)):
    ip = await utils.get_external_ip()
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, domain_manager.public_settings, ip)


@app.put("/api/domain")
def save_domain(body: DomainBody, _: bool = Depends(require_auth)):
    try:
        domain_manager.set_domain(body.domain, body.ssl_mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True}


async def _restart_proxy_after_tls():
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, proxy_manager.restart)
    except Exception:
        log.exception("proxy restart after TLS save failed")


@app.get("/api/health")
def health():
    tls = domain_manager.tls_status()
    return {
        "ok": True,
        "panel_port": os.environ.get("PANEL_PORT", "8000"),
        "proxy_running": proxy_manager.is_running(),
        "proxy_error": proxy_manager.last_error(),
        "letsencrypt_mounted": Path("/etc/letsencrypt").exists(),
        "ssl_plugin": Path(os.environ.get("SSL_PLUGIN_PATH", "/usr/local/lib/3proxy/SSLPlugin.ld.so")).is_file(),
        "tls_valid": tls.get("valid"),
        "tls_error": tls.get("error"),
        "tls_cert_count": tls.get("cert_count"),
    }


@app.post("/api/tls/validate")
async def validate_tls(body: TlsBody, _: bool = Depends(require_auth)):
    """Проверка путей без сохранения и перезапуска 3proxy."""
    loop = asyncio.get_running_loop()

    def check():
        cert = domain_manager.validate_cert_path(body.cert_path, "tls-cert", kind="fullchain")
        key = domain_manager.validate_cert_path(body.key_path, "tls-key", kind="privkey")
        valid, err = domain_manager.validate_tls_pair(cert, key)
        fullchain, count = domain_manager.build_fullchain_pem(cert)
        chain_ok, chain_err = domain_manager.verify_cert_chain_file(cert)
        return {
            "cert_path": cert,
            "key_path": key,
            "valid": valid and chain_ok,
            "error": err or chain_err,
            "cert_count": count,
            "sans": domain_manager.get_cert_sans(cert),
        }

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, check), timeout=20.0)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Таймаут проверки TLS")


@app.put("/api/tls")
@app.post("/api/tls")
async def save_tls(
    body: TlsBody,
    background_tasks: BackgroundTasks,
    _: bool = Depends(require_auth),
):
    loop = asyncio.get_running_loop()

    def save_only():
        domain_manager.save_tls_config(body.cert_path, body.key_path, body.domain)

    try:
        await asyncio.wait_for(loop.run_in_executor(None, save_only), timeout=30.0)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except OSError as e:
        raise HTTPException(status_code=400, detail=f"Ошибка доступа к файлам: {e}")
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail="Таймаут сохранения TLS — проверьте пути к fullchain.pem и privkey.pem",
        )
    except Exception as e:
        log.exception("save_tls failed")
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения TLS: {e}")

    background_tasks.add_task(_restart_proxy_after_tls)

    return {
        "ok": True,
        "tls_ready": True,
        "tls_valid": True,
        "proxy_running": proxy_manager.is_running(),
        "proxy_error": proxy_manager.last_error(),
        "proxy_restarting": True,
    }


@app.patch("/api/domain/ssl")
def save_domain_ssl(body: DomainSslBody, _: bool = Depends(require_auth)):
    try:
        domain_manager.set_ssl_mode(body.ssl_mode, body.cert_path, body.key_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True}


@app.post("/api/domain/verify")
async def verify_domain(_: bool = Depends(require_auth)):
    ip = await utils.get_external_ip()
    try:
        return domain_manager.verify_dns(ip)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/domain/activate")
async def activate_domain(_: bool = Depends(require_auth)):
    try:
        result = await domain_manager.activate_ssl()
        proxy_manager.reload()
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/domain")
def delete_domain(_: bool = Depends(require_auth)):
    try:
        domain_manager.remove_domain()
        proxy_manager.reload()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True}


# ------------------------------------------------------------------ Ports --

class PortCreate(BaseModel):
    port: int = Field(ge=1, le=65535)
    type: str = Field(pattern="^(http|https)$")


@app.get("/api/ports")
def get_ports(_: bool = Depends(require_auth)):
    return proxy_manager.list_ports()


@app.post("/api/ports")
def add_port(body: PortCreate, _: bool = Depends(require_auth)):
    try:
        port_id = proxy_manager.create_port(body.port, body.type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    proxy_manager.reload()
    return {"id": port_id}


@app.delete("/api/ports/{port_id}")
def remove_port(port_id: int, _: bool = Depends(require_auth)):
    proxy_manager.delete_port(port_id)
    proxy_manager.reload()
    return {"ok": True}


# ------------------------------------------------------------------ Users --

class UserCreate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    port_ids: list[int] = Field(default_factory=list)


class UserPortsUpdate(BaseModel):
    port_ids: list[int]


class UserBlockUpdate(BaseModel):
    blocked: bool


@app.get("/api/users")
def get_users(_: bool = Depends(require_auth)):
    return proxy_manager.list_users()


@app.post("/api/users")
def add_user(body: UserCreate, _: bool = Depends(require_auth)):
    username = body.username.strip() if body.username else utils.gen_username()
    password = body.password.strip() if body.password else utils.gen_password()
    if not username:
        username = utils.gen_username()
    if not password:
        password = utils.gen_password()
    try:
        user_id = proxy_manager.create_user(username, password, body.port_ids)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    proxy_manager.reload()
    return {"id": user_id, "username": username, "password": password}


@app.put("/api/users/{user_id}/ports")
def update_user_ports(user_id: int, body: UserPortsUpdate, _: bool = Depends(require_auth)):
    proxy_manager.set_user_ports(user_id, body.port_ids)
    proxy_manager.reload()
    return {"ok": True}


@app.patch("/api/users/{user_id}/block")
def block_user(user_id: int, body: UserBlockUpdate, _: bool = Depends(require_auth)):
    proxy_manager.set_user_blocked(user_id, body.blocked)
    proxy_manager.reload()
    return {"ok": True}


@app.delete("/api/users/{user_id}")
def remove_user(user_id: int, _: bool = Depends(require_auth)):
    proxy_manager.delete_user(user_id)
    proxy_manager.reload()
    return {"ok": True}


# ---------------------------------------------------------------- Frontend -

@app.get("/login")
def login_page():
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/")
def index_page(session: Optional[str] = Cookie(default=None, alias=auth.COOKIE_NAME)):
    if not auth.verify_session_token(session):
        return FileResponse(STATIC_DIR / "login.html")
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": str(exc)})
