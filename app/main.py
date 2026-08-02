from pathlib import Path
from typing import Optional

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import auth, domain_manager, proxy_manager, utils
from app.database import init_db

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Proxy Panel")


# --------------------------------------------------------------- Startup ---

@app.on_event("startup")
def on_startup():
    init_db()
    domain_manager.ensure_caddy()
    proxy_manager.start()


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
    domain = domain_manager.public_settings(ip)
    return {
        "ip": ip,
        "proxy_running": proxy_manager.is_running(),
        "caddy_running": domain_manager.is_caddy_running(),
        **domain,
    }


# ----------------------------------------------------------------- Domain --

class DomainBody(BaseModel):
    domain: str = Field(min_length=1, max_length=253)


@app.get("/api/domain")
async def get_domain(_: bool = Depends(require_auth)):
    ip = await utils.get_external_ip()
    return domain_manager.public_settings(ip)


@app.put("/api/domain")
def save_domain(body: DomainBody, _: bool = Depends(require_auth)):
    try:
        domain_manager.set_domain(body.domain)
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
