from redis import asyncio as aioredis
from sanic import Sanic, response
from sanic.log import logger
from sanic.request import Request
from sanic_jinja2 import SanicJinja2
from sanic_session import Session
from sanic_session.base import BaseSessionInterface
from sqlalchemy.ext.asyncio import create_async_engine

from admin.settings import DEBUG, SANIC_CONFIG, SERVER_IP
from admin.template_tags import any_in

app = Sanic("admin")
app.config.update(SANIC_CONFIG)
app.static("/static", "./static")

jinja = SanicJinja2(app, autoescape=True, enable_async=True)
jinja.env.globals["any_in"] = any_in
jinja.env.globals["STATIC_URL"] = (
    "/static/" if DEBUG else "https://storage.googleapis.com/cdn.mkeda.me/admin/"
)
jinja.env.globals["SERVER_IP"] = SERVER_IP

session = Session()

class RedisSessionInterface(BaseSessionInterface):
    def __init__(
        self,
        redis,
        domain: str = None,
        expiry: int = 2592000,
        httponly: bool = True,
        cookie_name: str = "session",
        prefix: str = "session:",
        sessioncookie: bool = False,
        samesite: str = None,
        session_name: str = "session",
        secure: bool = False,
    ):

        self.redis = redis

        super().__init__(
            expiry=expiry,
            prefix=prefix,
            cookie_name=cookie_name,
            domain=domain,
            httponly=httponly,
            sessioncookie=sessioncookie,
            samesite=samesite,
            session_name=session_name,
            secure=secure,
        )

    @staticmethod
    def __get_request_container(request):
        return request.ctx.__dict__ if hasattr(request, "ctx") else request

    async def _get_value(self, prefix, sid):
        return await self.redis.get(self.prefix + sid)

    async def _delete_key(self, key):
        await self.redis.delete(key)

    async def _set_value(self, key, data):
        await self.redis.setex(key, self.expiry, data)

    def _set_cookie_props(self, request, response):
        req = self.__get_request_container(request)
        cookie = response.add_cookie(
            self.cookie_name,
            req[self.session_name].sid,
            httponly=self.httponly,
            secure=False
        )

        # Set expires and max-age unless we are using session cookies
        if not self.sessioncookie:
            cookie.expires = self._calculate_expires(self.expiry)
            cookie.max_age = self.expiry

        if self.domain:
            cookie.domain = self.domain

        if self.samesite is not None:
            cookie.samesite = self.samesite

        if self.secure:
            cookie.secure = True


@app.listener("before_server_start")
async def init_cache(_app: Sanic, _) -> None:
    """Initialize db connections, session_interface and cache."""
    _app.ctx.engine = create_async_engine(
        "postgresql+asyncpg://"
        f"{SANIC_CONFIG['DB_USER']}:{SANIC_CONFIG['DB_PASSWORD']}"
        f"@{SANIC_CONFIG['DB_HOST']}/{SANIC_CONFIG['DB_DATABASE']}",
        pool_size=5,
    )

    _app.ctx.redis = await aioredis.Redis.from_url(
        _app.config["redis"], decode_responses=True
    )

    # Pass the getter method for the connection pool into the session.
    session.init_app(
        _app,
        interface=RedisSessionInterface(
            _app.ctx.redis,
            samesite="Strict",
            secure=not _app.config["DEBUG"],
            cookie_name="session" if _app.config["DEBUG"] else "__Host-session",
        ),
    )


@app.listener("after_server_stop")
async def close_redis_connections(_app: Sanic, _) -> None:
    """Close db and redis connections."""
    await _app.ctx.redis.close()


@app.middleware("request")
async def on_request(request: Request) -> None:
    """Set user value for templates."""
    request.ctx.conn = await request.app.ctx.engine.connect()
    await session.interface.open(request)
    request.ctx.user = request.ctx.session.get("user")


@app.middleware("response")
async def on_response(request: Request, response) -> None:
    await request.ctx.conn.commit()
    await request.ctx.conn.close()
    await session.interface.save(request, response)


@app.exception(Exception)
async def exception_handler(
    request: Request, exception: Exception, **__
) -> response.HTTPResponse:
    """Exception handler returns error in json format."""
    status_code = getattr(exception, "status_code", 500)
    error = " ".join(str(arg) for arg in exception.args)

    if status_code == 500:
        logger.exception(exception)

    if request.path.startswith("/api/"):
        return response.json({"error": error}, status_code)

    return await jinja.render_async(
        "error.html",
        request,
        status=status_code,
        status_code=status_code,
        message=error,
    )
