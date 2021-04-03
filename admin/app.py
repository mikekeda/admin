from collections import namedtuple

import aioredis
from aiocache import caches
from sanic import Sanic
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse
from sanic_jinja2 import SanicJinja2
from sanic_session import AIORedisSessionInterface, Session
from sqlalchemy.ext.asyncio import create_async_engine

from admin.settings import DEBUG, REDIS_CACHE_CONFIG, SANIC_CONFIG
from admin.template_tags import any_in

app = Sanic(__name__)
app.config.update(SANIC_CONFIG)
app.static("/static", "./static")

# Set jinja_env and session_interface to None to avoid code style warning.
app.jinja_env = namedtuple("JinjaEnv", ["globals"])({})

jinja = SanicJinja2(app, autoescape=True, enable_async=True)
app.jinja_env.globals.update(
    any_in=any_in,
    STATIC_URL="/static/"
    if DEBUG
    else "https://storage.googleapis.com/cdn.mkeda.me/admin/",
)

session = Session()


@app.listener("before_server_start")
async def init_cache(_app: Sanic, _) -> None:
    """Initialize db connections, session_interface and cache."""
    _app.ctx.engine = create_async_engine(
        "postgresql+asyncpg://"
        f"{SANIC_CONFIG['DB_USER']}:{SANIC_CONFIG['DB_PASSWORD']}"
        f"@{SANIC_CONFIG['DB_HOST']}/{SANIC_CONFIG['DB_DATABASE']}"
    )

    _app.ctx.redis = await aioredis.create_redis_pool(_app.config["redis"])

    # Pass the getter method for the connection pool into the session.
    session.init_app(
        _app,
        interface=AIORedisSessionInterface(
            _app.ctx.redis,
            samesite="Strict",
            secure=not _app.config["DEBUG"],
            cookie_name="session" if _app.config["DEBUG"] else "__Host-session",
        ),
    )

    caches.set_config(REDIS_CACHE_CONFIG)


@app.listener("after_server_stop")
async def close_redis_connections(_app: Sanic, _) -> None:
    """Close db and redis connections."""
    _app.ctx.redis.close()
    await _app.ctx.redis.wait_closed()


@app.middleware("request")
async def on_request(request: Request) -> None:
    """Set user value for templates."""
    request.ctx.conn = await request.app.ctx.engine.connect()
    request.ctx.user = request.ctx.session.get("user")


@app.middleware("response")
async def on_response(request: Request, _) -> None:
    await request.ctx.conn.commit()
    await request.ctx.conn.close()


@app.exception(Exception)
async def exception_handler(
    request: Request, exception: Exception, **__
) -> HTTPResponse:
    """Exception handler returns error in json format."""
    status_code = getattr(exception, "status_code", 500)

    if status_code == 500:
        logger.exception(exception)

    return await jinja.render_async(
        "error.html",
        request,
        status=status_code,
        status_code=status_code,
        message=" ".join(str(arg) for arg in exception.args),
    )
