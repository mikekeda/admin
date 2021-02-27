from collections import namedtuple

import aioredis
from aiocache import caches
from asyncio import AbstractEventLoop
from gino import Gino
from sanic import Sanic
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse
from sanic_jinja2 import SanicJinja2
from sanic_session import AIORedisSessionInterface, Session
from sqlalchemy.engine.url import URL

from admin.settings import REDIS_CACHE_CONFIG, SANIC_CONFIG
from admin.template_tags import get_item

app = Sanic(__name__)
app.config.update(SANIC_CONFIG)
app.static("/static", "./static")

db = Gino()

# Set jinja_env and session_interface to None to avoid code style warning.
app.jinja_env = namedtuple("JinjaEnv", ["globals"])({})

jinja = SanicJinja2(app)
app.jinja_env.globals.update(get_item=get_item)

session = Session()


@app.listener("before_server_start")
async def init_cache(_app: Sanic, loop: AbstractEventLoop) -> None:
    """Initialize db connections, session_interface and cache."""
    if _app.config.get("DB_DSN"):
        dsn = app.config.DB_DSN
    else:
        dsn = URL(
            drivername=_app.config.setdefault("DB_DRIVER", "asyncpg"),
            host=_app.config.setdefault("DB_HOST", "localhost"),
            port=_app.config.setdefault("DB_PORT", 5432),
            username=_app.config.setdefault("DB_USER", "postgres"),
            password=_app.config.setdefault("DB_PASSWORD", ""),
            database=_app.config.setdefault("DB_DATABASE", "postgres"),
        )

    await db.set_bind(
        dsn,
        echo=_app.config.setdefault("DB_ECHO", False),
        min_size=_app.config.setdefault("DB_POOL_MIN_SIZE", 1),
        max_size=_app.config.setdefault("DB_POOL_MAX_SIZE", 5),
        ssl=_app.config.setdefault("DB_SSL"),
        loop=loop,
        **_app.config.setdefault("DB_KWARGS", {}),
    )

    _app.redis = await aioredis.create_redis_pool(_app.config["redis"])

    # Pass the getter method for the connection pool into the session.
    session.init_app(
        _app, interface=AIORedisSessionInterface(_app.redis, samesite="Lax")
    )

    caches.set_config(REDIS_CACHE_CONFIG)


@app.listener("after_server_stop")
async def close_redis_connections(_app, _) -> None:
    """Close db and redis connections."""
    await db.pop_bind().close()
    _app.redis.close()
    await _app.redis.wait_closed()


@app.middleware("request")
async def add_session_to_request(request: Request) -> None:
    """Set user value for templates."""
    conn = await db.acquire(lazy=True)
    request.ctx.connection = conn
    request.ctx.user = request.ctx.session.get("user")


@app.middleware("response")
async def on_response(request: Request, _) -> None:
    conn = getattr(request.ctx, "connection", None)
    if conn is not None:
        await conn.release()


@app.exception(Exception)
async def exception_handler(
    request: Request, exception: Exception, **__
) -> HTTPResponse:
    """Exception handler returns error in json format."""
    status_code = getattr(exception, "status_code", 500)

    if status_code == 500:
        logger.exception(exception)

    return jinja.render(
        "error.html",
        request,
        status=status_code,
        status_code=status_code,
        message=" ".join(str(arg) for arg in exception.args),
    )
