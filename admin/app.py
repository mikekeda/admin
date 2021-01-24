from collections import namedtuple

import aioredis
from aiocache import caches
from gino import Gino
from sanic import Sanic
from sanic.log import logger
from sanic_session import Session, AIORedisSessionInterface
from sanic_jinja2 import SanicJinja2
from sqlalchemy.engine.url import URL

from admin.settings import get_env_var, SECRET_KEY, REDIS_CACHE_CONFIG
from admin.template_tags import get_item

app = Sanic(__name__)
app.config['DEBUG'] = bool(get_env_var('DEBUG', 'True'))
app.config['SOCKET_FILE'] = get_env_var('SOCKET_FILE', '/temp/admin.sock')
app.config['SECRET_KEY'] = SECRET_KEY
app.config['DB_USE_CONNECTION_FOR_REQUEST'] = False
app.config['DB_USER'] = get_env_var('DB_USER', 'admin_admin')
app.config['DB_PASSWORD'] = get_env_var('DB_PASSWORD', 'admin_admin_pasWQ27$')
app.config['DB_HOST'] = get_env_var('DB_HOST', '127.0.0.1')
app.config['DB_DATABASE'] = get_env_var('DB_NAME', 'admin')
app.config['redis'] = 'redis://127.0.0.1/8'
app.static('/static', './static')

db = Gino()

# Set jinja_env and session_interface to None to avoid code style warning.
app.jinja_env = namedtuple('JinjaEnv', ['globals'])({})

jinja = SanicJinja2(app)
app.jinja_env.globals.update(get_item=get_item)

session = Session()


@app.listener('before_server_start')
async def init_cache(_app, loop):
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
        **_app.config.setdefault("DB_KWARGS", dict()),
    )

    _app.redis = await aioredis.create_redis_pool(_app.config['redis'])

    # Pass the getter method for the connection pool into the session.
    session.init_app(_app, interface=AIORedisSessionInterface(_app.redis, samesite='Lax'))

    caches.set_config(REDIS_CACHE_CONFIG)


@app.listener('after_server_stop')
async def close_redis_connections(_app, _):
    """Close db and redis connections."""
    await db.pop_bind().close()
    _app.redis.close()
    await _app.redis.wait_closed()


@app.middleware('request')
async def add_session_to_request(request):
    """Set user value for templates."""
    conn = await db.acquire(lazy=True)
    request.ctx.connection = conn
    request.ctx.user = request.ctx.session.get('user')


@app.middleware("response")
async def on_response(request, _):
    conn = getattr(request.ctx, "connection", None)
    if conn is not None:
        await conn.release()


@app.exception(Exception)
async def exception_handler(request, exception: Exception, **__):
    """Exception handler returns error in json format."""
    status_code = getattr(exception, "status_code", 500)

    if status_code == 500:
        logger.exception(exception)

    return jinja.render(
        'error.html',
        request,
        status=status_code,
        status_code=status_code,
        message=''.join(exception.args)
    )
