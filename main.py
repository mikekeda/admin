import traceback

import aioredis
from aiocache import caches
from gino.ext.sanic import Gino
from sanic import Sanic
from sanic_session import Session, AIORedisSessionInterface
from sanic_jinja2 import SanicJinja2

import settings
from settings import get_env_var
from template_tags import get_item

app = Sanic(__name__)
app.config['SECRET_KEY'] = settings.SECRET_KEY
app.config['DB_USER'] = get_env_var('DB_USER', 'admin_admin')
app.config['DB_PASSWORD'] = get_env_var('DB_PASSWORD', 'admin_admin_pasWQ27$')
app.config['DB_HOST'] = get_env_var('DB_HOST', '127.0.0.1')
app.config['DB_DATABASE'] = get_env_var('DB_NAME', 'admin')
app.config['redis'] = 'redis://127.0.0.1/8'
app.static('/static', './static')

db = Gino()
db.init_app(app)

# Set jinja_env and session_interface to None to avoid code style warning.
app.jinja_env = None
app.session_interface = None

jinja = SanicJinja2(app)
app.jinja_env.globals.update(get_item=get_item)

session = Session()


@app.listener('before_server_start')
async def init_cache(_app, _):
    """ Initialize session_interface and cache. """
    _app.redis = await aioredis.create_redis_pool(_app.config['redis'])

    # Pass the getter method for the connection pool into the session.
    session.init_app(_app, interface=AIORedisSessionInterface(_app.redis))

    caches.set_config(settings.REDIS_CACHE_CONFIG)


@app.listener('after_server_stop')
async def close_redis_connections(_app, _):
    """ Close redis connections. """
    _app.redis.close()


@app.middleware('request')
async def add_session_to_request(request):
    """ Set user value for templates. """
    request['user'] = request['session'].get('user')


@app.exception(Exception)
async def exception_handler(request, exception: Exception, **__):
    """ Exception handler returns error in json format. """
    status_code = getattr(exception, "status_code", 500)

    if status_code == 500:
        print("\n".join([str(exception.args), traceback.format_exc()]))

    return jinja.render(
        'error.html',
        request,
        status=status_code,
        status_code=status_code,
        message=''.join(exception.args)
    )
