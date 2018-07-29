import aiohttp
import asyncio_redis
from aiocache import caches
from sanic import Sanic
from sanic.response import html, redirect
from sanic.views import HTTPMethodView
from sanic_session import RedisSessionInterface
from sanic_jinja2 import SanicJinja2

import settings

from models import User, authenticate, login, logout
from forms import LoginForm
from template_tags import get_item

app = Sanic(__name__)
app.config['SECRET_KEY'] = settings.SECRET_KEY
app.static('/static', './static')

# Set jinja_env and session_interface to None to avoid code style warning.
app.jinja_env = None
app.session_interface = None

jinja = SanicJinja2(app)
app.jinja_env.globals.update(get_item=get_item)


class Redis:
    """
    A simple wrapper class that allows you to share a connection
    pool across your application.
    """
    pool = None

    async def get_redis_pool(self):
        if not self.pool:
            self.pool = await asyncio_redis.Pool.create(
                **settings.REDIS_SESSION_CONFIG
            )

        return self.pool


@app.listener('before_server_start')
def init_cache(sanic, _):
    """ Initialize session_interface and cache. """
    sanic.redis = Redis()

    # Pass the getter method for the connection pool into the session.
    sanic.session_interface = RedisSessionInterface(sanic.redis.get_redis_pool)

    caches.set_config(settings.REDIS_CACHE_CONFIG)


@app.listener('after_server_stop')
async def close_redis_connections(sanic, _):
    """ Close redis connections. """
    if sanic.redis.pool:
        sanic.redis.pool.close()


@app.middleware('request')
async def add_session_to_request(request):
    # Before each request initialize a session using the client's request.
    await app.session_interface.open(request)
    request['user'] = request['session'].get('user')


@app.middleware('response')
async def save_session(request, response):
    # After each request save the session,
    # pass the response to set client cookies.
    try:
        await app.session_interface.save(request, response)
    except RuntimeError:
        pass


async def get_user(request):
    request['user'] = None
    user_dict = request['session'].get('user')
    if user_dict:
        request['user'] = User.get(id=user_dict['id'])

    return request['user']


@app.route("/")
async def homepage(request):
    if not request['session'].get('user'):
        return redirect('/login')

    sites = settings.SITES

    for site in sites:
        site['status'] = False

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(site['url']) as resp:
                    site['status'] = resp.status == 200
            except aiohttp.client_exceptions.ClientConnectorError:
                pass

    return html(jinja.render_string('sites.html', request, sites=sites))


@app.route("/about")
async def about_page(request):
    """ About page. """
    return html(jinja.render_string('about.html', request))


@app.route("/logout")
async def logout_page(request):
    """ Logout page. """
    logout(request)
    return redirect(settings.LOGIN_REDIRECT_URL)


class LoginView(HTTPMethodView):
    async def get(self, request):
        """ User login form. """
        if request['session'].get('user'):
            return redirect(settings.LOGIN_REDIRECT_URL)

        form = LoginForm(request)

        return jinja.render('login.html', request, form=form)

    async def post(self, request):
        """ Submit for User login form. """
        form = LoginForm(request)

        if form.validate():
            user = await authenticate(form.data['username'],
                                      form.data['password'])
            if user:
                login(request, user)
                return redirect(settings.LOGIN_REDIRECT_URL)
            else:
                form.username.errors.append('Not valid username or password!')

        return jinja.render('login.html', request, form=form)


app.add_route(LoginView.as_view(), '/login')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
