import asyncio
import os
import socket
import uuid
from functools import wraps
from typing import Tuple

import aiofiles
from aiohttp import ClientConnectorError, ClientSession
from sanic.exceptions import abort
from sanic.log import logger
from sanic.response import html
from sanic.response import json as sanic_json
from sanic.response import redirect
from sanic.views import HTTPMethodView
from sanic_session.base import SessionDict

import settings
from app import app, jinja, session
from admin.forms import LoginForm
from admin.models import APIKey, authenticate, Repo


async def login(request, user) -> None:
    """Store user id and username in the session."""
    request.ctx.session['user'] = {'id': user.id, 'username': user.username}

    # Refresh sid.
    old_sid = session.interface.prefix + request.ctx.session.sid
    request.ctx.session.sid = uuid.uuid4().hex  # generate new sid
    await session.interface._delete_key(old_sid)  # delete old record from datastore


def logout(request) -> None:
    """Remove user id and username from the session."""
    request.ctx.session = SessionDict(sid=request.ctx.session.sid)  # clear session
    request.ctx.session.modified = True  # mark as modified to update sid in cookies


async def get_site_status(url: str, _session: ClientSession) -> Tuple[str, int]:
    """Get site status."""
    try:
        async with _session.get(url) as resp:
            return url, resp.status
    except ClientConnectorError:
        return url, 404


@app.route("/")
async def homepage(request):
    if not request.ctx.session.get('user'):
        return redirect('/login')

    async with ClientSession() as _session:
        repos = await Repo.query.gino.all()
        tasks = [
            get_site_status(repo.url, _session)
            for repo in repos
        ]

        statuses = {key: val for key, val in await asyncio.gather(*tasks)}

        for repo in repos:
            repo.status = statuses.get(repo.url) == 200

    return html(jinja.render_string('sites.html', request, repos=repos))


@app.route("/sites/<repo_name>/logs")
async def logs_page(request, repo_name):
    """View site logs."""
    if not request.ctx.session.get('user'):
        return redirect('/login')

    repo = await Repo.query.gino.first(name=repo_name)
    logs = f"{settings.get_env_var('LOG_FOLDER')}/{repo.name}/error.log"
    if not repo or not os.path.exists(logs):
        abort(404)

    async with aiofiles.open(logs, 'r') as f:
        logs = (await f.readlines())[-10000:]  # last 10000 lines

    return html(jinja.render_string('logs.html', request, logs=''.join(logs),
                                    site_name=repo_name))


@app.route("/about")
async def about_page(request):
    """About page."""
    # from admin.models import db
    # await db.gino.create_all()
    return html(jinja.render_string('about.html', request))


@app.route("/logout")
async def logout_page(request):
    """Logout page."""
    logout(request)
    return redirect(settings.LOGIN_REDIRECT_URL)


def api_authentication():
    """Api authentication decorator."""
    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            token = request.headers.get(settings.API_KEY_HEADER)
            user = await APIKey.authenticate(token)

            if user:
                await login(request, user)
                return await f(request, *args, **kwargs)

            # User is not authorized.
            return sanic_json({'status': 'not_authorized'}, 403)
        return decorated_function
    return decorator


@app.route("/api", methods={"POST"})
@api_authentication()
async def api_page(request):
    """Api page."""
    # TODO[Mike] Do something!
    return sanic_json({})


class LoginView(HTTPMethodView):
    # noinspection PyMethodMayBeStatic
    async def get(self, request):
        """User login form."""
        if request.ctx.session.get('user'):
            return redirect(settings.LOGIN_REDIRECT_URL)

        form = LoginForm(request)

        return jinja.render('login.html', request, form=form)

    # noinspection PyMethodMayBeStatic
    async def post(self, request):
        """Submit for User login form."""
        form = LoginForm(request)

        if form.validate():
            user = await authenticate(form.data['username'], form.data['password'])
            if user:
                await login(request, user)
                return redirect(settings.LOGIN_REDIRECT_URL)
            else:
                form.username.errors.append('Not valid username or password!')

        return jinja.render('login.html', request, form=form)


app.add_route(LoginView.as_view(), '/login')


if __name__ == "__main__":
    if app.config['DEBUG']:
        app.run(host="0.0.0.0", port=8000, debug=True)
    else:
        # Remove old socket (is any).
        try:
            os.unlink(app.config['SOCKET_FILE'])
        except FileNotFoundError as e:
            logger.info(f"No old socket file found: {e}")

        # Create socket and run app.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(app.config['SOCKET_FILE'])
                app.run(sock=sock, access_log=False)
            except OSError as e:
                logger.warning(e)
