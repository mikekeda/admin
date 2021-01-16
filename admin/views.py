import asyncio
import os
import re
import time
import uuid
from functools import wraps
from typing import Tuple, Optional

import aiofiles
from aiohttp import ClientConnectorError, ClientSession
from sanic.exceptions import abort
from sanic.response import html
from sanic.response import json as sanic_json
from sanic.response import redirect
from sanic.views import HTTPMethodView
from sanic_session.base import SessionDict

from admin.app import app, jinja, session
from admin.forms import LoginForm
from admin.models import APIKey, Repo, authenticate
from admin.settings import API_KEY_HEADER, LOGIN_REDIRECT_URL, get_env_var


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


async def get_site_status(url: str, _session: ClientSession) -> Tuple[Optional[int], Optional[int]]:
    """Get site status."""
    if not url:
        return None, None

    start = time.monotonic()
    try:
        async with _session.get(url) as resp:
            status = resp.status
    except ClientConnectorError:
        status = 404

    return status, round((time.monotonic() - start) * 1000)


@app.route("/")
async def homepage(request):
    if not request.ctx.session.get('user'):
        return redirect('/login')

    async with ClientSession() as _session:
        repos = await Repo.query.order_by(Repo.id).gino.all()
        statuses = await asyncio.gather(*[
            get_site_status(repo.url, _session)
            for repo in repos
        ])

        for i, repo in enumerate(repos):
            repo.status = statuses[i][0] == 200
            repo.elapsed = statuses[i][1]

    return html(jinja.render_string('sites.html', request, repos=repos))


@app.route("/sites/<repo_name>/<file_name>")
async def logs_page(request, repo_name: str, file_name: str):
    """View site logs."""
    if not request.ctx.session.get('user'):
        return redirect('/login')

    if not file_name.endswith('.log') or not re.match("^[a-zA-Z-]*$", repo_name):
        abort(403)

    folder = repo_name.lower().replace('-', '_')
    logs = f"{get_env_var('LOG_FOLDER')}/{folder}/{file_name}"
    if not os.path.exists(logs):
        abort(404)

    async with aiofiles.open(logs, 'r') as f:
        logs = (await f.readlines())[-10000:]  # last 10000 lines

    return html(jinja.render_string('logs.html', request, logs=''.join(logs),
                                    site_name=repo_name, file_name=file_name))


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
    return redirect(LOGIN_REDIRECT_URL)


def api_authentication():
    """Api authentication decorator."""
    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            token = request.headers.get(API_KEY_HEADER)
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
            return redirect(LOGIN_REDIRECT_URL)

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
                return redirect(LOGIN_REDIRECT_URL)
            else:
                form.username.errors.append('Not valid username or password!')

        return jinja.render('login.html', request, form=form)


app.add_route(LoginView.as_view(), '/login')
