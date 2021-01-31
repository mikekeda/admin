import asyncio
import os
import re
import uuid
from functools import wraps
from shlex import quote
from typing import Optional

import aiofiles
from aiohttp import ClientConnectorError, ClientSession
from sanic.exceptions import abort
from sanic.log import logger
from sanic.response import html
from sanic.response import json as sanic_json
from sanic.response import redirect
from sanic.views import HTTPMethodView
from sanic_session.base import SessionDict

from admin.app import app, jinja, session
from admin.forms import LoginForm
from admin.models import APIKey, Metric, Repo, authenticate
from admin.settings import API_KEY_HEADER, LOGIN_REDIRECT_URL, get_env_var


def login_required():
    """Authentication decorator."""
    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            if request.ctx.session.get('user'):
                return await f(request, *args, **kwargs)

            # User is not authorized.
            return redirect('/login')
        return decorated_function
    return decorator


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


async def get_site_status(url: str, _session: ClientSession) -> Optional[int]:
    """Get site status."""
    if not url:
        return None

    try:
        async with _session.get(url) as resp:
            status = resp.status
    except ClientConnectorError:
        status = 404

    return status


async def check_supervisor_status(process: str) -> str:
    """Check supervisor status of given process."""
    proc = await asyncio.create_subprocess_shell(
        get_env_var('SUPERVISOR_CMD').format(process=quote(process)),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        logger.warning("Error getting supervisor status: " + stderr.decode())

    return stdout.decode().strip()


@app.route("/")
@login_required()
async def homepage(request):
    repos = await Repo.query.order_by(Repo.id).gino.all()

    # Collect processes names.
    processes = []
    for repo in repos:
        processes.extend([
            f"{repo.process_name}{['', '_celery', '_celerybeat'][i]}"
            for i, _ in enumerate(repo.processes)
        ])

    # Check site and supervisor statuses.
    async with ClientSession() as _session:
        site_statuses, supervisor_statuses = await asyncio.gather(
            asyncio.gather(*[  # check site statuses
                get_site_status(repo.url, _session)
                for repo in repos
            ]),
            asyncio.gather(*[  # check supervisor statuses
                check_supervisor_status(process)
                for process in processes
            ])
        )

    process_statuses = dict(zip(processes, supervisor_statuses))

    for status, repo in zip(site_statuses, repos):
        repo.status = status == 200
        repo.logs = []
        if len(repo.processes) >= 1:
            processes.append(repo.process_name)
            repo.logs.append(("error.log", process_statuses[repo.process_name]))
            repo.logs.append(("out.log", process_statuses[repo.process_name]))
        if len(repo.processes) >= 2:
            processes.append(f"{repo.process_name}_celery")
            repo.logs.append(("worker.log", process_statuses[f"{repo.process_name}_celery"]))
        if len(repo.processes) >= 3:
            processes.append(f"{repo.process_name}_celerybeat")
            repo.logs.append(("beat.log", process_statuses[f"{repo.process_name}_celerybeat"]))

    return html(jinja.render_string('sites.html', request, repos=repos))


@app.route("/sites/<repo_name>")
@login_required()
async def logs_page(request, repo_name: str):
    site = await Repo.query.where(Repo.title == repo_name).gino.first()

    processes = [
        f"{site.process_name}{['', '_celery', '_celerybeat'][i]}"
        for i, _ in enumerate(site.processes)
    ]

    async with ClientSession() as _session:
        metrics, site_status, supervisor_statuses = await asyncio.gather(
            Metric.query.where(Metric.site == site.id).gino.all(),
            get_site_status(site.url, _session),
            asyncio.gather(  # check supervisor statuses
                *[
                    check_supervisor_status(process) for process in processes
                ]
            ),
        )

    metrics = [
        [
            metric.timestamp.isoformat(),
            metric.response_time.microseconds / 1000,
            metric.status_code,
            metric.response_size,
        ]
        for metric in metrics
    ]

    return html(
        jinja.render_string(
            "site.html",
            request,
            site=site,
            metrics=metrics,
            site_status=site_status,
            supervisor_statuses=supervisor_statuses,
        )
    )


@app.route("/sites/<repo_name>/<file_name>")
@login_required()
async def logs_page(request, repo_name: str, file_name: str):
    """View site logs."""

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
