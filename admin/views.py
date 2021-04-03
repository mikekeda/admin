import asyncio
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta

import aiofiles
import git
from aiohttp import ClientSession
from sanic.exceptions import abort
from sanic.response import redirect
from sanic.views import HTTPMethodView
from sqlalchemy import and_, select

from admin.app import app, jinja
from admin.forms import LoginForm
from admin.models import Metric, Repo, authenticate
from admin.settings import LOGIN_REDIRECT_URL, LOGOUT_REDIRECT_URL, get_env_var
from admin.utils import (
    check_black_status,
    check_security_headers,
    check_supervisor_status,
    get_log_files,
    get_process_name,
    get_requirements_status,
    get_site_status,
    login,
    login_required,
    logout,
    update_requirements,
)


@app.route("/")
@login_required()
async def homepage(request):
    ex = request.ctx.conn.execute
    repos = (await ex(select(Repo).order_by(Repo.id))).fetchall()

    # Collect processes names.
    processes = []
    for repo in repos:
        processes.extend(
            [
                f"{get_process_name(repo)}{['', '_celery', '_celerybeat'][i]}"
                for i, _ in enumerate(repo.processes)
            ]
        )

    # Check site and supervisor statuses.
    async with ClientSession() as _session:
        (
            site_statuses,
            supervisor_statuses,
            black_statuses,
            security_headers_grades,
        ) = await asyncio.gather(
            asyncio.gather(
                *[  # check site statuses
                    get_site_status(repo.url, _session) for repo in repos
                ]
            ),
            asyncio.gather(
                *[  # check supervisor statuses
                    check_supervisor_status(process) for process in processes
                ]
            ),
            asyncio.gather(
                *[check_black_status(repo) for repo in repos]  # check if code is black
            ),
            asyncio.gather(
                *[  # get security headers grade
                    check_security_headers(repo, _session) for repo in repos
                ]
            ),
        )

    process_statuses = dict(zip(processes, supervisor_statuses))
    logs_files = (get_log_files(repo, process_statuses) for repo in repos)

    return await jinja.render_async(
        "sites.html",
        request,
        repos=zip(
            repos, site_statuses, logs_files, black_statuses, security_headers_grades
        ),
    )


@app.route("/sites/<repo_name>")
@login_required()
async def repo_page(request, repo_name: str):
    ex = request.ctx.conn.execute
    repo_name = repo_name.replace("%20", " ")
    site = (await ex(select(Repo).where(Repo.title == repo_name))).fetchone()
    if not site:
        abort(404)

    sites = await ex(select(Repo).with_only_columns([Repo.title]).order_by(Repo.title))
    sites = [site.title for site in sites]

    processes = [
        f"{get_process_name(site)}{['', '_celery', '_celerybeat'][i]}"
        for i, _ in enumerate(site.processes)
    ]

    folder = get_env_var("REPO_PREFIX") + get_process_name(site)

    async with ClientSession() as _session:
        (
            metrics,
            site_status,
            supervisor_statuses,
            requirements_status,
            requirements_dev_status,
            is_black,
            security_headers_grade,
        ) = await asyncio.gather(
            ex(
                select(Metric).where(
                    and_(
                        Metric.site == site.id,
                        Metric.timestamp > datetime.now() - timedelta(weeks=1),
                    )
                )
            ),
            get_site_status(site.url, _session),
            asyncio.gather(  # check supervisor statuses
                *[check_supervisor_status(process) for process in processes]
            ),
            get_requirements_status(folder, "requirements.txt", True),
            get_requirements_status(folder, "requirements-dev.txt", True),
            check_black_status(site),
            check_security_headers(site, _session),
        )

    metrics = [
        [
            m.timestamp.isoformat(),
            m.response_time.microseconds / 1000,
            m.status_code,
            m.response_size,
        ]
        for m in metrics
    ]

    process_statuses = dict(zip(processes, supervisor_statuses))
    logs_files = get_log_files(site, process_statuses)

    requirements_statuses = {}
    if requirements_status:
        requirements_statuses["requirements.txt"] = requirements_status
    if requirements_dev_status:
        requirements_statuses["requirements-dev.txt"] = requirements_dev_status

    return await jinja.render_async(
        "site.html",
        request,
        site=site,
        metrics=metrics,
        site_status=site_status,
        logs=logs_files,
        sites=sites,
        requirements_statuses=requirements_statuses,
        is_black=is_black,
        security_headers_grade=security_headers_grade,
    )


@app.route("/sites/<repo_name>/update", methods=["POST"])
@login_required()
async def update_requirements_txt(_, repo_name: str):
    """Update requirements.txt"""
    folder_name = get_env_var("REPO_PREFIX") + (
        repo_name.replace("%20", " ")
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
        .replace("/", "")
        .replace(".", "")
    )
    await update_requirements(folder_name)

    repo = git.Repo(folder_name)
    repo.index.add(["requirements.txt", "requirements-dev.txt"])
    repo.index.commit("Updated requirements.txt (automatically)")
    repo.remotes.origin.push("master")
    repo.remotes.github.push("master")

    return redirect(f"/sites/{repo_name}")


@app.route("/sites/<repo_name>/<file_name>")
@login_required()
async def logs_page(request, repo_name: str, file_name: str):
    """View site logs."""

    if not file_name.endswith(".log") or not re.match("^[a-zA-Z- ]*$", repo_name):
        abort(403)

    folder = repo_name.lower().replace("-", "_").replace(" ", "_")
    logs = f"{get_env_var('LOG_FOLDER')}/{folder}/{file_name}"
    if not os.path.exists(logs):
        abort(404)

    async with aiofiles.open(logs, "r") as f:
        logs = (await f.readlines())[-10000:]  # last 10000 lines

    return await jinja.render_async(
        "logs.html",
        request,
        logs="".join(logs),
        site_name=repo_name,
        file_name=file_name,
    )


@app.route("/metrics")
@login_required()
async def metric(request):
    ex = request.ctx.conn.execute
    sites = await ex(select(Repo).order_by(Repo.id).where(Repo.url.isnot(None)))
    site_ids = [s.id for s in sites]

    ping_dict = defaultdict(lambda: defaultdict(int))
    status_dict = defaultdict(lambda: defaultdict(int))
    metrics = await ex(
        select(Metric).where(
            and_(
                Metric.timestamp > datetime.now() - timedelta(days=1),
                Metric.site.in_(site_ids),
            )
        )
    )
    for m in metrics:
        timestamp = m.timestamp.isoformat(timespec="minutes")
        ping_dict[timestamp][m.site] = m.response_time.microseconds / 1000
        status_dict[timestamp][m.site] = m.status_code

    pings = [
        [timestamp] + [ping_dict[timestamp][site_id] for site_id in site_ids]
        for timestamp in ping_dict
    ]
    statuses = [
        [timestamp] + [status_dict[timestamp][site_id] for site_id in site_ids]
        for timestamp in status_dict
    ]

    return await jinja.render_async(
        "metric.html", request, sites=sites, pings=pings, statuses=statuses
    )


@app.route("/logs")
@login_required()
async def logs(request):
    """Show Nginx access.log"""
    access_logs = []

    known_user_agents = {
        "GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)",
    }

    known_ips = {
        get_env_var("SERVER_IP"),
        (request.headers.get("x-forwarded-for") or "").split(",")[0],
    }

    known_referees = set((get_env_var("KNOWN_REFEREES") or "").split(","))

    async with aiofiles.open(
        get_env_var("ACCESS_LOG"), "r", encoding="ISO-8859-1"
    ) as f:
        async for line in f:
            line = json.loads(line)
            if (
                line[2] == "GET"
                and line[4] == "200"
                and any(
                    (
                        line[1] in known_ips,
                        line[7] in known_referees,
                        line[8] in known_user_agents,
                    )
                )
            ):
                continue  # skip this

            line[0] = datetime.strptime(line[0], "%d/%b/%Y:%H:%M:%S %z")
            line[4] = int(line[4])

            access_logs.append(line)

    return await jinja.render_async(
        "access_log.html",
        request,
        logs=access_logs,
        known_ips=known_ips,
        bad_user_agents={"msnbot", "scrapbot", "Go-http-client"},
    )


@app.route("/about")
async def about_page(request):
    """About page."""
    return await jinja.render_async("about.html", request)


@app.route("/logout")
async def logout_page(request):
    """Logout page."""
    logout(request)
    return redirect(LOGOUT_REDIRECT_URL)


class LoginView(HTTPMethodView):
    # noinspection PyMethodMayBeStatic
    async def get(self, request):
        """User login form."""
        if request.ctx.session.get("user"):
            return redirect(LOGIN_REDIRECT_URL)

        form = LoginForm(request)

        return await jinja.render_async("login.html", request, form=form)

    # noinspection PyMethodMayBeStatic
    async def post(self, request):
        """Submit for User login form."""
        form = LoginForm(request)

        if form.validate():
            user = await authenticate(
                request.ctx.conn, form.data["username"], form.data["password"]
            )
            if user:
                await login(request, user)
                return redirect(LOGIN_REDIRECT_URL)
            else:
                form.username.errors.append("Not valid username or password!")

        return await jinja.render_async("login.html", request, form=form)


app.add_route(LoginView.as_view(), "/login")
