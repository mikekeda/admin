import asyncio
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import unquote

import aiofiles
from aiohttp import ClientSession
from sanic import response
from sanic.exceptions import SanicException
from sanic.views import HTTPMethodView
from sqlalchemy import and_, select

from admin.app import app, jinja
from admin.forms import LoginForm
from admin.models import Metric, Repo, JenkinsBuild, authenticate
from admin.settings import (
    LOGIN_REDIRECT_URL,
    LOGOUT_REDIRECT_URL,
    SERVER_IP,
    get_env_var,
)
from admin.utils import (
    api_authentication,
    check_supervisor_status,
    get_log_files,
    get_process_name,
    get_requirements_statuses,
    get_site_status,
    login,
    login_required,
    logout,
    save_build_info,
    view_login_required,
    update_requirements,
    get_python_version,
    get_npm_status,
)


class HomePageView(HTTPMethodView):
    decorators = [view_login_required]

    # noinspection PyMethodMayBeStatic
    async def get(self, request):
        ex = request.ctx.conn.execute
        sites = (await ex(select(Repo).order_by(Repo.id))).fetchall()

        # Get Jenkins Builds.
        rows = (
            await ex(select(JenkinsBuild).order_by(JenkinsBuild.started))
        ).fetchall()
        builds = defaultdict(list)
        last_successful_builds = {}
        for row in rows:
            builds[row.site_id].append(row)
            if row.status == "SUCCESS":
                last_successful_builds[row.site_id] = row

        # Collect processes names.
        processes = []
        for site in sites:
            processes.extend(
                [
                    f"{get_process_name(site.title)}{['', '_celery', '_celerybeat'][i]}"
                    for i, _ in enumerate(site.processes)
                ]
            )

        # Check supervisor statuses.
        supervisor_statuses = await asyncio.gather(
            *[  # check supervisor statuses
                check_supervisor_status(process) for process in processes
            ]
        )

        python_versions = [get_python_version(site.title) for site in sites]
        process_statuses = dict(zip(processes, supervisor_statuses))
        builds_per_site = [builds[site.id][-5:] for site in sites]
        logs_files = (get_log_files(site, process_statuses) for site in sites)

        return await jinja.render_async(
            "sites.html",
            request,
            repos=zip(
                sites,
                python_versions,
                builds_per_site,
                last_successful_builds,
                logs_files,
            ),
        )

    # noinspection PyMethodMayBeStatic
    async def post(self, request):
        await asyncio.gather(*[update_requirements(repo) for repo in request.form])

        return response.redirect("/")


@app.route("/sites/<repo_name>")
@login_required()
async def site_page(request, repo_name: str):
    ex = request.ctx.conn.execute
    repo_name = repo_name.replace("%20", " ")
    site = (await ex(select(Repo).where(Repo.title == repo_name))).fetchone()
    if not site:
        raise SanicException("Site not found", 404)

    sites = await ex(select(Repo).with_only_columns(Repo.title).order_by(Repo.title))
    sites = [site.title for site in sites]

    processes = [
        f"{get_process_name(site.title)}{['', '_celery', '_celerybeat'][i]}"
        for i, _ in enumerate(site.processes)
    ]

    async with ClientSession() as _session:
        (
            metrics,
            builds,
            site_status,
            supervisor_statuses,
            requirements_statuses,
        ) = await asyncio.gather(
            ex(
                select(Metric)
                .where(
                    and_(
                        Metric.site == site.id,
                        Metric.timestamp > datetime.now() - timedelta(weeks=1),
                    )
                )
                .order_by(Metric.timestamp)
            ),
            ex(
                select(JenkinsBuild)
                .where(
                    and_(
                        JenkinsBuild.site_id == site.id,
                    )
                )
                .order_by(JenkinsBuild.started.desc())
                .limit(10)
            ),
            get_site_status(site.url, _session),
            asyncio.gather(  # check supervisor statuses
                *[check_supervisor_status(process) for process in processes]
            ),
            get_requirements_statuses(site.title),
        )

    builds = builds.fetchall()[::-1]
    is_black = builds[-1].black_status

    metrics = [
        [
            m.timestamp.isoformat(),
            m.response_time.microseconds / 1000,
            m.status_code,
            m.response_size,
        ]
        for m in metrics
    ]

    builds = [
        [
            b.started.isoformat(),
            b.pep8_violations or 0,
            b.pylint_violations or 0,
            b.test_coverage or 0,
        ]
        for b in builds
    ]

    process_statuses = dict(zip(processes, supervisor_statuses))
    logs_files = get_log_files(site, process_statuses)

    return await jinja.render_async(
        "site.html",
        request,
        site=site,
        metrics=metrics,
        builds=builds,
        site_status=site_status,
        logs=logs_files,
        sites=sites,
        requirements_statuses=requirements_statuses,
        is_black=is_black,
    )


@app.route("/api/site_check/<url>", methods=["GET"])
@login_required()
async def site_api(_, url: str):
    url = unquote(url)
    async with ClientSession() as _session:
        status = await get_site_status(url, _session)
    return response.json(status)


@app.route("/api/available_updates/<site>", methods=["GET"])
@login_required()
async def available_backend_updates_api(_, site: str):
    site = unquote(site)
    requirements_statuses = await get_requirements_statuses(site)

    return response.json(requirements_statuses)


@app.route("/api/frontend_updates/<site>", methods=["GET"])
@login_required()
async def available_frontend_updates_api(_, site: str):
    site = unquote(site)
    try:
        requirements_statuses = await get_npm_status(site, True)
    except FileNotFoundError:
        requirements_statuses = []

    return response.json(requirements_statuses)


@app.route("/api/build/<site>/<build_number>/<status>", methods={"POST"})
@api_authentication()
async def build_api(
    request, site: str, build_number: int, status: str
) -> response.HTTPResponse:
    """Jenkins build status endpoint."""
    asyncio.create_task(
        save_build_info(request.app.ctx.engine, site, build_number, status)
    )

    return response.json({"status": "ok"}, 201)


@app.route("/sites/<repo_name>/update", methods=["POST"])
@login_required()
async def update_requirements_api(request, repo_name: str):
    """Update requirements.txt"""

    await update_requirements(repo_name, set(request.form))

    return response.redirect(f"/sites/{repo_name}")


@app.route("/sites/<repo_name>/<file_name>")
@login_required()
async def log_page(request, repo_name: str, file_name: str):
    """View site logs."""

    if not file_name.endswith(".log") or not re.match("^[a-zA-Z- ]*$", repo_name):
        raise SanicException("Bad file name", 403)

    folder = get_process_name(repo_name)
    logs = f"{get_env_var('LOG_FOLDER')}/{folder}/{file_name}"
    if not os.path.exists(logs):
        raise SanicException("File not found", 404)

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
async def metric_page(request):
    ex = request.ctx.conn.execute
    sites = (
        await ex(select(Repo).order_by(Repo.id).where(Repo.url.isnot(None)))
    ).fetchall()
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
async def logs_page(request):
    """Show Nginx access.log"""
    access_logs = []

    known_user_agents = {
        "GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)",
    }

    known_ips = {
        SERVER_IP,
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
    return response.redirect(LOGOUT_REDIRECT_URL)


class LoginView(HTTPMethodView):
    # noinspection PyMethodMayBeStatic
    async def get(self, request):
        """User login form."""
        if request.ctx.session.get("user"):
            return response.redirect(LOGIN_REDIRECT_URL)

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
                return response.redirect(LOGIN_REDIRECT_URL)
            else:
                form.username.errors.append("Not valid username or password!")

        return await jinja.render_async("login.html", request, form=form)


app.add_route(HomePageView.as_view(), "/")
app.add_route(LoginView.as_view(), "/login")
