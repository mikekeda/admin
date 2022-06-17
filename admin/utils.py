from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime
from functools import cache, wraps
from shlex import quote
from typing import Iterator, Optional, Iterable
from xml.etree import ElementTree

import aiofiles
from aiohttp import ClientConnectorError, ClientSession
import git
from sanic.log import logger
from sanic.request import Request
from sanic import response
from sanic_session.base import SessionDict
from sqlalchemy import and_, select, insert, update
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncEngine

from admin.app import app, session
from admin.models import APIKey, JenkinsBuild, Repo
from admin.settings import (
    API_KEY_HEADER,
    LOGOUT_REDIRECT_URL,
    ENV_FOLDER,
    JENKINS_HOME,
    get_env_var,
)


def cached(ttl: int = None, args_slice: int = None):
    """Cache decorator."""

    def decorator(f):
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            ordered_kwargs = sorted(kwargs.items())
            cache_key = (
                (f.__module__ or "")
                + f.__name__
                + str(args[:args_slice] if args_slice else args)
                + str(ordered_kwargs)
            )

            async with app.ctx.redis.client() as conn:
                value = await conn.get(cache_key)
                if value:
                    return json.loads(value)

                value = await f(*args, **kwargs)
                await conn.set(cache_key, json.dumps(value), ex=ttl)

            return value

        return decorated_function

    return decorator


def login_required():
    """Authentication decorator."""

    def decorator(f):
        @wraps(f)
        async def decorated_function(request: Request, *args, **kwargs):
            if request.ctx.session.get("user"):
                return await f(request, *args, **kwargs)

            # User is not authorized.
            return response.redirect(LOGOUT_REDIRECT_URL)

        return decorated_function

    return decorator


def view_login_required(view):
    """Authentication decorator."""

    def decorator(request: Request, *args, **kwargs):
        if request.ctx.session.get("user"):
            return view(request, *args, **kwargs)

        # User is not authorized.
        return response.redirect(LOGOUT_REDIRECT_URL)

    return decorator


async def login(request: Request, user: Row) -> None:
    """Store user id and username in the session."""
    request.ctx.session["user"] = {"id": user.id, "username": user.username}

    # Refresh sid.
    old_sid = session.interface.prefix + request.ctx.session.sid
    request.ctx.session.sid = uuid.uuid4().hex  # generate new sid
    await session.interface._delete_key(old_sid)  # delete old record from datastore


def logout(request: Request) -> None:
    """Remove user id and username from the session."""
    request.ctx.session = SessionDict(sid=request.ctx.session.sid)  # clear session
    request.ctx.session.modified = True  # mark as modified to update sid in cookies


def get_process_name(title: str) -> str:
    return title.lower().replace("-", "_").replace(" ", "_")


@cached(ttl=300, args_slice=1)
async def get_site_status(url: str, _session: ClientSession) -> int:
    """Get site status."""
    try:
        async with _session.get(url) as resp:
            status = resp.status
    except ClientConnectorError:
        status = 404

    return status


@cached(ttl=60)
async def check_supervisor_status(process: str) -> str:
    """Check supervisor status of given process."""
    proc = await asyncio.create_subprocess_shell(
        get_env_var("SUPERVISOR_CMD").format(process=quote(process)),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        logger.warning("Error getting supervisor status: " + stderr.decode())

    return stdout.decode().strip()


@cached(ttl=300)
async def check_black_status(site: str) -> bool:
    """Check if code is black."""
    folder = get_env_var("REPO_PREFIX") + get_process_name(site)
    proc = await asyncio.create_subprocess_shell(
        f'cd {folder} && black --check . --exclude "(migrations|alembic|node_modules)"',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()

    return "All done!" in stderr.decode()


@cached(ttl=86400, args_slice=1)
async def check_security_headers(url: str, _session: ClientSession) -> str:
    """Return security headers grade."""
    url = f"https://securityheaders.com/?hide=on&q={url}"
    async with _session.get(url) as resp:
        return resp.headers.get("X-Grade", "")


def get_log_files(
    repo: Row, process_statuses: dict[str, str]
) -> Iterator[tuple[str, str]]:
    """Return log file name with corresponding supervisor status."""
    if len(repo.processes) >= 1:
        yield "error.log", process_statuses[get_process_name(repo.title)]
        yield "out.log", process_statuses[get_process_name(repo.title)]
    if len(repo.processes) >= 2:
        yield "worker.log", process_statuses[f"{get_process_name(repo.title)}_celery"]
    if len(repo.processes) >= 3:
        yield "beat.log", process_statuses[f"{get_process_name(repo.title)}_celerybeat"]


@cached(ttl=60, args_slice=1)
async def get_pypi_version(
    line: str, _session: ClientSession
) -> tuple[str, Optional[str], Optional[str]]:
    """Get the current and latest version for given package."""

    if "==" not in line:
        return line, None, None

    package, current_version = line.split("==")
    url = f"https://pypi.python.org/pypi/{package}/json"
    try:
        async with _session.get(url) as resp:
            new_version = (await resp.json())["info"]["version"]
    except (ClientConnectorError, KeyError) as e:
        logger.warning("Error getting pypi info for %s: %s", package, repr(e))
        return line, current_version, None  # we were now able to get the latest version

    return package, current_version, new_version


async def get_requirements_status(
    folder: str, file_name: str, show_only_outdated: bool = False
) -> Iterable[tuple[str, Optional[str], Optional[str]]]:
    """Parse requirements.txt to get list of packages with current and latest versions."""
    async with aiofiles.open(f"{folder}/{file_name}", "r") as f:
        requirements = await f.readlines()

    async with ClientSession() as _session:
        versions = await asyncio.gather(
            *[get_pypi_version(line.strip("\n"), _session) for line in requirements]
        )

    if show_only_outdated:
        versions = [
            (package, current_version, new_version)
            for package, current_version, new_version in versions
            if new_version is not None and current_version != new_version
        ]

    return versions


async def get_requirements_statuses(
    title: str,
) -> dict[str, tuple[str, Optional[str], Optional[str]]]:
    folder = get_env_var("REPO_PREFIX") + get_process_name(title)

    requirements_status, requirements_dev_status = await asyncio.gather(
        *[
            get_requirements_status(folder, "requirements.txt", True),
            get_requirements_status(folder, "requirements-dev.txt", True),
        ],
        return_exceptions=True,
    )

    requirements_statuses = {}
    if requirements_status and not issubclass(type(requirements_status), Exception):
        requirements_statuses["requirements.txt"] = requirements_status
    if requirements_dev_status and not issubclass(
        type(requirements_dev_status), Exception
    ):
        requirements_statuses["requirements-dev.txt"] = requirements_dev_status

    return requirements_statuses


@cache
def get_python_version(site: str) -> str:
    """Get Python version for the given site."""
    site = site.lower().replace(" ", "_")
    for file in os.listdir(f"{ENV_FOLDER}/{site}/bin"):
        if file.startswith("python3."):
            return file[6:]

    return ""


def api_authentication():
    """Api authentication decorator."""

    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            token = request.headers.get(API_KEY_HEADER)
            user = await APIKey.authenticate(request.ctx.conn.execute, token)

            if user:
                await login(request, user)
                return await f(request, *args, **kwargs)

            # User is not authorized.
            return response.json({"status": "not_authorized"}, 403)

        return decorated_function

    return decorator


def update_remote(folder_name: str) -> None:
    """Push local changes to the remote repositories."""
    repo = git.Repo(folder_name)
    repo.index.add(["requirements.txt", "requirements-dev.txt"])
    repo.index.commit("Updated requirements.txt (automatically)")
    repo.remotes.origin.push("master")
    repo.remotes.github.push("master")


async def update_requirements_txt(
    packages: Optional[set[str]], folder_name: str
) -> None:
    """Update requirements.txt and requirements-dev.txt."""
    for file_name in ("requirements.txt", "requirements-dev.txt"):
        versions = await get_requirements_status(folder_name, file_name)
        logger.info(
            "Updating requirements for %s/%s: %s",
            folder_name,
            file_name,
            [
                (package, current_version, new_version)
                for package, current_version, new_version in versions
                if current_version != new_version
            ],
        )

        async with aiofiles.open(f"{folder_name}/{file_name}", "w") as f:
            await f.writelines(
                [
                    (
                        "==".join(
                            [
                                package,
                                new_version
                                if (packages is None or package in packages)
                                else current_version,
                            ]
                        )
                        if new_version
                        else package
                    )
                    + "\n"
                    for package, current_version, new_version in versions
                ]
            )


async def update_requirements(repo_name: str, packages: set[str] = None) -> None:
    """Update requirements for the given repository."""

    folder_name = get_env_var("REPO_PREFIX") + (
        repo_name.replace("%20", " ")
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
        .replace("/", "")
        .replace(".", "")
    )

    await update_requirements_txt(packages, folder_name)
    update_remote(folder_name)


async def save_build_info(
    engine: AsyncEngine, jenkins_site: str, build_number: int, status: str
) -> None:
    """Save Jenkins build info."""
    site = jenkins_site.replace("_", " ")
    values = {}
    if status == "SUCCESS":
        # Get test_coverage.
        test_coverage = (
            ElementTree.parse(
                f"{JENKINS_HOME}/jobs/{jenkins_site}/builds/{build_number}/coverage.xml"
            )
            .getroot()
            .get("line-rate")
        )

        values = {
            "black_status": await check_black_status(site),
            "test_coverage": float(test_coverage),
            "pep8_violations": 0,
            "pylint_violations": 0,
            "commit": "",
            "commit_message": "",
        }

        # Get pep8_violations, pylint_violations.
        root = ElementTree.parse(
            f"{JENKINS_HOME}/jobs/{jenkins_site}/builds/{build_number}/violations/violations.xml"
        ).getroot()
        for t in root:
            for f in t:
                values[f"{t.get('name')}_violations"] += int(f.get("count"))

        # Get commit, commit_message.
        with open(
            f"{JENKINS_HOME}/jobs/{jenkins_site}/builds/{build_number}/changelog.xml",
            "r",
        ) as f:
            for line in f:
                if line.startswith("commit "):
                    values["commit"] = line[6:].strip()
                elif line.startswith("    "):
                    values["commit_message"] = line[4:].strip()

    async with engine.connect() as conn:
        repo = (await conn.execute(select(Repo.id).where(Repo.title == site))).one()

        if status == "STARTED":
            await conn.execute(
                insert(JenkinsBuild).values(
                    site_id=repo.id,
                    number=build_number,
                    status=status,
                )
            )
        else:
            (
                await conn.execute(
                    update(JenkinsBuild)
                    .where(
                        and_(
                            JenkinsBuild.site_id == repo.id,
                            JenkinsBuild.number == build_number,
                        )
                    )
                    .values(
                        status=status,
                        finished=datetime.utcnow()
                        if status in {"SUCCESS", "FAILURE", "ABORTED"}
                        else None,
                        **values,
                    )
                    .returning(JenkinsBuild.id)
                )
            ).one()

        await conn.commit()
