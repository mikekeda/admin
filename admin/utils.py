from __future__ import annotations

import asyncio
import uuid
from functools import wraps
from shlex import quote
from typing import Iterator, Optional, Iterable

import aiofiles
from aiohttp import ClientConnectorError, ClientSession
from sanic.exceptions import abort
from sanic.log import logger
from sanic.response import json as sanic_json
from sanic.response import redirect
from sanic_session.base import SessionDict

from admin.app import session
from admin.models import APIKey
from admin.settings import API_KEY_HEADER, LOGOUT_REDIRECT_URL, get_env_var


def login_required():
    """Authentication decorator."""

    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            if request.ctx.session.get("user"):
                return await f(request, *args, **kwargs)

            # User is not authorized.
            return redirect(LOGOUT_REDIRECT_URL)

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
            return sanic_json({"status": "not_authorized"}, 403)

        return decorated_function

    return decorator


async def login(request, user) -> None:
    """Store user id and username in the session."""
    request.ctx.session["user"] = {"id": user.id, "username": user.username}

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
        get_env_var("SUPERVISOR_CMD").format(process=quote(process)),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        logger.warning("Error getting supervisor status: " + stderr.decode())

    return stdout.decode().strip()


async def check_black_status(repo) -> bool:
    """Check if code is black."""
    folder = get_env_var("REPO_PREFIX") + repo.process_name
    proc = await asyncio.create_subprocess_shell(
        f'cd {folder} && black --check . --exclude "(migrations|alembic)"',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()

    return "All done!" in stderr.decode()


async def check_security_headers(repo, _session: ClientSession) -> str:
    """Return security headers grade."""
    if not repo.url:
        return ""

    url = f"https://securityheaders.com/?hide=on&q={repo.url}"
    async with _session.get(url) as resp:
        return resp.headers.get("X-Grade", "")


def get_log_files(repo, process_statuses: dict[str, str]) -> Iterator[tuple[str, str]]:
    """Return log file name with corresponding supervisor status."""
    if len(repo.processes) >= 1:
        yield "error.log", process_statuses[repo.process_name]
        yield "out.log", process_statuses[repo.process_name]
    if len(repo.processes) >= 2:
        yield "worker.log", process_statuses[f"{repo.process_name}_celery"]
    if len(repo.processes) >= 3:
        yield "beat.log", process_statuses[f"{repo.process_name}_celerybeat"]


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
        return line, current_version, None  # we were now able to get latest version

    return package, current_version, new_version


async def get_requirements_status(
    folder: str, file_name: str, show_only_outdated: bool = False
) -> Iterable[tuple[str, Optional[str], Optional[str]]]:
    """Parse requirements.txt to get list of packages with current and latest versions."""
    try:
        async with aiofiles.open(f"{folder}/{file_name}", "r") as f:
            requirements = await f.readlines()
    except FileNotFoundError as e:
        logger.warning("No such Log file (%s/%s): %s", folder, file_name, repr(e))
        abort(404)

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


async def update_requirements(folder: str):
    """Update requirements.txt"""
    for file_name in ("requirements.txt", "requirements-dev.txt"):
        versions = await get_requirements_status(folder, file_name)

        async with aiofiles.open(f"{folder}/{file_name}", "w") as f:
            await f.writelines(
                [
                    ("==".join([package, new_version]) if new_version else package)
                    + "\n"
                    for package, _, new_version in versions
                ]
            )
