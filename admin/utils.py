from __future__ import annotations

import asyncio
import uuid
from functools import wraps
from shlex import quote
from typing import Iterator, Optional, Iterable

import aiofiles
from aiohttp import ClientConnectorError, ClientSession
import git
from sqlalchemy.engine import Row
from sanic.exceptions import SanicException
from sanic.log import logger
from sanic.request import Request
from sanic.response import redirect
from sanic_session.base import SessionDict

from admin.app import session
from admin.settings import LOGOUT_REDIRECT_URL, get_env_var


def login_required():
    """Authentication decorator."""

    def decorator(f):
        @wraps(f)
        async def decorated_function(request: Request, *args, **kwargs):
            if request.ctx.session.get("user"):
                return await f(request, *args, **kwargs)

            # User is not authorized.
            return redirect(LOGOUT_REDIRECT_URL)

        return decorated_function

    return decorator


def view_login_required(view):
    """Authentication decorator."""

    def decorator(request: Request, *args, **kwargs):
        if request.ctx.session.get("user"):
            return view(request, *args, **kwargs)

        # User is not authorized.
        return redirect(LOGOUT_REDIRECT_URL)

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


async def check_black_status(repo: Row) -> bool:
    """Check if code is black."""
    folder = get_env_var("REPO_PREFIX") + get_process_name(repo.title)
    proc = await asyncio.create_subprocess_shell(
        f'cd {folder} && black --check . --exclude "(migrations|alembic)"',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()

    return "All done!" in stderr.decode()


async def check_security_headers(repo: Row, _session: ClientSession) -> str:
    """Return security headers grade."""
    if not repo.url:
        return ""

    url = f"https://securityheaders.com/?hide=on&q={repo.url}"
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
        SanicException("File not found", 404)

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


def update_remote(folder_name: str) -> None:
    """Push local changes to the remote repositories."""
    repo = git.Repo(folder_name)
    repo.index.add(["requirements.txt", "requirements-dev.txt"])
    repo.index.commit("Updated requirements.txt (automatically)")
    repo.remotes.origin.push("master")
    repo.remotes.github.push("master")


async def update_requirements(repo_name: str) -> None:
    """Update requirements for the given repository."""

    folder_name = get_env_var("REPO_PREFIX") + (
        repo_name.replace("%20", " ")
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
        .replace("/", "")
        .replace(".", "")
    )

    for file_name in ("requirements.txt", "requirements-dev.txt"):
        versions = await get_requirements_status(folder_name, file_name)
        logger.info(
            "Updated requirements for %s/%s: %s", folder_name, file_name, versions
        )

        async with aiofiles.open(f"{folder_name}/{file_name}", "w") as f:
            await f.writelines(
                [
                    ("==".join([package, new_version]) if new_version else package)
                    + "\n"
                    for package, _, new_version in versions
                ]
            )

    update_remote(folder_name)
