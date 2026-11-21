import asyncio
import json
import os
import re
import uuid
from datetime import datetime, UTC
from functools import cache, wraps
from shlex import quote
from typing import Iterator, Optional, Iterable
from xml.etree import ElementTree

import aiofiles
from aiohttp import ClientConnectorError, ClientError, ClientSession
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

REQUIREMENTS_FILES = ("requirements.txt", "requirements-dev.txt")
# Pinned by sites but published without wheels (checked 2026-11); everything else must resolve to a wheel.
SDIST_ALLOWED = ("flask-testing", "langid", "pylint-flask")
# Only exact pins are auto-updated; extras stay on the line but are not part of the PyPI project name.
REQUIREMENT_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?==(?P<version>\S+)$")
# Matches pylint's default ("f.py:1:0: C0114:") and parseable ("f.py:1: [C0114(...)") formats.
PYLINT_VIOLATION_RE = re.compile(r"^(?!\.pylintrc:)[^*\s].*:\d+:(?:\d+:)? \[?[CRWEF]\d{4}\b")
PEP8_VIOLATION_RE = re.compile(r"^.+:\d+:\d+: [EWC]\d{3} ")
# Shared by the check and the "make black" action so they agree; matches the 120 used by pycodestyle in Jenkins.
BLACK_OPTIONS = '--line-length 120 --extend-exclude "/(migrations|alembic|node_modules)/"'


def cached(ttl: int = None, args_slice: int = None):
    """Cache decorator."""

    def decorator(f):
        @wraps(f)
        async def decorated_function(*args, **kwargs):
            ordered_kwargs = sorted(kwargs.items())
            cache_key = (
                (f.__module__ or "") + f.__name__ + str(args[:args_slice] if args_slice else args) + str(ordered_kwargs)
            )

            # Pooled commands, not a dedicated client: holding a connection across f() exhausts the pool.
            value = await app.ctx.redis.get(cache_key)
            if value:
                return json.loads(value)

            value = await f(*args, **kwargs)
            await app.ctx.redis.set(cache_key, json.dumps(value), ex=ttl)

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
async def check_black_status(site: str) -> str:
    """Check if code is black."""
    folder = get_env_var("REPO_PREFIX") + get_process_name(site)
    proc = await asyncio.create_subprocess_shell(
        f"cd {quote(folder)} && black --check . {BLACK_OPTIONS}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()

    return "" if "All done!" in stderr.decode() else stderr.decode()


def get_log_files(repo: Row, process_statuses: dict[str, str]) -> Iterator[tuple[str, str]]:
    """Return log file name with corresponding supervisor status."""
    if len(repo.processes) >= 1:
        yield "error.log", process_statuses[get_process_name(repo.title)]
        yield "out.log", process_statuses[get_process_name(repo.title)]
    if len(repo.processes) >= 2:
        yield "worker.log", process_statuses[f"{get_process_name(repo.title)}_celery"]
    if len(repo.processes) >= 3:
        yield "beat.log", process_statuses[f"{get_process_name(repo.title)}_celerybeat"]


@cached(ttl=60, args_slice=1)
async def get_pypi_version(line: str, _session: ClientSession) -> tuple[str, Optional[str], Optional[str]]:
    """Get the current and latest version for given package."""

    match = REQUIREMENT_RE.match(line.strip())
    if not match:
        return line, None, None

    package = match["name"] + (match["extras"] or "")
    current_version = match["version"]
    url = f"https://pypi.org/pypi/{match['name']}/json"
    try:
        async with _session.get(url) as resp:
            new_version = (await resp.json())["info"]["version"]
    except (ClientError, KeyError, ValueError) as e:
        logger.warning("Error getting pypi info for %s: %s", package, repr(e))
        return package, current_version, None

    return package, current_version, new_version


def format_requirement(package: str, current_version: Optional[str], new_version: Optional[str]) -> str:
    """Render a requirements line, bumping it to new_version when one is given."""
    if current_version is None:
        return package

    return f"{package}=={new_version or current_version}"


@cached(ttl=60, args_slice=1)
async def get_npm_version(
    package: str, current_version: str, _session: ClientSession
) -> tuple[str, Optional[str], Optional[str]]:
    url = f"https://registry.npmjs.org/{package}"
    async with _session.get(url) as resp:
        new_version = (await resp.json())["dist-tags"]["latest"]

    return package, current_version, new_version


async def get_npm_status(
    title: str, show_only_outdated: bool = False
) -> Iterable[tuple[str, Optional[str], Optional[str]]]:
    folder = get_env_var("REPO_PREFIX") + get_process_name(title)
    async with aiofiles.open(f"{folder}/static/package.json", "r") as f:
        content = json.loads(await f.read())
        dependencies = content.get("dependencies", {})
        async with ClientSession() as _session:
            versions = await asyncio.gather(
                *[get_npm_version(package, version.lstrip("^"), _session) for package, version in dependencies.items()]
            )

    if show_only_outdated:
        versions = [
            (package, current_version, new_version)
            for package, current_version, new_version in versions
            if new_version is not None and current_version != new_version
        ]

    return versions


async def get_requirements_status(
    folder: str, file_name: str, show_only_outdated: bool = False
) -> Iterable[tuple[str, Optional[str], Optional[str]]]:
    """Parse requirements.txt to get list of packages with current and latest versions."""
    async with aiofiles.open(f"{folder}/{file_name}", "r") as f:
        requirements = await f.readlines()

    async with ClientSession() as _session:
        versions = await asyncio.gather(*[get_pypi_version(line.strip("\n"), _session) for line in requirements])

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
    if requirements_dev_status and not issubclass(type(requirements_dev_status), Exception):
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
                # Not login(): that would save a 30-day UI session for every API call.
                request.ctx.user = {"id": user.id, "username": user.username}
                return await f(request, *args, **kwargs)

            # User is not authorized.
            return response.json({"status": "not_authorized"}, 403)

        return decorated_function

    return decorator


def sync_with_remote(folder_name: str) -> None:
    """Fast-forward the checkout to origin/main; raise GitCommandError if it has diverged."""
    git.Repo(folder_name).remotes.origin.pull("main", ff_only=True)


def update_remote(folder_name: str, changed_files: list[str], commit_message: str) -> None:
    """Commit the changed files and push them to every remote; raise if any push fails."""
    repo = git.Repo(folder_name)
    # Missing untracked or ignored paths (e.g. an ignored package-lock.json) make `git add` fail.
    paths = [p for p in changed_files if os.path.exists(os.path.join(folder_name, p)) or repo.git.ls_files("--", p)]
    ignored = set(repo.ignored(*paths)) if paths else set()
    paths = [p for p in paths if p not in ignored]
    if not paths:
        return  # `git add --all --` with no paths would stage the whole tree.

    # The git CLI honours core.sharedRepository; GitPython's own object writer does not.
    repo.git.add("--all", "--", *paths)
    repo.git.commit("-m", commit_message)
    for remote in repo.remotes:
        remote.push("main").raise_if_error()


async def check_requirements_installable(folder_name: str) -> None:
    """Raise RuntimeError if the site's requirements files cannot be installed together."""
    pip = f"{ENV_FOLDER}/{os.path.basename(folder_name)}/bin/pip"
    requirement_args = [arg for file_name in REQUIREMENTS_FILES for arg in ("-r", file_name)]
    proc = await asyncio.create_subprocess_exec(
        pip,
        "install",
        "--dry-run",
        "--quiet",
        "--no-cache-dir",
        "--disable-pip-version-check",
        # Building an sdist runs its setup.py; wheels resolve without executing package code.
        "--only-binary",
        ":all:",
        *[arg for name in SDIST_ALLOWED for arg in ("--no-binary", name)],
        *requirement_args,
        cwd=folder_name,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode:
        raise RuntimeError(f"Updated requirements for {folder_name} do not install:\n{stderr.decode()[-3000:]}")


async def update_requirements_txt(packages: Optional[set[str]], folder_name: str) -> list[str]:
    """Update requirements.txt and requirements-dev.txt."""
    updated_packages = []

    for file_name in REQUIREMENTS_FILES:
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
        updated_packages.extend(
            [
                f"{package}: {current_version}->{new_version}"
                for package, current_version, new_version in versions
                if new_version and new_version != current_version and (packages is None or package in packages)
            ]
        )

        async with aiofiles.open(f"{folder_name}/{file_name}", "w") as f:
            await f.writelines(
                [
                    format_requirement(
                        package,
                        current_version,
                        new_version if (packages is None or package in packages) else None,
                    )
                    + "\n"
                    for package, current_version, new_version in versions
                ]
            )

    return updated_packages


def repo_to_folder(repo_name: str) -> str:
    """Convert repository name to folder name."""
    return get_env_var("REPO_PREFIX") + (
        repo_name.replace("%20", " ").lower().replace("-", "_").replace(" ", "_").replace("/", "").replace(".", "")
    )


async def update_requirements(repo_name: str, packages: set[str] = None) -> None:
    """Update requirements for the given repository."""

    folder_name = repo_to_folder(repo_name)
    await asyncio.to_thread(sync_with_remote, folder_name)

    originals = {}
    for file_name in REQUIREMENTS_FILES:
        async with aiofiles.open(f"{folder_name}/{file_name}", "r") as f:
            originals[file_name] = await f.read()

    async def restore_originals() -> None:
        for name, content in originals.items():
            async with aiofiles.open(f"{folder_name}/{name}", "w") as out:
                await out.write(content)

    updated_packages = await update_requirements_txt(packages, folder_name)
    if not updated_packages:
        await restore_originals()
        return

    try:
        await check_requirements_installable(folder_name)
    except Exception:
        await restore_originals()
        raise

    updated_packages = ", ".join(updated_packages)
    updated_packages = updated_packages if len(updated_packages) <= 69 else updated_packages[:66] + "..."
    commit_message = f"Updated requirements.txt (automatically)\n{updated_packages}"

    await asyncio.to_thread(update_remote, folder_name, list(REQUIREMENTS_FILES), commit_message)


async def make_code_black(repo_name: str) -> None:
    """Make code black for the given repository."""
    folder = repo_to_folder(repo_name)
    await asyncio.to_thread(sync_with_remote, folder)
    proc = await asyncio.create_subprocess_shell(
        f"cd {quote(folder)} && black . {BLACK_OPTIONS}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    lines = stderr.decode().splitlines()

    # Commit whatever black did reformat, so a partial run never leaves the deployed tree dirty.
    changed_files = [line.removeprefix("reformatted ") for line in lines if line.startswith("reformatted ")]
    await asyncio.to_thread(update_remote, folder, changed_files, "Made code black (automatically)")

    errors = [line for line in lines if line.startswith("error: ")]
    if proc.returncode or errors:
        raise RuntimeError(f"black failed for {repo_name}:\n" + "\n".join(errors or lines[-20:]))


async def update_frontend(repo_name: str) -> None:
    """Update frontend for the given repository."""
    folder = repo_to_folder(repo_name)
    await asyncio.to_thread(sync_with_remote, folder)
    proc = await asyncio.create_subprocess_shell(
        f"cd {quote(folder)}/static && npm update --save --ignore-scripts",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if "changed " not in stdout.decode():
        logger.warning("Error updating frontend: " + stderr.decode() or stdout.decode())
        return None

    await asyncio.to_thread(
        update_remote,
        folder,
        ["static/package.json", "static/package-lock.json", "static/node_modules"],
        "Updated frontend (automatically)",
    )


def count_matching_lines(lines: Iterable[str], pattern: re.Pattern) -> int:
    """Count report lines that are real violations (tool errors such as 'not found' are skipped)."""
    return sum(1 for line in lines if pattern.match(line))


async def save_build_info(engine: AsyncEngine, jenkins_site: str, build_number: int, status: str) -> None:
    """Save Jenkins build info."""
    values = {}
    if status == "SUCCESS":
        # Get test_coverage.
        try:
            test_coverage = (
                ElementTree.parse(f"{JENKINS_HOME}/workspace/{jenkins_site}/reports/coverage.xml")
                .getroot()
                .get("line-rate")
            )
        except FileNotFoundError:
            test_coverage = 0

        values = {
            "black_status": await check_black_status(jenkins_site.lower()),
            "test_coverage": float(test_coverage),
            "pep8_violations": 0,
            "pylint_violations": 0,
            "commit": "",
            "commit_message": "",
        }

        with open(f"{JENKINS_HOME}/workspace/{jenkins_site}/reports/pylint.report", "r") as f:
            values["pylint_violations"] = count_matching_lines(f, PYLINT_VIOLATION_RE)

        with open(f"{JENKINS_HOME}/workspace/{jenkins_site}/reports/pep8.report", "r") as f:
            values["pep8_violations"] = count_matching_lines(f, PEP8_VIOLATION_RE)

        # Get commit, commit_message.
        with open(
            f"{JENKINS_HOME}/jobs/{jenkins_site}/builds/{build_number}/changelog.xml",
            "r",
        ) as f:
            for line in f:
                if line.startswith("commit "):
                    values["commit"] = line[6:].strip()
                elif line.startswith("    "):
                    if values.get("commit_message"):
                        values["commit_message"] += "\n" + line[4:].strip()
                    else:
                        values["commit_message"] = line[4:].strip()

                    # Trim commit message if needed
                    values["commit_message"] = (
                        values["commit_message"]
                        if len(values["commit_message"]) <= 120
                        else values["commit_message"][:117] + "..."
                    )

    async with engine.connect() as conn:
        site = jenkins_site.replace("_", " ")
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
                        finished=(datetime.now() if status in {"SUCCESS", "FAILURE", "ABORTED"} else None),
                        **values,
                    )
                    .returning(JenkinsBuild.id)
                )
            ).one()

        await conn.commit()
