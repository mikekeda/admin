import asyncio
import os
import stat
import subprocess

import git
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import create_async_engine
import pytest

# Set test DB.
if os.environ.get("ADMIN_DB_NAME") is None:
    os.environ["ADMIN_DB_NAME"] = "test_admin"

from admin import utils
from admin.models import Base, hash_password, User
from admin.views import app
from admin.settings import get_env_var

test_username = "test_user_1"
test_password = os.urandom(16).hex()
app.config["WTF_CSRF_ENABLED"] = False
DB_URL = "postgresql+asyncpg://{}:{}@{}:5432/{}".format(
    get_env_var("DB_USER", "admin_admin"),
    get_env_var("DB_PASSWORD", "admin_admin_pasWQ27$"),
    get_env_var("DB_HOST", "127.0.0.1"),
    get_env_var("DB_NAME", "test_admin"),
)


def _test_page(url: str) -> None:
    """Test given page that should be not accessible for anonymous."""

    # Anonymous user - redirect to login page.
    request, response = app.test_client.get(url, allow_redirects=False)
    assert response.status == 302
    assert response.headers["Location"] == "/login"
    assert request.ctx.session.get("user") is None

    # Login.
    credentials = {"username": test_username, "password": test_password}
    request, response = app.test_client.post("/login", data=credentials, allow_redirects=False)
    session_cookie = response.cookies["session"]

    # Check as logged user.
    request, response = app.test_client.get(url, cookies={"session": session_cookie}, timeout=30)
    assert response.status == 200


@pytest.fixture
async def setup():
    """Create test databases and tables for tests and drop them after."""
    engine = create_async_engine(DB_URL)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

        # Add test user.
        await conn.execute(
            insert(User).values(
                {
                    "username": test_username,
                    "email": "test@test.com",
                    "password": hash_password(test_password),
                }
            )
        )
        await conn.commit()

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def test_home_page(setup):
    # Anonymous user - redirect to login page.
    _test_page("/")


def test_metrics_page(setup):
    _test_page("/metrics")


def test_logs_page(setup):
    _test_page("/logs")


def test_login_page(setup):
    # Anonymous user - redirect to login page.
    _, response = app.test_client.get("/login")
    assert response.status == 200

    # Login with invalid credentials.
    for username, password in (
        ("wrong", "wrong"),
        (test_username, "wrong"),
        ("wrong", test_password),
    ):
        credentials = {"username": username, "password": password}
        request, response = app.test_client.post("/login", data=credentials, allow_redirects=False)
        assert response.status == 200
        assert request.ctx.session.get("user") is None

    # Login test user.
    credentials = {"username": test_username, "password": test_password}
    request, response = app.test_client.post("/login", data=credentials, allow_redirects=False)
    assert response.status == 302
    assert request.ctx.session.get("user", {}).get("username") == test_username

    session_cookie = response.cookies["session"]

    # Try to open login page again.
    _, response = app.test_client.get("/login", allow_redirects=False, cookies={"session": session_cookie})
    assert response.status == 302
    assert response.headers["Location"] == "/"
    assert request.ctx.session.get("user") is not None

    # Logout.
    request, response = app.test_client.get("/logout", allow_redirects=False)
    assert response.status == 302
    assert response.headers["Location"] == "/login"
    assert request.ctx.session.get("user") is None


def test_about_page(setup):
    _, response = app.test_client.get("/about")
    assert response.status == 200


def test_404_page(setup):
    _, response = app.test_client.get("/this-page-doesnt-exist")
    assert response.status == 404


def test_requirement_regex_keeps_extras_out_of_pypi_name():
    match = utils.REQUIREMENT_RE.match("uvicorn[standard]==0.40.0")
    assert (match["name"], match["extras"], match["version"]) == ("uvicorn", "[standard]", "0.40.0")
    assert utils.REQUIREMENT_RE.match("Sanic-Cors==2.2.0")["name"] == "Sanic-Cors"
    for line in ("--extra-index-url https://download.pytorch.org/whl/cpu", "pkg>=1.0", "pkg @ git+https://x", ""):
        assert utils.REQUIREMENT_RE.match(line) is None


def test_format_requirement():
    assert utils.format_requirement("uvicorn[standard]", "0.40.0", "0.54.0") == "uvicorn[standard]==0.54.0"
    assert utils.format_requirement("celery", "5.6.3", None) == "celery==5.6.3"
    raw = "--extra-index-url https://download.pytorch.org/whl/cpu"
    assert utils.format_requirement(raw, None, None) == raw


def test_count_pylint_violations():
    report = [
        "************* Module run\n",
        "run.py:1:0: C0114: Missing module docstring (missing-module-docstring)\n",
        "tool/utils.py:10: [E1121(too-many-function-args), check_news] Too many positional arguments\n",
        ".pylintrc:1: [E0015(unrecognized-option), ] Unrecognized option found: cache-size\n",
        "xargs: pylint: No such file or directory\n",
        "Your code has been rated at 8.12/10 (previous run: 8.12/10, +0.00)\n",
    ]
    assert utils.count_matching_lines(report, utils.PYLINT_VIOLATION_RE) == 2


def test_count_pep8_violations():
    report = [
        "./api/tests.py:33:1: E402 module level import not at top of file\n",
        "tool/context_processors.py:20:25: W503 line break before binary operator\n",
        "/tmp/jenkins1472401243911634443.sh: 23: pycodestyle: not found\n",
    ]
    assert utils.count_matching_lines(report, utils.PEP8_VIOLATION_RE) == 2


def test_check_requirements_installable_raises_on_pip_failure(tmp_path, monkeypatch):
    site = tmp_path / "sites" / "demo"
    site.mkdir(parents=True)
    pip = tmp_path / "env" / "demo" / "bin" / "pip"
    pip.parent.mkdir(parents=True)
    pip.write_text("#!/bin/sh\necho 'ResolutionImpossible' >&2\nexit 1\n")
    pip.chmod(0o755)
    monkeypatch.setattr(utils, "ENV_FOLDER", str(tmp_path / "env"))

    with pytest.raises(RuntimeError, match="ResolutionImpossible"):
        asyncio.run(utils.check_requirements_installable(str(site)))

    pip.write_text("#!/bin/sh\nexit 0\n")
    asyncio.run(utils.check_requirements_installable(str(site)))


def test_update_requirements_restores_files_when_not_installable(tmp_path, monkeypatch):
    originals = {
        "requirements.txt": "celery==5.6.3\npython-dateutil==4.0.0\n",
        "requirements-dev.txt": "pytest==9.2.0\n",
    }
    for name, content in originals.items():
        (tmp_path / name).write_text(content)

    async def fake_status(folder, file_name, show_only_outdated=False):
        if file_name == "requirements.txt":
            return [("celery", "5.6.3", "5.7.0"), ("python-dateutil", "4.0.0", "4.0.0")]
        return [("pytest", "9.2.0", "9.2.0")]

    async def not_installable(folder):
        raise RuntimeError("conflict")

    def must_not_push(*args):
        raise AssertionError("nothing may be committed when requirements do not install")

    monkeypatch.setattr(utils, "repo_to_folder", lambda name: str(tmp_path))
    monkeypatch.setattr(utils, "sync_with_remote", lambda folder: None)
    monkeypatch.setattr(utils, "get_requirements_status", fake_status)
    monkeypatch.setattr(utils, "check_requirements_installable", not_installable)
    monkeypatch.setattr(utils, "update_remote", must_not_push)

    with pytest.raises(RuntimeError, match="conflict"):
        asyncio.run(utils.update_requirements("Demo"))

    for name, content in originals.items():
        assert (tmp_path / name).read_text() == content


def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def test_update_remote_pushes_every_remote_and_keeps_objects_group_writable(tmp_path):
    for name in ("origin", "github"):
        _git("init", "--bare", "-b", "main", str(tmp_path / f"{name}.git"), cwd=tmp_path)
    work = tmp_path / "work"
    _git("init", "-b", "main", str(work), cwd=tmp_path)
    for args in (
        ("config", "user.email", "t@t"),
        ("config", "user.name", "t"),
        ("config", "core.sharedRepository", "group"),
        ("remote", "add", "origin", str(tmp_path / "origin.git")),
        ("remote", "add", "github", str(tmp_path / "github.git")),
    ):
        _git(*args, cwd=work)
    (work / "requirements.txt").write_text("celery==5.7.0\n")
    (work / ".gitignore").write_text("package-lock.json\n")
    (work / "package-lock.json").write_text("{}\n")

    utils.update_remote(
        str(work), ["requirements.txt", "package-lock.json", "missing.txt"], "Updated requirements.txt (automatically)"
    )

    head = git.Repo(work).head.commit.hexsha
    for name in ("origin", "github"):
        assert git.Repo(tmp_path / f"{name}.git").commit("main").hexsha == head
    object_dirs = [p for p in (work / ".git" / "objects").iterdir() if len(p.name) == 2]
    assert object_dirs and all(p.stat().st_mode & stat.S_IWGRP for p in object_dirs)
    assert git.Repo(work).git.ls_files().splitlines() == ["requirements.txt"]


def test_update_remote_raises_when_push_fails(tmp_path):
    work = tmp_path / "work"
    _git("init", "-b", "main", str(work), cwd=tmp_path)
    _git("config", "user.email", "t@t", cwd=work)
    _git("config", "user.name", "t", cwd=work)
    _git("remote", "add", "origin", str(tmp_path / "missing.git"), cwd=work)
    (work / "requirements.txt").write_text("celery==5.7.0\n")

    with pytest.raises(git.GitCommandError):
        utils.update_remote(str(work), ["requirements.txt"], "msg")


def test_make_code_black_commits_partial_results_and_raises(tmp_path, monkeypatch):
    (tmp_path / "ugly.py").write_text("x = [1,\n  2]\n")
    locked = tmp_path / "locked.py"
    locked.write_text("y = ( 1 )\n")
    locked.chmod(0o444)
    committed = []

    monkeypatch.setattr(utils, "repo_to_folder", lambda name: str(tmp_path))
    monkeypatch.setattr(utils, "sync_with_remote", lambda folder: None)
    monkeypatch.setattr(utils, "update_remote", lambda folder, files, message: committed.extend(files))

    with pytest.raises(RuntimeError, match="locked.py"):
        asyncio.run(utils.make_code_black("Demo"))

    assert [os.path.basename(f) for f in committed] == ["ugly.py"]
    assert (tmp_path / "ugly.py").read_text() == "x = [1, 2]\n"
