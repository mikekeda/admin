import os
import pytest

# Set test DB.
if os.environ.get("ADMIN_DB_NAME") is None:
    os.environ["ADMIN_DB_NAME"] = "test_admin"

from admin.models import User, db
from admin.views import app
from admin.settings import get_env_var

test_username = "test_user_1"
test_password = "qwerty"
app.config["WTF_CSRF_ENABLED"] = False
DB_URL = "asyncpg://{}:{}@{}:5432/{}".format(
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
    request, response = app.test_client.post(
        "/login", data=credentials, allow_redirects=False
    )
    session_cookie = response.cookies["session"]

    # Check as logged user.
    request, response = app.test_client.get(url, cookies={"session": session_cookie})
    assert response.status == 200


@pytest.fixture
async def setup():
    """Create test databases and tables for tests and drop them after."""
    await db.set_bind(DB_URL)

    await db.gino.drop_all()
    await db.gino.create_all()

    # Add test user.
    await User.create(
        username=test_username, email="test@test.com", password=test_password
    )
    await db.pop_bind().close()

    yield db

    await db.set_bind(DB_URL)
    await db.gino.drop_all()


def test_home_page(setup):
    # Anonymous user - redirect to login page.
    _test_page("/")


def test_metrics_page(setup):
    _test_page("/metrics")


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
        request, response = app.test_client.post(
            "/login", data=credentials, allow_redirects=False
        )
        assert response.status == 200
        assert request.ctx.session.get("user") is None

    # Login test user.
    credentials = {"username": test_username, "password": test_password}
    request, response = app.test_client.post(
        "/login", data=credentials, allow_redirects=False
    )
    assert response.status == 302
    assert request.ctx.session.get("user", {}).get("username") == test_username

    session_cookie = response.cookies["session"]

    # Try to open login page again.
    _, response = app.test_client.get(
        "/login", allow_redirects=False, cookies={"session": session_cookie}
    )
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
