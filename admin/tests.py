import os
import pytest

# Set test DB.
if os.environ.get('ADMIN_DB_NAME') is None:
    os.environ['ADMIN_DB_NAME'] = 'test_admin'

from admin.models import User, db
from admin.views import app
from admin.settings import get_env_var

test_username = 'test_user_1'
test_password = 'qwerty'
app.config['WTF_CSRF_ENABLED'] = False
DB_URL = "asyncpg://{}:{}@{}:5432/{}".format(
    get_env_var('DB_USER', 'admin_admin'),
    get_env_var('DB_PASSWORD', 'admin_admin_pasWQ27$'),
    get_env_var('DB_HOST', '127.0.0.1'),
    get_env_var('DB_NAME', 'test_admin')
)


@pytest.fixture
async def setup():
    """Create test databases and tables for tests and drop them after."""
    await db.set_bind(DB_URL)

    await db.gino.drop_all()
    await db.gino.create_all()

    # Add test user.
    await User.create(username=test_username, email='test@test.com',
                      password=test_password)
    await db.pop_bind().close()

    yield db

    await db.set_bind(DB_URL)
    await db.gino.drop_all()


def test_home_page(setup):
    # Anonymous user - redirect to login page.
    request, response = app.test_client.get('/', allow_redirects=False)
    assert response.status == 302
    assert response.headers["Location"] == '/login'
    assert request.ctx.session.get('user') is None


def test_login_page(setup):
    # Anonymous user - redirect to login page.
    _, response = app.test_client.get('/login')
    assert response.status == 200

    # Login test user.
    credentials = {
        'username': test_username,
        'password': test_password
    }
    request, response = app.test_client.post(
        '/login',
        data=credentials,
        allow_redirects=False
    )
    assert response.status == 302
    assert request.ctx.session.get('user', {}).get('username') == test_username


def test_about_page(setup):
    _, response = app.test_client.get('/about')
    assert response.status == 200
