import os
import unittest

# Set test DB.
if os.environ.get('ADMIN_DB_NAME') is None:
    os.environ['ADMIN_DB_NAME'] = 'test_admin'

from main import app
from models import User, MODELS

app.config['WTF_CSRF_ENABLED'] = False


class BaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create all tables.
        for model in MODELS:
            model.create_table()

        # Add test user.
        cls.user = User(username='test_user_1', email='test@test.com',
                        password='qwerty')
        cls.user.save()

    @classmethod
    def tearDownClass(cls):
        # Drop all tables.
        for model in reversed(MODELS):
            model.drop_table(cascade=True)

    def test_home_page(self):
        # Anonymous user - redirect to login page.
        request, response = app.test_client.get('/', allow_redirects=False)
        self.assertEqual(response.status, 302)
        self.assertEqual(response.headers["Location"], '/login')
        self.assertIsNone(request['session'].get('user'))

    def test_login_page(self):
        # Anonymous user - redirect to login page.
        _, response = app.test_client.get('/login')
        self.assertEqual(response.status, 200)

        # Login test user.
        credentials = {
            'username': self.user.username,
            'password': self.user.password
        }
        request, response = app.test_client.post(
            '/login',
            data=credentials,
            allow_redirects=False
        )
        self.assertEqual(response.status, 302)
        self.assertEqual(request['session'].get('user', {}).get('username'),
                         self.user.username)

    def test_about_page(self):
        _, response = app.test_client.get('/about')
        self.assertEqual(response.status, 200)
