import datetime
from bcrypt import hashpw
from peewee import PostgresqlDatabase, Model, CharField, DateTimeField

import settings

database = PostgresqlDatabase(**settings.DB_CONFIG)


def hash_password(value: str) -> str:
    """ Hash user password to store hash in a database. """
    return hashpw(value.encode('utf-8'), settings.SECRET_KEY.encode(
        'utf-8')).decode("utf-8")


async def authenticate(username: str, password: str) -> object:
    """ If the given credentials are valid, return a User object. """
    user = User.get(username=username)
    if user and user.password == hash_password(password):
        return user


def login(request, user) -> None:
    """ Store user id and username in the session. """
    request['session']['user'] = {'id': user.id, 'username': user.username}


def logout(request):
    """ Remove user id and username from the session. """
    return request['session'].pop('user', None)


class PasswordField(CharField):
    def db_value(self, value):
        """Convert the python value for storage in the database."""
        return hash_password(value)


class User(Model):
    """ User model. """

    password = PasswordField()
    last_login = DateTimeField(null=True)
    username = CharField(max_length=64, unique=True)
    first_name = CharField(max_length=64, null=True)
    last_name = CharField(max_length=64, null=True)
    email = CharField(max_length=64, unique=True)
    date_joined = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = database


MODELS = [User]
