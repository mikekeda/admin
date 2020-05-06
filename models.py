import datetime
from bcrypt import hashpw

from app import db

import settings


def hash_password(value: str) -> str:
    """ Hash user password to store hash in a database. """
    return hashpw(value.encode('utf-8'), settings.SECRET_KEY.encode(
        'utf-8')).decode("utf-8")


async def authenticate(username: str, password: str) -> object:
    """ If the given credentials are valid, return a User object. """
    user = await User.query.gino.first(username=username)
    if user and user.password == hash_password(password):
        return user


def login(request, user) -> None:
    """ Store user id and username in the session. """
    request['session']['user'] = {'id': user.id, 'username': user.username}


def logout(request):
    """ Remove user id and username from the session. """
    return request['session'].pop('user', None)


class User(db.Model):
    """ User model. """
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(255), nullable=False)
    last_login = db.Column(db.DateTime)
    username = db.Column(db.String(64), nullable=False, unique=True)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    email = db.Column(db.String(64), nullable=False, unique=True)
    date_joined = db.Column(db.DateTime, nullable=False,
                            default=datetime.datetime.utcnow)

    def __init__(self, *args, **kwargs):
        if 'password' in kwargs:
            kwargs['password'] = hash_password(kwargs['password'])

        super().__init__(*args, **kwargs)
