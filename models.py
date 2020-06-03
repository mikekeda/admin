import datetime
import uuid

from bcrypt import hashpw

from sanic_session.base import SessionDict

from app import db, session

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


async def login(request, user) -> None:
    """ Store user id and username in the session. """
    request.ctx.session['user'] = {'id': user.id, 'username': user.username}

    # Refresh sid.
    old_sid = session.interface.prefix + request.ctx.session.sid
    request.ctx.session.sid = uuid.uuid4().hex  # generate new sid
    await session.interface._delete_key(old_sid)  # delete old record from datastore


def logout(request):
    """ Remove user id and username from the session. """
    request.ctx.session = SessionDict(sid=request.ctx.session.sid)  # clear session
    request.ctx.session.modified = True  # mark as modified to update sid in cookies


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
