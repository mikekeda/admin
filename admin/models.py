import datetime
import secrets
import string
from typing import Optional, Tuple

from bcrypt import hashpw
from sqlalchemy import ARRAY
from sqlalchemy.sql import and_, or_

from admin.app import db
from admin.settings import SECRET_KEY


def hash_password(value: str) -> str:
    """Hash user password to store hash in a database."""
    return hashpw(value.encode('utf-8'), SECRET_KEY.encode(
        'utf-8')).decode("utf-8")


async def authenticate(username: str, password: str) -> "User":
    """If the given credentials are valid, return a User object."""
    user = await User.query.gino.first(username=username)
    if user and user.password == hash_password(password):
        return user


class User(db.Model):
    """User model."""
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
        """Hash password."""
        if 'password' in kwargs:
            kwargs['password'] = hash_password(kwargs['password'])

        super().__init__(*args, **kwargs)


class Repo(db.Model):
    """Repo model."""
    __tablename__ = 'repos'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(64), nullable=False, unique=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    url = db.Column(db.String(64))
    codacy = db.Column(db.String(128))
    coverage = db.Column(db.String(128))
    processes = db.Column(ARRAY(db.Boolean()), server_default="{}")

    @property
    def process_name(self) -> str:
        return self.title.lower().replace("-", "_").replace(" ", "_")


class Metric(db.Model):
    """Metric model."""
    __tablename__ = 'metrics'

    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.Integer, db.ForeignKey("repos.id"))
    response_time = db.Column(db.Interval, nullable=False)
    response_size = db.Column(db.Float, nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)


class APIKey(db.Model):
    """API keys model."""
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Integer, db.ForeignKey("user.id"))
    prefix = db.Column(db.String(8), nullable=False, unique=True)
    hashed_key = db.Column(db.String(100), nullable=False)
    created = db.Column(db.DateTime, default=datetime.datetime.now)
    name = db.Column(db.String(50), nullable=False,
                     doc="A free-form name for the API key. Need not be unique. 50 characters max.")
    revoked = db.Column(db.Boolean(), default=False,
                        doc="If the API key is revoked, clients cannot use it anymore. (This cannot be undone.)")
    expiry_date = db.Column(db.DateTime, doc="Once API key expires, clients cannot use it anymore.")

    @classmethod
    async def authenticate(cls, token: str) -> Optional[User]:
        """Get user by api key."""
        if not token:
            return None

        prefix, _, key = token.partition(".")
        api_key = await cls.load(user=User).query.where(and_(
            cls.prefix == prefix,
            cls.revoked.is_(False),
            or_(
                cls.expiry_date >= datetime.datetime.now(),
                cls.expiry_date.is_(None),
            ),
        )).gino.first()
        if api_key and api_key.hashed_key == hash_password(key):
            return api_key.user

        return None

    @staticmethod
    def _get_secure_random_string(length) -> str:
        """Generate random string."""
        secure_str = ''.join((secrets.choice(string.ascii_letters) for _ in range(length)))
        return secure_str

    @classmethod
    async def create_key(cls, user: User, name: str) -> Tuple["APIKey", str]:
        """Create api key."""
        prefix = cls._get_secure_random_string(8)
        key = cls._get_secure_random_string(32)
        api_key = await cls.create(
            user=user,
            prefix=prefix,
            hashed_key=hash_password(key),
            name=name,
        )
        return api_key, key
