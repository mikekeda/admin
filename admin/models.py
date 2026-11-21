from __future__ import annotations

import datetime
import enum
import secrets
import string
from typing import Optional

from bcrypt import checkpw, gensalt, hashpw
from sqlalchemy import (
    ARRAY,
    Boolean,
    Column,
    DateTime,
    Integer,
    Interval,
    Float,
    ForeignKey,
    Enum,
    select,
    String,
    Text,
    and_,
    or_,
    insert,
    update,
    UniqueConstraint,
)
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

from admin.settings import SECRET_KEY

Base = declarative_base()


def hash_password(value: str) -> str:
    """Hash a password or API key with its own random salt."""
    return hashpw(value.encode("utf-8"), gensalt()).decode("utf-8")


def check_password(value: str, hashed: str) -> bool:
    """Return whether value matches the stored bcrypt hash."""
    try:
        return checkpw(value.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:  # bcrypt 5 rejects inputs over 72 bytes; treat them as a failed match, not a 500.
        return False


def _uses_shared_salt(hashed: str) -> bool:
    """Return whether the hash predates per-user salts (those all used SECRET_KEY as the salt)."""
    return hashed.startswith(SECRET_KEY)


_DUMMY_HASH = hash_password(secrets.token_hex(16))


async def authenticate(conn: AsyncConnection, username: str, password: str) -> Optional[Row]:
    """If the given credentials are valid, return a User object."""
    user = (await conn.execute(select(User).where(User.username == username))).fetchone()
    if user is None:
        check_password(password, _DUMMY_HASH)  # Same bcrypt cost as a real user, so timing does not reveal usernames.
        return None

    if not check_password(password, user.password):
        return None

    if _uses_shared_salt(user.password):
        await conn.execute(update(User).where(User.id == user.id).values(password=hash_password(password)))

    return user


class BuildStatus(enum.Enum):
    STARTED = "STARTED"
    SUCCESS = "SUCCESS"
    UNSTABLE = "UNSTABLE"
    FAILURE = "FAILURE"
    NOT_BUILT = "NOT_BUILT"
    ABORTED = "ABORTED"


class User(Base):
    """User model."""

    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    password = Column(String(255), nullable=False)
    last_login = Column(DateTime)
    username = Column(String(64), nullable=False, unique=True)
    first_name = Column(String(64))
    last_name = Column(String(64))
    email = Column(String(64), nullable=False, unique=True)
    date_joined = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)


class Repo(Base):
    """Repo model."""

    __tablename__ = "repos"

    id = Column(Integer, primary_key=True)
    title = Column(String(64), nullable=False, unique=True)
    name = Column(String(64), nullable=False, unique=True)
    url = Column(String(64))
    codacy = Column(String(128))
    coverage = Column(String(128))
    processes = Column(ARRAY(Boolean), server_default="{}")


class Metric(Base):
    """Metric model."""

    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True)
    site = Column(Integer, ForeignKey("repos.id"))
    response_time = Column(Interval, nullable=False)
    response_size = Column(Float, nullable=False)
    status_code = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)


class JenkinsBuild(Base):
    __tablename__ = "jenkins_builds"
    __table_args__ = (UniqueConstraint("site_id", "number", name="unique_build"),)

    id = Column(Integer, primary_key=True)
    site_id = Column(Integer, ForeignKey("repos.id"), index=True)
    number = Column(Integer, nullable=False)
    status = Column(Enum(BuildStatus), nullable=False)
    started = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    finished = Column(DateTime)
    black_status = Column(Text)
    test_coverage = Column(Float)
    pep8_violations = Column(Integer)
    pylint_violations = Column(Integer)
    commit = Column(String(40))
    commit_message = Column(String(120))

    site = relationship("Repo")


class APIKey(Base):
    """API keys model."""

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("user.id"))
    prefix = Column(String(8), nullable=False, unique=True)
    hashed_key = Column(String(100), nullable=False)
    created = Column(DateTime, default=datetime.datetime.now)
    name = Column(
        String(50),
        nullable=False,
        doc="A free-form name for the API key. Need not be unique. 50 characters max.",
    )
    revoked = Column(
        Boolean(),
        default=False,
        doc="If the API key is revoked, clients cannot use it anymore.",
    )
    expiry_date = Column(DateTime, doc="Once API key expires, clients cannot use it anymore.")

    user = relationship("User")

    @classmethod
    async def authenticate(cls, ex, token: str) -> Optional[User]:
        """Get user by api key."""
        if not token:
            return None

        prefix, _, key = token.partition(".")
        api_key = (
            await ex(
                select(cls).where(
                    and_(
                        cls.prefix == prefix,
                        cls.revoked.is_(False),
                        or_(
                            cls.expiry_date >= datetime.datetime.now(),
                            cls.expiry_date.is_(None),
                        ),
                    )
                )
            )
        ).first()

        if api_key and check_password(key, api_key.hashed_key):
            return (await ex(select(User).where(User.id == api_key.user_id))).one()

        return None

    @staticmethod
    def _get_secure_random_string(length) -> str:
        """Generate random string."""
        secure_str = "".join((secrets.choice(string.ascii_letters) for _ in range(length)))
        return secure_str

    @classmethod
    async def create_key(cls, ex, user: User, name: str) -> str:
        """Create api key."""
        prefix = cls._get_secure_random_string(8)
        key = cls._get_secure_random_string(32)

        api_key = (
            await ex(
                insert(cls)
                .values(
                    user_id=user["id"],
                    prefix=prefix,
                    hashed_key=hash_password(key),
                    name=name,
                )
                .returning(cls.prefix),
            )
        ).one()

        return ".".join([api_key.prefix, key])
