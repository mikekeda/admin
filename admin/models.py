from __future__ import annotations

import datetime
from typing import Optional

from bcrypt import hashpw
from sqlalchemy import (
    ARRAY,
    Boolean,
    Column,
    DateTime,
    Integer,
    Interval,
    Float,
    ForeignKey,
    select,
    String,
)
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.ext.declarative import declarative_base

from admin.settings import SECRET_KEY

Base = declarative_base()


def hash_password(value: str) -> str:
    """Hash user password to store hash in a database."""
    return hashpw(value.encode("utf-8"), SECRET_KEY.encode("utf-8")).decode("utf-8")


async def authenticate(
    conn: AsyncConnection, username: str, password: str
) -> Optional[Row]:
    """If the given credentials are valid, return a User object."""
    user = (
        await conn.execute(select(User).where(User.username == username))
    ).fetchone()
    if user and user.password == hash_password(password):
        return user

    return None


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
