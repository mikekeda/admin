import os

import requests

SITE_ENV_PREFIX = "ADMIN"


def get_env_var(name: str, default: str = "") -> str:
    """Get all sensitive data from google vm custom metadata."""
    try:
        name = "_".join([SITE_ENV_PREFIX, name])
        res = os.environ.get(name)
        if res is not None:
            # Check env variable (Jenkins build).
            return res
        else:
            res = requests.get(
                "http://metadata.google.internal/computeMetadata/"
                "v1/instance/attributes/{}".format(name),
                headers={"Metadata-Flavor": "Google"},
            )
            if res.status_code == 200:
                return res.text
    except requests.exceptions.ConnectionError:
        pass

    return default


SECRET_KEY = get_env_var("SECRET_KEY", "$2b$12$MWTgOhUlHUPKLkL0MO65UO")
LOGIN_REDIRECT_URL = "/"

SANIC_CONFIG = {
    "DEBUG": bool(get_env_var("DEBUG", "True")),
    "SOCKET_FILE": get_env_var("SOCKET_FILE", "/temp/admin.sock"),
    "SECRET_KEY": SECRET_KEY,
    "DB_USE_CONNECTION_FOR_REQUEST": False,
    "DB_USER": get_env_var("DB_USER", "admin_admin"),
    "DB_PASSWORD": get_env_var("DB_PASSWORD", "admin_admin_pasWQ27$"),
    "DB_HOST": get_env_var("DB_HOST", "127.0.0.1"),
    "DB_DATABASE": get_env_var("DB_NAME", "admin"),
    "redis": "redis://127.0.0.1/8",
}

API_KEY_HEADER = "Authorization"

REDIS_CACHE_CONFIG = {
    "default": {
        "cache": "aiocache.RedisCache",
        "endpoint": "localhost",
        "db": 8,
        "timeout": 2,
        "serializer": {"class": "aiocache.serializers.PickleSerializer"},
    }
}

# CELERY STUFF
CELERY_BROKER_URL = "redis://localhost:6379/8"
CELERY_result_backend = "redis://localhost:6379/8"
CELERY_accept_content = ["application/json"]
CELERY_task_serializer = "json"
CELERY_result_serializer = "json"
CELERY_timezone = "UTC"
