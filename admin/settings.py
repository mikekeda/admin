import os

import requests

SITE_ENV_PREFIX = "ADMIN"


def get_env_var(name: str, default: str = "") -> str:
    """Get all sensitive data from google vm custom metadata."""
    try:
        name = f"{SITE_ENV_PREFIX}_{name}"
        res = os.environ.get(name)
        if res is not None:
            # Check env variable (Jenkins build).
            return res
        else:
            res = requests.get(
                f"http://metadata.google.internal/computeMetadata/v1/instance/attributes/{name}",
                headers={"Metadata-Flavor": "Google"},
            )
            if res.status_code == 200:
                return res.text
    except requests.exceptions.ConnectionError:
        pass

    return default


SECRET_KEY = get_env_var("SECRET_KEY", "$2b$12$MWTgOhUlHUPKLkL0MO65UO")
DEBUG = bool(get_env_var("DEBUG", "True"))
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login"
ENV_FOLDER = get_env_var("ENV_FOLDER")
JENKINS_HOME = get_env_var("JENKINS_HOME")
SERVER_IP = get_env_var("SERVER_IP")
API_KEY_HEADER = "Authorization"

SANIC_CONFIG = {
    "DEBUG": bool(get_env_var("DEBUG", "True")),
    "SOCKET_FILE": get_env_var("SOCKET_FILE", "/temp/admin.sock"),
    "SECRET_KEY": SECRET_KEY,
    "DB_USER": get_env_var("DB_USER", "admin_admin"),
    "DB_PASSWORD": get_env_var("DB_PASSWORD", "admin_admin_pasWQ27$"),
    "DB_HOST": get_env_var("DB_HOST", "127.0.0.1"),
    "DB_DATABASE": get_env_var("DB_NAME", "admin"),
    "redis": "redis://127.0.0.1/8",
    "RESPONSE_TIMEOUT": 120,
}

# CELERY STUFF
CELERY_BROKER_URL = "redis://localhost:6379/8"
CELERY_result_backend = "redis://localhost:6379/8"
CELERY_accept_content = ["application/json"]
CELERY_task_serializer = "json"
CELERY_result_serializer = "json"
CELERY_timezone = "UTC"

EMAIL_CONFIG = {
    "host": "smtp.mailgun.org",
    "port": 2525,
    "host_user": get_env_var("EMAIL_HOST_USER"),
    "host_password": get_env_var("EMAIL_HOST_PASSWORD"),
    "server_name": "info.mkeda.me",
    "email": "admin@info.mkeda.me",
    "recipient": "mriynuk@gmail.com",
}
