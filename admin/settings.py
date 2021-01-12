import os
import requests

SITE_ENV_PREFIX = 'ADMIN'


def get_env_var(name: str, default: str = '') -> str:
    """Get all sensitive data from google vm custom metadata."""
    try:
        name = '_'.join([SITE_ENV_PREFIX, name])
        res = os.environ.get(name)
        if res is not None:
            # Check env variable (Jenkins build).
            return res
        else:
            res = requests.get(
                'http://metadata.google.internal/computeMetadata/'
                'v1/instance/attributes/{}'.format(name),
                headers={'Metadata-Flavor': 'Google'}
            )
            if res.status_code == 200:
                return res.text
    except requests.exceptions.ConnectionError:
        pass

    return default


SECRET_KEY = get_env_var('SECRET_KEY', '$2b$12$MWTgOhUlHUPKLkL0MO65UO')
LOGIN_REDIRECT_URL = '/'
API_KEY_HEADER = "Authorization"

REDIS_CACHE_CONFIG = {
    'default': {
        'cache': 'aiocache.RedisCache',
        'endpoint': 'localhost',
        'db': 8,
        'timeout': 2,
        'serializer': {
            'class': 'aiocache.serializers.PickleSerializer'
        }
    }
}
