import os
import json
import requests

SITE_ENV_PREFIX = 'ADMIN'


def get_env_var(name: str, default: str = '') -> str:
    """ Get all sensitive data from google vm custom metadata. """
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

SITES = json.loads(get_env_var('SITES', json.dumps([])))
for site in SITES:
    if not site.get('name'):
        site['name'] = site['title'].lower().replace(' ', '_')
    if not site.get('log'):
        site['logs'] = '{}/{}/error.log'.format(
            get_env_var('LOG_FOLDER'), site['name']
        )
SITES = {site['name']: site for site in SITES}
