import asyncio
import os

from aiohttp import ClientSession, ClientConnectorError
import aiofiles
from sanic.exceptions import abort
from sanic.response import html, redirect
from sanic.views import HTTPMethodView

import settings
from models import User, authenticate, login, logout
from forms import LoginForm
from main import app, jinja


async def get_site_status(url: str, session):
    """ Get site status. """
    try:
        async with session.get(url) as resp:
            return url, resp.status
    except ClientConnectorError:
        return url, 404


async def get_user(request):
    request['user'] = None
    user_dict = request['session'].get('user')
    if user_dict:
        request['user'] = User.get(id=user_dict['id'])

    return request['user']


@app.route("/")
async def homepage(request):
    if not request['session'].get('user'):
        return redirect('/login')

    async with ClientSession() as session:
        tasks = [
            asyncio.ensure_future(get_site_status(site['url'], session))
            for site in settings.SITES.values()
        ]

        statuses = {key: val for key, val in await asyncio.gather(*tasks)}

        for site in settings.SITES.values():
            site['status'] = statuses.get(site['url']) == 200

    return html(jinja.render_string('sites.html', request,
                                    sites=settings.SITES.values()))


@app.route("/sites/<site_name>/logs")
async def logs_page(request, site_name):
    """ View site logs. """
    if not request['session'].get('user'):
        return redirect('/login')

    site = settings.SITES.get(site_name)
    if not site or not os.path.exists(site['logs']):
        abort(404)

    async with aiofiles.open(site['logs'], 'r') as f:
        logs = await f.readlines()

    return html(jinja.render_string('logs.html', request, logs=''.join(logs),
                                    site_name=site_name))


@app.route("/about")
async def about_page(request):
    """ About page. """
    return html(jinja.render_string('about.html', request))


@app.route("/logout")
async def logout_page(request):
    """ Logout page. """
    logout(request)
    return redirect(settings.LOGIN_REDIRECT_URL)


class LoginView(HTTPMethodView):
    # noinspection PyMethodMayBeStatic
    async def get(self, request):
        """ User login form. """
        if request['session'].get('user'):
            return redirect(settings.LOGIN_REDIRECT_URL)

        form = LoginForm(request)

        return jinja.render('login.html', request, form=form)

    # noinspection PyMethodMayBeStatic
    async def post(self, request):
        """ Submit for User login form. """
        form = LoginForm(request)

        if form.validate():
            user = await authenticate(form.data['username'],
                                      form.data['password'])
            if user:
                login(request, user)
                return redirect(settings.LOGIN_REDIRECT_URL)
            else:
                form.username.errors.append('Not valid username or password!')

        return jinja.render('login.html', request, form=form)


app.add_route(LoginView.as_view(), '/login')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
