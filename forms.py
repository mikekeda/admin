from sanic_wtf import SanicForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired


class LoginForm(SanicForm):
    """ Login form. """
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
