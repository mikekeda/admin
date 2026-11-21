from sanic_wtf import SanicForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired


class LoginForm(SanicForm):
    """Login form."""

    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


class CSRFForm(SanicForm):
    """CSRF token only, for POSTs whose fields are built dynamically (repo and package checkboxes)."""
