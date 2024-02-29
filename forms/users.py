
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, DateField, DateTimeField, \
    PasswordField, SelectMultipleField,HiddenField
from wtforms.validators import DataRequired, Length

from models.constants import ROLES


class UsersForm(FlaskForm):
    users_id = HiddenField(label='users_id', id='users_id', validators=[DataRequired()])
    username = StringField(label='username', id='username', validators=[DataRequired(), Length(max=100)])
    password = PasswordField(label='password', id='password', validators=[DataRequired(), Length(max=100)])
    confirm_password = PasswordField(label='confirm_password', id='confirm_password', validators=[DataRequired(), Length(max=100)])
    role = SelectField(label='role', id='role', choices=ROLES, validators=[DataRequired()])
