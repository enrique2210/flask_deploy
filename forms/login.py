# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    username = StringField('Username', id='username', validators=[DataRequired()])
    password = PasswordField('Password', id='password', validators=[DataRequired()])
