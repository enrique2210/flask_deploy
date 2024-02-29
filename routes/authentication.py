from flask import render_template, request, Blueprint, redirect, url_for
from flask_login import (
    current_user,
    login_user,
    logout_user
)

from forms.login import LoginForm
from models.users import Users
from models.utils import verify_pass

blueprint = Blueprint('authentication', __name__, url_prefix='')


@blueprint.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm(request.form)

    if 'login' in request.form:

        username = request.form['username']
        password = request.form['password']

        user = Users.query.filter_by(username=username).first()

        if user and verify_pass(password, user.password):
            login_user(user)
            return redirect(url_for('home.dashboard'))

        return render_template('accounts/login.html',
                               msg='Usuario o contraseña incorrecto',
                               form=login_form)

    if not current_user.is_authenticated:
        return render_template('accounts/login.html',
                               form=login_form)
    else:
        return redirect(url_for('home.dashboard'))


@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication.login'))
