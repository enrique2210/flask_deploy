from flask import render_template, request, Blueprint, redirect, url_for
from flask_login import current_user
from jinja2 import TemplateNotFound

blueprint = Blueprint('home', __name__, url_prefix='/')


@blueprint.route('/')
def index():
    return "Hello World :3"

@blueprint.route('/dashboard')
def dashboard():
    if current_user.is_authenticated:
        return render_template('/home/index.html')
    return redirect(url_for('authentication.login'))
