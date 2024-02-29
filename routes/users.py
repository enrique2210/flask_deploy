from flask import render_template, request, Blueprint
from flask_login import current_user
from jinja2 import TemplateNotFound

from forms.users import UsersForm
from models.constants import Role
from models.users import Users
from models.utils import is_admin

blueprint = Blueprint('users', __name__, url_prefix='/users')


@blueprint.route('')
@is_admin
def index():
    return render_template('/users/table.html', segment='users')

@blueprint.route('form')
@is_admin
def form():
    users_form = UsersForm()
    return render_template('/users/form.html', segment='users', form=users_form)

# Helper - Extract current page name from request
def get_segment(request):
    try:
        segment = request.path.split('/')[-1]
        if segment == '':
            segment = 'index'
        return segment
    except:
        return None


@blueprint.route('form/<id>')
@is_admin
def form_edit(id):
    users = Users.find_by_id(id)
    users_form = UsersForm(obj=users,users_id=users.id)
    return render_template('/users/form_edit.html', segment='users', form=users_form)
