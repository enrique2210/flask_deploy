import os
import uuid

from flask import request, make_response, Blueprint
from flask_login import login_required, current_user
from sqlalchemy import text, select, cast

from forms.users import UsersForm
from models import db
from models.constants import Role
from models.users import Users
from models.utils import is_admin
from models.utils import hash_pass
blueprint = Blueprint('api_user', __name__, url_prefix='/api/users')


@blueprint.route('', methods=['GET'])
@is_admin
def get():
    try:
        _query = db.session.query(Users.id, Users.username, Users.status, Users.role)
        _query = _query.where(Users.role != Role.ADMIN)
        if "status" in request.args:
            _query = _query.where(Users.status == request.args['status'])

        result = _query.all()
        result = [res._asdict() for res in result]


        return make_response(result, 201)
    except Exception as e:
        return make_response(e.args, 400)


@blueprint.route('/activate', methods=['GET'])
@is_admin
def update_status():
    try:
        user = Users.find_by_id(request.args['user_id'])
        user.status = request.args['new_status']
        db.session.commit()
        return make_response("Usuario actualizado", 201)
    except Exception as e:
        return make_response(e.args, 400)


@blueprint.route('', methods=['POST'])
@is_admin
def add():
    try:
        form = request.form

        if form.get("password") != form.get("confirm_password"):
            return make_response("Contraseñas no coinciden", 400)

        user_data = {
            "id": str(uuid.uuid4()),
            "username": form.get("username"),
            "password": form.get("password"),
            "role": form.get("role"),
        }
        user = Users(**user_data)
        db.session.add(user)
        db.session.commit()
        return make_response('Usuario guardado con exito.', 201)
    except Exception as e:
        return make_response("Error generando tu usuario, verifica la informacion", 400)


@blueprint.route('', methods=['PATCH'])
@login_required
def edit():
    users_id = request.get_json()['users_id']
    try:
        data = request.get_json()
        if data["password"] != data["confirm_password"]:
            return make_response("Contraseñas no coinciden", 400)
        users = Users.find_by_id(users_id)
        users.password = hash_pass(data["password"])
        users.save_to_db()

        return make_response('usuario actualizado con exito.', 201)
    except Exception as e:
        return make_response(e.args, 400)