import uuid
from datetime import datetime

from flask_login import UserMixin
from sqlalchemy import DateTime, String, Enum, Column

from models import db
from models.constants import Role
from models.utils import hash_pass


class Users(db.Model, UserMixin):
    id = Column(String(36), primary_key=True, default=str(uuid.uuid4()), unique=True)
    username = Column(String(100), index=True, unique=True)
    password = db.Column(db.LargeBinary)
    role = Column(Enum(Role))
    status = Column(String(2), default=1, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            # depending on whether value is an iterable or not, we must
            # unpack it's value (when **kwargs is request.form, some values
            # will be a 1-element list)
            if hasattr(value, '__iter__') and not isinstance(value, str):
                # the ,= unpack of a singleton fails PEP8 (travis flake8 test)
                value = value[0]

            if property == 'password':
                value = hash_pass(value)  # we need bytes here (not plain str)

            setattr(self, property, value)

    def __repr__(self):
        return str(self.username)

    @classmethod
    def get_all(cls):
        users = Users.query.order_by(Users.id.asc()).all()
        return users

    @classmethod
    def find_by_id(cls, user_id):
        user = Users.query.filter_by(id=user_id).first()
        return user

    def save_to_db(self) -> None:
        db.session.add(self)
        db.session.commit()
        