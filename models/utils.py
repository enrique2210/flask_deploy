import os
import hashlib
import binascii
from functools import wraps

import flask_login
from flask import render_template

from models.constants import Role


def hash_pass(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash)  # return bytes


def verify_pass(provided_password, stored_password):
    """Verify a stored password against one provided by user"""
    stored_password = stored_password.decode('ascii')
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password


def is_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if hasattr(flask_login.current_user, "id") and \
                flask_login.current_user.role == Role.ADMIN:
            return func(*args, **kwargs)
        return render_template('home/page-401.html'), 401

    return wrapper
