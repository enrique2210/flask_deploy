import logging
import os

from flask_login import LoginManager

import config
from api import api

from flask import Flask

from models.users import Users
from routes.home import blueprint as home_bp
from routes.authentication import blueprint as authentication_bp
from routes.users import blueprint as user_bp
from models import db
from flask_migrate import Migrate
migrate = Migrate()
logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s]: {} %(levelname)s %(message)s'.format(os.getpid()),
                    datefmt='%Y-%m-%d %H:%M:%S',
                    handlers=[logging.StreamHandler()])

logger = logging.getLogger()
login_manager = LoginManager()

def create_app():
    logger.info(f'Starting app in {config.APP_ENV} environment')
    app = Flask(__name__, template_folder='templates')
    app.config.from_object('config')
    api.init_app(app)

    # initialize SQLAlchemy
    db.init_app(app)
    # initialize Migrates
    migrate.init_app(app, db)
    # initialize Login Manager
    login_manager.init_app(app)

    app.register_blueprint(home_bp)
    app.register_blueprint(authentication_bp)
    app.register_blueprint(user_bp)

    return app

@login_manager.user_loader
def user_loader(id):
    return Users.query.filter_by(id=id).first()


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = Users.query.filter_by(username=username).first()
    return user if user else None


if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0', debug=True)
