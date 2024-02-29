import os


class BaseConfig():
    API_PREFIX = '/api'
    TESTING = False
    DEBUG = False

    # SALT
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # MYSQL
    mysql_db_username = os.environ.get('DB_USERNAME')
    mysql_db_password = os.environ.get('USER_DB_PASSWORD')
    mysql_db_name = os.environ.get('DB_NAME')
    mysql_db_hostname = os.environ.get('DB_HOSTNAME')


class DevConfig(BaseConfig):
    FLASK_ENV = 'development'
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_ADDR}/{DB_NAME}".format(
        DB_USER=BaseConfig.mysql_db_username,
        DB_PASS=BaseConfig.mysql_db_password,
        DB_ADDR=BaseConfig.mysql_db_hostname,
        DB_NAME=BaseConfig.mysql_db_name)
    CELERY_BROKER = 'pyamqp://rabbit_user:rabbit_password@broker-rabbitmq//'
    CELERY_RESULT_BACKEND = 'rpc://rabbit_user:rabbit_password@broker-rabbitmq//'


class ProductionConfig(BaseConfig):
    FLASK_ENV = 'production'
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_ADDR}/{DB_NAME}".format(
        DB_USER=BaseConfig.mysql_db_username,
        DB_PASS=BaseConfig.mysql_db_password,
        DB_ADDR=BaseConfig.mysql_db_hostname,
        DB_NAME=BaseConfig.mysql_db_name)
    CELERY_BROKER = 'pyamqp://rabbit_user:rabbit_password@broker-rabbitmq//'
    CELERY_RESULT_BACKEND = 'rpc://rabbit_user:rabbit_password@broker-rabbitmq//'
