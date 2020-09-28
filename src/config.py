import os


class Config(object):
    DEBUG = False
    SECRET_KEY = '#R%&sdfsd/e4%/344444444'
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ProductionConfig(Config):
    SECRET_KEY = os.environ["SECRET_KEY"]
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.abspath(
        os.getcwd()) + "\\database.db"


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.abspath("./database.db")
