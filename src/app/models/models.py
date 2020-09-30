from datetime import datetime
from app import db


class Base(db.Model):
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True)
    date_created = db.Column(db.DateTime(), default=datetime.utcnow())
    date_modified = db.Column(db.DateTime(),
                              default=db.func.current_timestamp(),
                              onupdate=db.func.current_timestamp())


class Users(Base):
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    about_me = db.Column(db.String(280), default="")


class Whitelist(Base):
    ip = db.Column(db.String(50), nullable=False)
