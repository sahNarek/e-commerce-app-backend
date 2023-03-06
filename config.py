import os

class Config():
    DEBUG = True

class Development(Config):
    SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]