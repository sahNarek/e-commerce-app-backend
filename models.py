from app import db
from sqlalchemy import UniqueConstraint


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True)
    password = db.Column(db.String(), nullable=False)
    is_admin = db.Column(db.Boolean(), default=False)
    UniqueConstraint(email, name="unique_uuid"),

    def __init__(self, name, email, password, is_admin):
        self.name = name
        self.email = email
        self.password = password
        self.is_admin = is_admin

    def __repr__(self):
        return f"<User {self.name}>"

    def to_dict(self):
        return {
            "name": self.name,
            "email": self.email,
            "isAdmin": self.is_admin
        }