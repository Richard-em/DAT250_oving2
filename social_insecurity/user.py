from flask_login import UserMixin
from social_insecurity import sqlite

## User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    @staticmethod
    def get_by_username(username: str):
        query = "SELECT * FROM Users WHERE username = ?;"
        row = sqlite.query(query, username, one=True)
        if row:
            return User(row["id"], row["username"], row["password"])
        return None
