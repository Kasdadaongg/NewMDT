import os

class Config:
    SECRET_KEY = os.urandom(24)  # Random secret key for sessions
    USERS_FILE = 'users.json'  # Path to your JSON database
