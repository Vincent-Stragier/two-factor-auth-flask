"""Configuration file."""

import os

SECRET_KEY = "secret_key"
SQLALCHEMY_DATABASE_URI = os.environ.get(
    "DATABASE_URL", "sqlite:///local_database.sqlite"
)
SQLALCHEMY_TRACK_MODIFICATIONS = False
