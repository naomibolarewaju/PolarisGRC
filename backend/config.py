import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent


class Config:
    #Flask application configuration
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key-change-in-production"
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(BASE_DIR / "polarisgrc.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JSON_SORT_KEYS = False
