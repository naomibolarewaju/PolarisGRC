#backend using the Flask application factory pattern
#create_app() builds and configures a new Flask instance, allowing
#different configurations for development, testing, and production.

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app(config_class=None):
    #Create and configure the Flask application.
    app = Flask(__name__)

    if config_class is None:
        from backend.config import Config
        config_class = Config

    app.config.from_object(config_class)

    db.init_app(app)

    from backend.routes.api import api_bp
    from backend.routes.dashboard import dashboard_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)

    return app
