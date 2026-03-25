"""Flask application factory for PolarisGRC.

``create_app()`` builds and configures a Flask instance using the factory
pattern, which allows different configurations to be injected for development,
testing, and production without module-level side effects.

Extensions initialised here
---------------------------
* **SQLAlchemy** (``db``) — ORM and database session management.
* **LoginManager** — session-based user authentication via Flask-Login.
  Redirects unauthenticated requests to ``auth.login`` and reloads the active
  user from the database on every request via the ``user_loader`` callback.
* **CSRFProtect** (``csrf``) — validates the ``_csrf_token`` field (or
  ``X-CSRFToken`` header) on every state-changing request.  JSON API routes
  that are designed for programmatic agent access are opted out individually
  with ``@csrf.exempt``.
"""

from datetime import timedelta

from flask import Flask, flash, jsonify, redirect, request, url_for
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

# Module-level extension instances.  Initialised with the app inside
# create_app() so they can be imported elsewhere without triggering the
# application context.
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()


def create_app(config_class=None):
    """Create and configure a Flask application instance.

    Args:
        config_class: A configuration class (or object) whose attributes are
            loaded via ``app.config.from_object()``.  Defaults to
            ``backend.config.Config`` when not supplied.

    Returns:
        A fully configured :class:`flask.Flask` application with all
        extensions initialised and blueprints registered.

    Example::

        from backend import create_app
        app = create_app()
        app.run()
    """
    app = Flask(__name__)

    if config_class is None:
        from backend.config import Config
        config_class = Config

    app.config.from_object(config_class)

    # ── Secure session-cookie settings ────────────────────────────────────────
    # Prevents the session cookie from being sent over plain HTTP.
    # Set to False in development if you are not using HTTPS on localhost.
    app.config["SESSION_COOKIE_SECURE"] = True

    # Blocks JavaScript from reading the session cookie, mitigating XSS theft.
    app.config["SESSION_COOKIE_HTTPONLY"] = True

    # 'Lax' sends the cookie on same-site requests and safe cross-site
    # navigations (e.g. clicking a link), but not on cross-site POST/AJAX.
    # This is a defence-in-depth layer on top of CSRF tokens.
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # How long a "remember me" session lasts (also the max cookie lifetime).
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

    # ── Database ───────────────────────────────────────────────────────────────
    db.init_app(app)
    migrate.init_app(app, db)

    # ── CSRF protection ────────────────────────────────────────────────────────
    # Automatically validates _csrf_token on POST/PUT/PATCH/DELETE for every
    # view that is not decorated with @csrf.exempt.  Flask-WTF's FlaskForm
    # embeds the token via {{ form.hidden_tag() }}.
    csrf.init_app(app)

    # ── Authentication ─────────────────────────────────────────────────────────
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "info"
    login_manager.init_app(app)

    # ── Blueprints ─────────────────────────────────────────────────────────────
    from backend.routes.api import api_bp
    from backend.routes.auth import auth_bp
    from backend.routes.dashboard import dashboard_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    return app


@login_manager.unauthorized_handler
def unauthorized():
    """Handle unauthenticated requests.

    API endpoints (``/api/*``) receive a JSON 401 response so that API clients
    get machine-readable errors rather than an HTML login-page redirect.
    All other routes flash the configured login message and redirect to
    ``auth.login``, preserving the ``next`` parameter so the user is returned
    to the page they were trying to reach after logging in.
    """
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "Authentication required"}), 401
    if login_manager.login_message:
        flash(login_manager.login_message, login_manager.login_message_category)
    return redirect(url_for("auth.login", next=request.path))


@login_manager.user_loader
def load_user(user_id: str):
    """Reload a ``User`` from the database for every authenticated request.

    Flask-Login calls this callback with the value stored in the user's
    session (the user's primary key as a string).  Returning ``None`` causes
    Flask-Login to treat the session as unauthenticated.

    Args:
        user_id: The user's primary key serialised as a string by Flask-Login.

    Returns:
        The :class:`backend.models.User` instance whose ``id`` matches
        ``user_id``, or ``None`` if no such user exists.
    """
    try:
        from backend.models import User
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None
