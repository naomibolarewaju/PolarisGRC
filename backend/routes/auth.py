"""Authentication blueprint for PolarisGRC.

Routes
------
* ``GET/POST /register`` — New user registration.
* ``GET/POST /login``    — Existing user login.
* ``GET      /logout``   — Session teardown.
* ``GET/POST /profile``  — Authenticated user profile and password change.
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from urllib.parse import urlsplit

from backend import db
from backend.forms import ChangePasswordForm, LoginForm, RegistrationForm
from backend.models import Scan, User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Display the registration form and create a new user on valid submission.

    **GET** — Renders the empty ``register.html`` form.

    **POST** — Validates the submitted :class:`~backend.forms.RegistrationForm`.
    On success:

    1. Creates a :class:`~backend.models.User` instance with the supplied
       username and email.
    2. Hashes the password via :meth:`~backend.models.User.set_password` (bcrypt).
    3. Persists the record with ``db.session.add`` / ``db.session.commit``.
    4. Flashes a success message and redirects to the login page.

    On failure (validation errors or duplicate username/email), the form is
    re-rendered with inline error messages.

    Already-authenticated users are redirected to the dashboard immediately
    without seeing the form.

    Returns:
        A :class:`flask.Response` — either a redirect or a rendered template.
    """
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Display the login form and authenticate the user on valid submission.

    **GET** — Renders the empty ``login.html`` form.  Already-authenticated
    users are redirected to ``dashboard.index`` immediately.

    **POST** — Validates the submitted :class:`~backend.forms.LoginForm`.

    * Looks up the user by username **or** email (a single OR-filtered query).
    * If the user is not found or the password does not match the stored bcrypt
      hash, flashes an error and redirects back to this page (prevents leaking
      whether the identifier or the password was wrong).
    * On success calls :func:`flask_login.login_user`, which writes a signed
      session cookie (extended lifetime when *remember_me* is checked).
    * Respects the ``next`` query-string parameter set by Flask-Login when it
      redirected an unauthenticated request — but only if the URL is relative
      (i.e. ``url_parse(next).netloc`` is empty) to prevent open-redirect
      attacks.

    Args:
        None — reads from :data:`flask.request` directly.

    Returns:
        A :class:`flask.Response` — a redirect on success/already-authenticated,
        or the rendered ``login.html`` template on GET / failed validation.
    """
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()

    if form.validate_on_submit():
        identifier = form.username.data
        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        if user is None or not user.check_password(form.password.data):
            flash("Invalid username or password.", "error")
            return redirect(url_for("auth.login"))

        login_user(user, remember=form.remember_me.data)
        flash(f"Welcome back, {user.username}!", "success")

        next_page = request.args.get("next")
        if next_page and not urlsplit(next_page).netloc:
            return redirect(next_page)
        return redirect(url_for("dashboard.index"))

    return render_template("login.html", form=form)


@auth_bp.route("/logout")
def logout():
    """Log the current user out and redirect to the login page."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Display the user profile page and handle password changes.

    **GET** — Renders ``profile.html`` with account information, scan statistics,
    and an empty :class:`~backend.forms.ChangePasswordForm`.

    **POST** — Validates the submitted form:

    1. Verifies the supplied *current_password* against the stored bcrypt hash.
       If wrong, flashes an error and redirects back to this page (avoids
       re-rendering the form with the bad password still in the field).
    2. If correct, hashes the new password with
       :meth:`~backend.models.User.set_password` and commits the change.
    3. Flashes a success message and redirects to ``auth.profile``.

    Template context:
        form:        :class:`~backend.forms.ChangePasswordForm` instance.
        total_scans: Total number of scans belonging to the current user.
        latest_scan: Most recent :class:`~backend.models.Scan`, or ``None``.

    Returns:
        A :class:`flask.Response` — redirect on success/wrong-password,
        or the rendered ``profile.html`` template.
    """
    form = ChangePasswordForm()

    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    latest_scan = (
        Scan.query
        .filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .first()
    )

    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "error")
            return redirect(url_for("auth.profile"))

        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash("Password changed successfully.", "success")
        return redirect(url_for("auth.profile"))

    return render_template(
        "profile.html",
        form=form,
        total_scans=total_scans,
        latest_scan=latest_scan,
    )
