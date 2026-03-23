"""WTForms form definitions for PolarisGRC.

Forms
-----
* :class:`RegistrationForm`   — New user sign-up with duplicate-username/email guards.
* :class:`LoginForm`          — Existing user login accepting username or email.
* :class:`ChangePasswordForm` — Authenticated user password change.
"""

from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError

from backend.models import User


class RegistrationForm(FlaskForm):
    """Form for creating a new PolarisGRC user account.

    Validates that the submitted username and email are not already taken
    (via custom ``validate_*`` methods that Flask-WTF calls automatically),
    and that both password fields match.

    Fields:
        username:  Unique login name (3–80 characters).
        email:     Valid, unique email address.
        password:  Plain-text password (min 8 characters; stored as bcrypt hash).
        password2: Confirmation field — must equal ``password``.
        submit:    Form submission button.
    """

    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=80)],
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email()],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters"),
        ],
    )
    password2 = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match"),
        ],
    )
    submit = SubmitField("Register")

    # ── Custom uniqueness validators ───────────────────────────────────────────

    def validate_username(self, username) -> None:
        """Raise :class:`ValidationError` if *username* is already registered.

        Flask-WTF calls this automatically as part of ``validate_on_submit()``
        because the method follows the ``validate_<fieldname>`` naming convention.

        Args:
            username: The ``username`` field object whose ``.data`` attribute
                holds the submitted value.

        Raises:
            ValidationError: If a :class:`~backend.models.User` with the same
                username already exists in the database.
        """
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError("Username already taken.")

    def validate_email(self, email) -> None:
        """Raise :class:`ValidationError` if *email* is already registered.

        Args:
            email: The ``email`` field object whose ``.data`` attribute holds
                the submitted value.

        Raises:
            ValidationError: If a :class:`~backend.models.User` with the same
                email address already exists in the database.
        """
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError("Email already registered.")


class LoginForm(FlaskForm):
    """Form for authenticating an existing PolarisGRC user.

    The ``username`` field accepts either a username or an email address so
    users are not required to remember which identifier they registered with.

    Fields:
        username:    Username or email address supplied by the user.
        password:    Plain-text password to verify against the stored bcrypt hash.
        remember_me: If checked, Flask-Login extends the session cookie lifetime.
        submit:      Form submission button.
    """

    username = StringField(
        "Username or Email",
        validators=[DataRequired()],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired()],
    )
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Log In")


class ChangePasswordForm(FlaskForm):
    """Form for changing the password of the currently logged-in user.

    The current password must be supplied and verified before the new password
    is accepted, preventing an unattended authenticated session from being used
    to lock out the real owner.

    Fields:
        current_password: Plain-text current password for identity verification.
        new_password:     Replacement password (min 8 characters).
        new_password2:    Confirmation — must equal ``new_password``.
        submit:           Form submission button.
    """

    current_password = PasswordField(
        "Current Password",
        validators=[DataRequired()],
    )
    new_password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters"),
        ],
    )
    new_password2 = PasswordField(
        "Confirm New Password",
        validators=[
            DataRequired(),
            EqualTo("new_password", message="Passwords must match"),
        ],
    )
    submit = SubmitField("Change Password")
