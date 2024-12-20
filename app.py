"""Flask app."""

import base64
import os
from io import BytesIO

import onetimepass
import pyqrcode
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    session,
    url_for,
)
from flask_bootstrap import Bootstrap
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, SubmitField, EmailField
from wtforms.validators import EqualTo, Length, DataRequired, Email

# Create application instance
app = Flask(__name__)
app.config.from_object("config")

# Initialize extensions
bootstrap = Bootstrap(app)
local_database = SQLAlchemy(app)
login_manager = LoginManager(app)


class User(UserMixin, local_database.Model):
    """User model."""

    __tablename__ = "users"
    user_id = local_database.Column(local_database.Integer, primary_key=True)
    username = local_database.Column(local_database.String(128), index=True)
    first_name = local_database.Column(local_database.String(128), index=True)
    last_name = local_database.Column(local_database.String(128), index=True)
    email = local_database.Column(local_database.String(128), index=True)
    verified_email = local_database.Column(local_database.Boolean())
    password_hash = local_database.Column(local_database.String(128))
    otp_secret = local_database.Column(local_database.String(16))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.otp_secret is None:
            # Generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode("utf-8")

    @property
    def password(self):
        """Password property."""
        raise AttributeError("'password' is not a readable attribute")

    @password.setter
    def password(self, password: str) -> None:
        """Password setter.

        Args:
            password (str): the user's password.
        """
        self.password_hash = generate_password_hash(password)

    def get_id(self):
        return self.user_id

    def verify_password(self, password) -> bool:
        """Verify user's password.

        Args:
            password (str): the potential password.

        Returns:
            bool: return True is the password is correct. False otherwise.
        """
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self) -> str:
        """Generate the user's one time token URI.

        Returns:
            str: the one time token URI.
        """
        return (
            f"otpauth://totp/2FA-Demo:{self.username}?"
            f"secret={self.otp_secret}&issuer=2FA-Demo"
        )

    def verify_totp(self, token: str) -> bool:
        """Verify the user's one time token.

        Args:
            token (str): the token to verify.

        Returns:
            bool: return True if the token is valid. False otherwise.
        """
        return onetimepass.valid_totp(token, self.otp_secret)


@login_manager.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    """Registration form."""

    username = StringField(
        "Username",
        validators=[DataRequired(), Length(1, 128)],
    )

    first_name = StringField(
        "First name",
        validators=[DataRequired(), Length(1, 128)],
    )

    last_name = StringField(
        "Last name",
        validators=[DataRequired(), Length(1, 128)],
    )

    email = EmailField(
        "Email",
        validators=[DataRequired(), Length(1, 128), Email()],
    )

    password = PasswordField(
        "Password",
        validators=[DataRequired()],
    )

    password_again = PasswordField(
        "Password again",
        validators=[DataRequired(), EqualTo("password")],
    )

    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    """Login form."""

    username = StringField(
        "Username",
        validators=[DataRequired(), Length(1, 64)],
    )

    password = PasswordField(
        "Password",
        validators=[DataRequired()],
    )

    token = StringField(
        "Token",
        validators=[DataRequired(), Length(6, 6)],
    )

    submit = SubmitField("Login")


@app.route("/")
def index():
    """Index route."""
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for("index"))

    form = RegisterForm()

    if form.validate_on_submit():

        user = User.query.filter_by(username=form.username.data).first()

        if user is not None:
            flash("Username already exists.")
            return redirect(url_for("register"))

        # add new user to the database
        user = User(
            username=form.username.data,
            password=form.password.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            verified_email=False,
        )

        local_database.session.add(user)
        local_database.session.commit()

        # redirect to the two-factor auth page, passing username in session
        session["username"] = user.username
        return redirect(url_for("two_factor_setup"))

    return render_template("register.html", form=form)


@app.route("/twofactor")
def two_factor_setup():
    """Two-factor route."""
    if "username" not in session:
        return redirect(url_for("index"))

    user = User.query.filter_by(username=session["username"]).first()

    if user is None:
        return redirect(url_for("index"))

    # Since this page contains the sensitive qrcode,
    # make sure the browser does not cache it.
    return (
        render_template("two-factor-setup.html"),
        200,
        {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.route("/qrcode")
def qrcode() -> tuple:
    """QR code route."""
    if "username" not in session:
        abort(404)

    user = User.query.filter_by(username=session["username"]).first()
    if user is None:
        abort(404)

    # For added security, remove username from session
    del session["username"]

    # Render qrcode for FreeTOTP
    url_qr_code = pyqrcode.create(user.get_totp_uri())

    with BytesIO() as stream:
        url_qr_code.svg(stream, scale=3)

        return (
            stream.getvalue(),
            200,
            {
                "Content-Type": "image/svg+xml",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login route."""
    if current_user.is_authenticated:
        # If user is logged in we get out of here
        return redirect(url_for("index"))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if (
            user is None
            or not user.verify_password(form.password.data)
            or not user.verify_totp(form.token.data)
        ):
            flash("Invalid username, password or token.")
            return redirect(url_for("login"))

        # Log user in
        login_user(user)
        flash("You are now logged in!")
        return redirect(url_for("index"))

    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    """User logout route."""
    logout_user()
    return redirect(url_for("index"))


# Create database tables if they don't exist yet
with app.app_context():
    local_database.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
