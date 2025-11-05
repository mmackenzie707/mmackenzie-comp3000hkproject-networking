import os
from flask import Blueprint, render_template_string, request, redirect, url_for, session
from flask_login import (
    login_user, logout_user, login_required, LoginManager, UserMixin
)
from .auth import verify_user, init_db, add_user, SECRET_KEY

bp = Blueprint("auth", __name__, url_prefix="")

class User(UserMixin):
    def __init__(self, id):
        self.id=id

login_manager = LoginManager
login_manager.login_view = "auth.login"

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if verify_user(username, password):
            login_user(User(username))
            next_page = request.args.get("next") or "/"
            return redirect(next_page)
        else:
            return render_template_string(LOGIN_PAGE, error="Invalid Credentials")
    return render_template_string(LOGIN_PAGE, error=None)

@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))

LOGIN_PAGE = """<!doctype html>
<html lang="en"><head>
  <meta charset="utf-8"><title>SmartFW Login</title>
  <style>body{font-family:system-ui;background:#141419;color:#e0e0e0;display:flex;height:100vh;align-items:center;justify-content:center}
  form{background:#1e1e24;padding:2rem;border-radius:8px;width:300px}
  input{width:100%;padding:.5rem;margin:.5rem 0;border:none;border-radius:4px}
  button{width:100%;padding:.6rem;border:none;border-radius:4px;background:#1976d2;color:#fff;cursor:pointer}
  .err{color:#f44336;margin-bottom:.5rem}</style>
</head><body>
  <form method="post">
    <h3>SmartFW Login</h3>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <input name="username" placeholder="Username" required>
    <input name="password" type="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
  </form>
</body></html>"""