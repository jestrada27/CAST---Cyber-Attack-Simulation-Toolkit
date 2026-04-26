import hashlib

from flask import Blueprint, redirect, render_template, request, session, url_for

from castrange.config import state
from castrange.db import get_conn

bp = Blueprint("auth", __name__)


def _md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        next_url = request.args.get("next") or request.form.get("next", "")

        cfg = state.get()
        level = cfg["level"]
        conn = get_conn()
        row = None
        try:
            if level == "easy":
                # V1 SQLi (easy): raw concatenation, no escaping
                pw_md5 = _md5(password)
                sql = (
                    "SELECT id, username, role FROM users "
                    f"WHERE username = '{username}' AND password_md5 = '{pw_md5}'"
                )
                row = conn.execute(sql).fetchone()
            elif level == "medium":
                # V1 SQLi (medium): naive single-quote doubling, still vulnerable
                u = username.replace("'", "''")
                pw_md5 = _md5(password)
                sql = (
                    "SELECT id, username, role FROM users "
                    f"WHERE username = '{u}' AND password_md5 = '{pw_md5}'"
                )
                row = conn.execute(sql).fetchone()
            else:
                # hard: parameterized — V4 weak hash + V5 default creds remain
                pw_md5 = _md5(password)
                row = conn.execute(
                    "SELECT id, username, role FROM users "
                    "WHERE username = ? AND password_md5 = ?",
                    (username, pw_md5),
                ).fetchone()
        except Exception as ex:
            conn.close()
            if level == "easy":
                # V10 verbose error reflection
                return render_template("login.html", error=f"SQL error: {ex}"), 500
            return render_template("login.html", error="Login failed."), 500
        finally:
            try:
                conn.close()
            except Exception:
                pass

        if row:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            # V9 open redirect: next is not validated
            if next_url:
                return redirect(next_url)
            return redirect(url_for("auth.dashboard"))

        error = "Invalid credentials."

    return render_template("login.html", error=error)


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))
    return render_template("dashboard.html",
                           username=session.get("username"),
                           role=session.get("role"))
