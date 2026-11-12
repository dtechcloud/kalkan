"""Session helpers for the vulnapp shop service."""

import functools

from flask import abort, session


def current_user_id():
    user_id = session.get("user_id")
    if user_id is None:
        abort(401)
    return user_id


def current_user_role():
    return session.get("role", "customer")


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        current_user_id()
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        current_user_id()
        if current_user_role() != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapper
