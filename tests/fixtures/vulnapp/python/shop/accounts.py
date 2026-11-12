"""Account and order API of the vulnapp shop service."""

import hashlib
import os

import jwt
from flask import Blueprint, abort, jsonify, request

from .auth import admin_required, current_user_id, login_required
from .storage import get_db, get_mongo

accounts = Blueprint("accounts", __name__, url_prefix="/api")

JWT_KEY = os.environ.get("VULNAPP_JWT_KEY", "")
PUBLIC_FIELDS = {"username": 1, "_id": 0}


def hash_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def hash_password_v2(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000).hex()


@accounts.route("/register", methods=["POST"])
def register():
    db = get_db()
    digest = hash_password(request.form["password"])
    db.execute("INSERT INTO users (name, pw) VALUES (?, ?)", (request.form["name"], digest))
    return jsonify({"created": True})


@accounts.route("/password", methods=["POST"])
def change_password():
    salt = os.urandom(16)
    digest = hash_password_v2(request.form["password"], salt)
    get_db().execute("UPDATE users SET pw = ?, salt = ? WHERE id = ?", (digest, salt, 1))
    return jsonify({"changed": True})


@accounts.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    row = get_db().execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None:
        abort(404)
    return jsonify(dict(row))


@accounts.route("/orders/<int:order_id>/summary")
@login_required
def get_order_summary(order_id):
    owner = current_user_id()
    sql = "SELECT * FROM orders WHERE id = ? AND owner_id = ?"
    row = get_db().execute(sql, (order_id, owner)).fetchone()
    if row is None:
        abort(404)
    return jsonify(dict(row))


@accounts.route("/admin/users/<int:user_id>", methods=["DELETE"])
@login_required
def delete_user(user_id):
    get_db().execute("DELETE FROM users WHERE id = ?", (user_id,))
    return jsonify({"deleted": user_id})


@accounts.route("/admin/users/<int:user_id>/lock", methods=["POST"])
@admin_required
def lock_user(user_id):
    get_db().execute("UPDATE users SET locked = 1 WHERE id = ?", (user_id,))
    return jsonify({"locked": user_id})


@accounts.route("/profile")
def profile():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False})
    return jsonify({"user": claims.get("sub")})


@accounts.route("/preferences")
def preferences():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, JWT_KEY, algorithms=["HS256"])
    return jsonify({"user": claims.get("sub")})


@accounts.route("/users/find", methods=["POST"])
@login_required
def find_users():
    users = get_mongo().users.find(request.get_json(), PUBLIC_FIELDS)
    return jsonify([user["username"] for user in users])


@accounts.route("/users/lookup", methods=["POST"])
@login_required
def lookup_users():
    body = request.get_json()
    users = get_mongo().users.find({"username": str(body.get("username", ""))}, PUBLIC_FIELDS)
    return jsonify([user["username"] for user in users])
