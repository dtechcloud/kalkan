from flask import Flask, request

from app import db
from app.helpers import http_get, login_required, require_authorization, settings_update

app = Flask(__name__)


@app.get("/users")
@login_required
def get_user():
    user_id = request.args.get("id")
    return db.find_user(user_id)


@app.get("/fetch")
def fetch():
    url = request.args.get("url")
    return http_get(url)


@app.get("/files")
def read_file():
    name = request.args.get("name")
    return open("/srv/files/" + name).read()


@app.get("/admin")
def admin():
    require_authorization(request)
    return settings_update(request)
