"""Document downloads of the vulnapp shop service."""

import os

from flask import Blueprint, abort, request, send_file
from werkzeug.security import safe_join
from werkzeug.utils import secure_filename

files = Blueprint("files", __name__, url_prefix="/files")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INVOICE_DIR = os.path.join(BASE_DIR, "data", "invoices")
NOTES_DIR = os.path.join(BASE_DIR, "data", "notes")


@files.route("/invoice")
def invoice():
    filename = request.args.get("name", "")
    return send_file(os.path.join(INVOICE_DIR, filename))


@files.route("/receipt")
def receipt():
    safe_name = secure_filename(request.args.get("name", ""))
    return send_file(os.path.join(INVOICE_DIR, safe_name))


@files.route("/note")
def note():
    name = request.args.get("name", "")
    with open(os.path.join(NOTES_DIR, name), encoding="utf-8") as handle:
        return handle.read()


@files.route("/memo")
def memo():
    name = request.args.get("name", "")
    path = safe_join(NOTES_DIR, name)
    if path is None:
        abort(404)
    with open(path, encoding="utf-8") as handle:
        return handle.read()
