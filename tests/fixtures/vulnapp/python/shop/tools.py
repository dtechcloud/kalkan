"""Operator tools of the vulnapp shop service."""

import ast
import base64
import json
import pickle
import subprocess

import requests
import yaml
from flask import Blueprint, abort, jsonify, request
from lxml import etree

tools = Blueprint("tools", __name__, url_prefix="/tools")

STATUS_FEEDS = {
    "payments": "https://status.payments.vulnapp.internal/feed.json",
    "shipping": "https://status.shipping.vulnapp.internal/feed.json",
}


@tools.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout


@tools.route("/ping/v2")
def ping_v2():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run(["ping", "-c", "1", "--", host], capture_output=True, text=True)
    return result.stdout


@tools.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    resp = requests.get(url, timeout=5)
    return resp.text


@tools.route("/status/<name>")
def status(name):
    feed_url = STATUS_FEEDS.get(name)
    if feed_url is None:
        abort(404)
    resp = requests.get(feed_url, timeout=5)
    return resp.text


@tools.route("/calc")
def calc():
    expression = request.args.get("expr", "0")
    return str(eval(expression))


@tools.route("/calc/literal")
def calc_literal():
    expression = request.args.get("expr", "0")
    return str(ast.literal_eval(expression))


@tools.route("/import/xml", methods=["POST"])
def import_xml():
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    doc = etree.fromstring(request.data, parser)
    return jsonify({"root": doc.tag})


@tools.route("/import/xml-strict", methods=["POST"])
def import_xml_strict():
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    doc = etree.fromstring(request.data, parser)
    return jsonify({"root": doc.tag})


@tools.route("/import/config", methods=["POST"])
def import_config():
    config = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(config)


@tools.route("/import/settings", methods=["POST"])
def import_settings():
    settings = yaml.load(request.data, Loader=yaml.SafeLoader)
    return jsonify(settings)


@tools.route("/session/restore", methods=["POST"])
def restore_session():
    state = pickle.loads(base64.b64decode(request.form["state"]))
    return jsonify(state)


@tools.route("/session/load", methods=["POST"])
def load_session():
    state = json.loads(base64.b64decode(request.form["state"]))
    return jsonify(state)
