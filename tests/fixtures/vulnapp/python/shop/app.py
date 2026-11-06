"""Shop front end of the vulnapp service."""

from flask import Flask, jsonify, make_response, redirect, render_template_string, request, url_for
from flask_cors import cross_origin
from markupsafe import escape

from .accounts import accounts
from .files import files
from .storage import get_db
from .tools import tools

app = Flask(__name__)
app.register_blueprint(accounts)
app.register_blueprint(files)
app.register_blueprint(tools)


@app.route("/")
def landing():
    section = request.args.get("section", "home")
    return render_template_string("<h1>vulnapp</h1><p>{{ section }}</p>", section=section)


@app.route("/products/search")
def search_products():
    name = request.args.get("name", "")
    cur = get_db().cursor()
    cur.execute(f"SELECT id, name, price FROM products WHERE name LIKE '%{name}%'")
    return jsonify([dict(row) for row in cur.fetchall()])


@app.route("/products/filter")
def filter_products():
    name = request.args.get("name", "")
    cur = get_db().cursor()
    cur.execute("SELECT id, name, price FROM products WHERE name LIKE ?", (f"%{name}%",))
    return jsonify([dict(row) for row in cur.fetchall()])


@app.route("/search")
def search_page():
    query = request.args.get("q", "")
    return make_response(f"<h2>Results for {query}</h2>")


@app.route("/search/compact")
def search_page_compact():
    query = request.args.get("q", "")
    return make_response(f"<h2>Results for {escape(query)}</h2>")


@app.route("/greeting")
def greeting():
    name = request.args.get("name", "guest")
    return render_template_string(f"<h1>Hello {name}!</h1>")


@app.route("/welcome")
def welcome():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello {{ name }}!</h1>", name=name)


@app.route("/login/continue")
def continue_login():
    target = request.args.get("next", "/")
    return redirect(target)


@app.route("/logout/continue")
def continue_logout():
    section = request.args.get("section", "home")
    return redirect(url_for("landing", section=section))


@app.route("/api/cart")
@cross_origin(origins="*", supports_credentials=True)
def cart():
    return jsonify({"items": []})


@app.route("/api/wishlist")
@cross_origin(origins=["https://shop.vulnapp.internal"], supports_credentials=True)
def wishlist():
    return jsonify({"items": []})
