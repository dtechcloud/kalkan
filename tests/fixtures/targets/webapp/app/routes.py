# Sample Flask routes for kalkan run engine tests. Not a real application.
import sqlite3

from flask import Flask, request

app = Flask(__name__)
DB_PATH = "app.db"


@app.route("/users")
def users():
    user_id = request.args.get("id")
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT name FROM users WHERE id = ?", (user_id,)).fetchone()
    return {"name": row[0] if row else None}
