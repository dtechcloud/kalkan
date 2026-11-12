import sqlite3


def find_user(user_id):
    conn = sqlite3.connect("shop.db")
    cur = conn.cursor()
    # look up one user
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cur.fetchall()
