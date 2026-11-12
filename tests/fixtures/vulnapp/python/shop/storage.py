"""Database helpers for the vulnapp shop service."""

import os
import sqlite3

from pymongo import MongoClient

DB_PATH = os.environ.get("VULNAPP_DB", "vulnapp.sqlite3")
MONGO_URL = os.environ.get("VULNAPP_MONGO_URL", "mongodb://localhost:27017")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_mongo():
    return MongoClient(MONGO_URL)["vulnapp"]
