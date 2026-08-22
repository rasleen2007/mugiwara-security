"""HTTP route handlers with injectable SQL used by agent tests."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)

_CONNECTION = sqlite3.connect("users.db")


@app.route("/users")
def list_users():
    """List users matching an unfiltered name parameter."""
    username = request.args.get("username", "")
    cursor = _CONNECTION.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return str(cursor.fetchall())


@app.route("/ping", methods=["POST"])
def ping():
    """Health probe endpoint accepting POST requests."""
    return "pong"
