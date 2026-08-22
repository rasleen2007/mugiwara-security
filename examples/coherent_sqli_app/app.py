"""Intentionally vulnerable demo target for Mugiwara Security judge demos.

DEMO COLLATERAL - DO NOT DEPLOY.
This tiny Flask application deliberately contains a classic SQL injection
so that Mugiwara Security can demonstrate a genuine VERIFIED-by-PoC result
against a real Docker sandbox container. Run it only inside an isolated
sandbox and only against targets you are explicitly authorized to test.

Mugiwara demo:

    uv run mugiwara scan examples/coherent_sqli_app --sandbox docker

Expected outcome for this application: the ``sql_injection`` finding at
``app.py`` is confirmed by a synthesized, safety-screened Proof-of-Concept
probe executed inside the ephemeral sandbox container and is reported as
VERIFIED with attached evidence (canary token, HTTP trace, execution logs).
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)
_connection = sqlite3.connect("users.db")
_connection.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
_connection.execute("INSERT INTO users VALUES (1, 'demo-user')")
_connection.commit()
_connection.close()


@app.route("/users")
def list_users():
    """List users matching an unfiltered name parameter (vulnerable on purpose)."""
    username = request.args.get("username", "")
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    rows = str(cursor.fetchall())
    connection.close()
    return rows


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
