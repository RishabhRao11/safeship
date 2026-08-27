"""
safe_but_flagged.py -- Step 6, Test 2: the false-positive fixture.

Everything in this file is SAFE. It exists to prove the opposite point from
vulnerable.py: a static analyser reports things that are not bugs, and a tool that
cannot tell the difference wastes its user's time until they stop reading it.

Semgrep flags this file. It is wrong to. Whether the LLM layer correctly says so is
the clearest single demonstration of what the LLM adds over Semgrep alone -- if it
just agrees with the scanner, the second half of VibeSec is decorative.
"""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


# ---------------------------------------------------------------------------
# SAFE #1 -- int() cast before interpolation
# ---------------------------------------------------------------------------
# Semgrep sees an f-string containing a variable inside a SQL query and fires.
# It is pattern-matching the SHAPE of SQL injection.
#
# But int() either returns an integer or raises ValueError. There is no input that
# makes it return a string containing a quote. By the time user_id reaches the
# f-string it cannot carry SQL syntax, so there is nothing to inject. The dangerous
# shape is present; the danger is not.
@app.route("/user")
def get_user():
    user_id = int(request.args.get("id"))
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()


# ---------------------------------------------------------------------------
# SAFE #2 -- allowlist before interpolation
# ---------------------------------------------------------------------------
# Column names cannot be parameterised with ? placeholders -- the driver only
# parameterises values. So string interpolation is the ONLY way to write this, and
# an allowlist is the correct defence: sort_column is guaranteed to be one of three
# literals the programmer chose. Nothing the user sends can reach the query.
ALLOWED_SORT_COLUMNS = {"name", "created_at", "email"}


@app.route("/users/sorted")
def sorted_users():
    sort_column = request.args.get("sort", "name")
    if sort_column not in ALLOWED_SORT_COLUMNS:
        return {"error": "invalid sort column"}, 400

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users ORDER BY {sort_column}"
    cursor.execute(query)
    return cursor.fetchall()


# ---------------------------------------------------------------------------
# SAFE #3 -- subprocess with a list and no shell
# ---------------------------------------------------------------------------
# A command-injection rule may fire on "subprocess called with a variable." But the
# argument is a LIST and shell=False (the default), so no shell ever parses it. A
# hostname of "example.com; rm -rf /" is passed to ping as one literal argument --
# the semicolon is just a character in a string that ping will reject as a bad
# hostname. There is no shell to inject into.
import subprocess


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host.replace(".", "").replace("-", "").isalnum():
        return {"error": "invalid hostname"}, 400
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True)
    return {"output": result.stdout.decode()}
