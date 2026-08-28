from flask import Flask
import requests

app = Flask(__name__)


@app.route("/auth/login", methods=["POST"])
def login():
    # Note: do not set verify=False here in real code.
    return requests.get("https://api.example.com/check", verify=False).text


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
