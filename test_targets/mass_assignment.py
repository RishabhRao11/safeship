"""User profile management endpoints."""

import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)

DB_PATH = "app.db"


def get_connection():
    """Open a connection to the application database."""
    return sqlite3.connect(DB_PATH)


@app.route("/api/profile", methods=["POST"])
def update_profile():
    """Update a user's profile.

    Accepts a JSON body containing the user id and any profile fields to change.
    Returns the number of fields updated.
    """
    data = request.get_json()

    if not data:
        return jsonify({"error": "no data provided"}), 400

    user_id = data.pop("user_id", None)
    if user_id is None:
        return jsonify({"error": "user_id is required"}), 400

    conn = get_connection()
    cursor = conn.cursor()

    updated = 0
    for field, value in data.items():
        cursor.execute(f"UPDATE users SET {field} = '{value}' WHERE id = {user_id}")
        updated += 1

    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "fields_updated": updated})
