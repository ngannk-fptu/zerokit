"""
Deliberately vulnerable Flask app — controlled pentest target for ZeroKit E2E tests.

WARNING: This app contains REAL exploitable vulnerabilities by design.
Do NOT deploy to any network accessible outside of local Docker testing.
"""

import os
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test.db")


def init_db():
    """Create tables and seed test data."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    c.execute("DELETE FROM users")
    c.execute("DELETE FROM items")
    c.execute("INSERT INTO users VALUES (1, 'alice', 'alice@example.com')")
    c.execute("INSERT INTO users VALUES (2, 'bob', 'bob@example.com')")
    c.execute("INSERT INTO items VALUES (1, 'Widget', 9.99)")
    c.execute("INSERT INTO items VALUES (2, 'Gadget', 19.99)")
    conn.commit()
    conn.close()


def init_data_dir():
    """Create BASE_DIR with a harmless welcome file."""
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(os.path.join(BASE_DIR, "welcome.txt"), "w") as f:
        f.write("Welcome to the vuln-flask-app test fixture.\n")


# ── Vuln 1: SQL Injection (CWE-89) ──────────────────────────────────────────
# String concatenation — exploitable via UNION-based extraction.
@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # VULNERABLE: raw string interpolation
    query = f"SELECT * FROM users WHERE name='{name}'"
    try:
        cursor.execute(query)
        rows = [dict(r) for r in cursor.fetchall()]
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500
    conn.close()
    return jsonify(rows)


# ── Vuln 2: Path Traversal (CWE-22) ─────────────────────────────────────────
# Unsanitized os.path.join — exploitable with ../ sequences.
@app.route("/file")
def get_file():
    path = request.args.get("path", "")
    full_path = os.path.join(BASE_DIR, path)
    try:
        with open(full_path, "r") as f:
            content = f.read()
    except FileNotFoundError:
        return jsonify({"error": "file not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return content, 200, {"Content-Type": "text/plain"}


# ── False Positive: Parameterized Query (safe) ──────────────────────────────
# Scanners may flag this, but the parameterized placeholder prevents injection.
@app.route("/item")
def get_item():
    item_id = request.args.get("id", "")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    # SAFE: parameterized query
    cursor.execute("SELECT * FROM items WHERE id=?", (item_id,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/")
def index():
    return jsonify({
        "app": "vuln-flask-app",
        "purpose": "ZeroKit E2E pentest target",
        "routes": ["/user?name=", "/file?path=", "/item?id="],
    })


if __name__ == "__main__":
    init_db()
    init_data_dir()
    app.run(host="0.0.0.0", port=5000, debug=False)
