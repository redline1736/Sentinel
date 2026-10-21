# vulnerable_app.py
from flask import Flask, request, session, make_response
import sqlite3, os

app = Flask(__name__)
app.secret_key = "super-secret-key"   # hardcoded, but not the CSRF issue here

DB = "bank.db"

def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, balance INTEGER)")
    con.execute("CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, user TEXT)")
    con.execute("INSERT OR IGNORE INTO users VALUES ('alice', 1000)")
    con.execute("INSERT OR IGNORE INTO users VALUES ('bob', 1000)")
    con.commit()
    con.close()

init_db()

def current_user():
    sid = request.cookies.get("session")
    if not sid:
        return None
    con = sqlite3.connect(DB)
    row = con.execute("SELECT user FROM sessions WHERE sid=?", (sid,)).fetchone()
    con.close()
    return row[0] if row else None

@app.route("/login")
def login():
    """Trivial login for demo: /login?user=alice"""
    user = request.args.get("user", "alice")
    sid = os.urandom(16).hex()
    con = sqlite3.connect(DB)
    con.execute("INSERT INTO sessions VALUES (?, ?)", (sid, user))
    con.commit()
    con.close()
    resp = make_response(f"Logged in as {user}")
    # ⚠️ No SameSite, no Secure, no HttpOnly — classic vulnerable cookie
    resp.set_cookie("session", sid)
    return resp

# ============================================================
# VULNERABLE ENDPOINT — the one we care about
# ============================================================
@app.route("/transfer", methods=["POST"])
def transfer():
    user = current_user()
    if not user:
        return "Not logged in", 401

    to     = request.form.get("to")
    amount = request.form.get("amount")

    con = sqlite3.connect(DB)
    con.execute("UPDATE users SET balance = balance - ? WHERE name = ?", (amount, user))
    con.execute("UPDATE users SET balance = balance + ? WHERE name = ?", (amount, to))
    con.commit()
    con.close()
    return f"Transferred {amount} from {user} to {to}"

@app.route("/balance")
def balance():
    user = current_user()
    if not user:
        return "Not logged in", 401
    con = sqlite3.connect(DB)
    bal = con.execute("SELECT balance FROM users WHERE name=?", (user,)).fetchone()[0]
    con.close()
    return f"{user}: {bal}"

if __name__ == "__main__":
    app.run(port=5000, debug=True)