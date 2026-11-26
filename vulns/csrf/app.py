
from flask import (
    Flask, request, session,
    redirect, render_template, jsonify
)

app = Flask(__name__)

app.secret_key = "insecure-lab-secret"

# Intentionally insecure cookie configuration for
# demonstrating cross-site requests in a local lab.
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True

# Fake account data
accounts = {
    "alice": {
        "password": "password123",
        "balance": 1000
    },
    "bob": {
        "password": "password123",
        "balance": 500
    }
}


@app.route("/")
def index():
    if "username" not in session:
        return redirect("/login")

    return redirect("/dashboard")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        account = accounts.get(username)

        if account and account["password"] == password:
            session["username"] = username
            return redirect("/dashboard")

        return "Invalid credentials", 401

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    username = session.get("username")

    if not username:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=username,
        balance=accounts[username]["balance"]
    )


# INTENTIONALLY VULNERABLE ENDPOINT
@app.route("/transfer", methods=["POST"])
def transfer():
    username = session.get("username")

    if not username:
        return "Unauthorized", 401

    recipient = request.form.get("recipient")
    amount = request.form.get("amount", type=int)

    if recipient not in accounts:
        return "Unknown recipient", 400

    if amount is None or amount <= 0:
        return "Invalid amount", 400

    if accounts[username]["balance"] < amount:
        return "Insufficient balance", 400

    # No CSRF token validation!
    accounts[username]["balance"] -= amount
    accounts[recipient]["balance"] += amount

    return jsonify({
        "status": "success",
        "from": username,
        "to": recipient,
        "amount": amount,
        "remaining_balance": accounts[username]["balance"]
    })


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
        ssl_context="adhoc"
    )
