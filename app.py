"""
VulnLab — intentionally vulnerable Flask application.

Every endpoint is a common.txt word so `gobuster dir` finds it.

DO NOT expose this to the internet.
"""

from flask import (
    Flask, request, render_template_string, Response,
    session, jsonify, redirect, url_for
)
import os, re, json, html, secrets, sqlite3
from datetime import datetime
from threading import Lock

app = Flask(__name__)
app.secret_key = os.environ.get("GQ_SECRET_KEY", secrets.token_hex(32))

# ======================================================================
# Layout / shared CSS
# ======================================================================

BASE_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--panel2:#0d1117;--border:#30363d;
--text:#c9d1d9;--muted:#8b949e;--accent:#58a6ff;--danger:#f85149;
--ok:#3fb950;--warn:#d29922;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.wrap{max-width:960px;margin:32px auto;padding:0 20px}
header{border-bottom:1px solid var(--border);padding-bottom:14px;margin-bottom:22px;
display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:10px}
header h1{margin:0;font-size:20px}
header p{margin:0;color:var(--muted);font-size:13px}
nav a{color:var(--accent);margin-left:16px;text-decoration:none;font-size:13px}
nav a:hover{text-decoration:underline}
.card{background:var(--panel);border:1px solid var(--border);border-radius:6px;
padding:20px;margin:14px 0}
.card h2{margin:0 0 12px;font-size:15px;font-weight:600}
.card h3{margin:16px 0 8px;font-size:12px;color:var(--muted);
text-transform:uppercase;letter-spacing:.06em;font-weight:500}
label{display:block;color:var(--muted);font-size:11px;
text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
input[type=text],input[type=password],input[type=email],textarea,select{
width:100%;padding:9px 11px;background:var(--panel2);color:var(--text);
border:1px solid var(--border);border-radius:4px;font-family:var(--mono);
font-size:13px;outline:none}
input:focus,textarea:focus,select:focus{border-color:var(--accent)}
textarea{min-height:140px;resize:vertical}
button,input[type=submit]{margin-top:12px;padding:8px 18px;background:#21262d;
color:var(--text);border:1px solid var(--border);border-radius:4px;
cursor:pointer;font-size:13px}
button:hover,input[type=submit]:hover{background:#30363d}
pre{background:var(--panel2);border:1px solid var(--border);border-radius:4px;
padding:12px 14px;overflow-x:auto;font-family:var(--mono);font-size:12.5px;
margin:8px 0}
code{font-family:var(--mono);background:#21262d;padding:2px 6px;border-radius:3px;
font-size:12px}
.badge{display:inline-block;padding:2px 9px;border-radius:10px;font-size:10.5px;
font-weight:600;letter-spacing:.06em;text-transform:uppercase}
.badge.ok{background:#3fb95033;color:var(--ok)}
.badge.warn{background:#d2992233;color:var(--warn)}
.badge.err{background:#f8514933;color:var(--danger)}
.muted{color:var(--muted)}
.row{display:flex;gap:14px;flex-wrap:wrap}
.row>*{flex:1;min-width:220px}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:500;text-transform:uppercase;
letter-spacing:.06em;font-size:10.5px}
.hint{background:#1f6feb1a;border-left:3px solid var(--accent);
padding:10px 14px;border-radius:0 4px 4px 0;font-size:12.5px;
color:var(--muted);margin:12px 0}
.warn{color:var(--danger)}
a{color:var(--accent)}
footer{margin-top:40px;text-align:center;color:var(--muted);font-size:12px}
"""

NAV_ITEMS = [
    ("/", "Home"), ("/search", "Search"), ("/xss", "XSS"),
    ("/guestbook", "Guestbook"), ("/users", "Users"),
    ("/docs", "Docs"), ("/console", "GraphQL"),
    ("/login", "Login"), ("/dashboard", "Dashboard"),
]


def layout(title, body, status=200):
    nav = "".join(f'<a href="{p}">{n}</a>' for p, n in NAV_ITEMS)

    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} · VulnLab</title>
<style>{BASE_CSS}</style></head><body>
<div class="wrap">
  <header>
    <div>
      <h1>🧪 VulnLab</h1>
      <p>Intentionally vulnerable application — for authorized testing only.</p>
    </div>
    <nav>{nav}</nav>
  </header>
  {body}
  <footer>⚠️ Never expose this to the internet.</footer>
</div></body></html>"""

    return Response(
        html_doc,
        status=status,
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "X-XSS-Protection": "0"
        }
    )


# ======================================================================
# Database
# ======================================================================

_db = None
_lock = Lock()


def get_db():
    global _db

    if _db is None:
        _db = sqlite3.connect(":memory:", check_same_thread=False)
        c = _db.cursor()

        c.execute("""CREATE TABLE users(
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT,
            bio TEXT)""")

        c.execute("""CREATE TABLE products(
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price REAL)""")

        c.execute("""CREATE TABLE comments(
            id INTEGER PRIMARY KEY,
            author TEXT,
            body TEXT,
            created_at TEXT)""")

        c.execute("""CREATE TABLE secrets(
            id INTEGER PRIMARY KEY,
            owner TEXT,
            secret TEXT)""")

        c.executemany("INSERT INTO users VALUES(?,?,?,?,?,?)", [
            (
                1,
                "admin",
                "admin123",
                "admin@vulnlab.local",
                "admin",
                "Administrator of the lab. Loves coffee."
            ),
            (
                2,
                "alice",
                "password",
                "alice@vulnlab.local",
                "user",
                "Security researcher. Reads RFCs for fun."
            ),
            (
                3,
                "bob",
                "hunter2",
                "bob@vulnlab.local",
                "user",
                "Full-stack dev. Writes mostly Python."
            ),
        ])

        c.executemany("INSERT INTO products VALUES(?,?,?,?)", [
            (1, "Laptop Pro 14", "Aluminium unibody, 32 GB RAM", 1899.00),
            (2, "Wireless Headphones", "ANC, 40-hour battery", 249.00),
            (3, "Mechanical Keyboard", "Hot-swappable, RGB", 149.00),
            (4, "USB-C Hub", "7-in-1, HDMI 4K", 79.00),
        ])

        c.executemany("INSERT INTO comments VALUES(?,?,?,?)", [
            (
                1,
                "alice",
                "Great lab, really helps with scanner testing.",
                "2026-01-05 10:00:00"
            ),
            (
                2,
                "bob",
                "Can confirm the GraphQL endpoint is spicy.",
                "2026-01-06 14:32:00"
            ),
        ])

        c.executemany("INSERT INTO secrets VALUES(?,?,?)", [
            (1, "admin", "FLAG{adm1n_0nly_s3cr3t}"),
            (2, "alice", "FLAG{al1ce_pr1v4t3}"),
        ])

        _db.commit()

    return _db


def q(sql, params=()):
    with _lock:
        try:
            return get_db().execute(sql, params).fetchall(), None
        except Exception as e:
            return [], str(e)


def q_raw(sql):
    """Deliberately unsafe: callers concatenate user input."""
    with _lock:
        try:
            return get_db().execute(sql).fetchall(), None
        except Exception as e:
            return [], str(e)


# ======================================================================
# / — Home
# ======================================================================

@app.route("/")
def index():
    with _lock:
        users = get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]
        products = get_db().execute("SELECT COUNT(*) FROM products").fetchone()[0]

    body = f"""
    <div class="card">
      <h2>Welcome to VulnLab</h2>
      <p class="muted">A small, realistic web app for testing DAST scanners,
         WAFs and manual pentest workflows. <strong>{users}</strong> users,
         <strong>{products}</strong> products in the catalogue.</p>
      <div class="hint">
        Start with <a href="/search">/search</a>, <a href="/users">/users</a>,
        or the <a href="/console">GraphQL console</a>.
      </div>
    </div>

    <div class="row">
      <div class="card"><h2>Search</h2>
        <p class="muted">Product search with full-text matching.</p>
        <a href="/search"><button type="button">Open →</button></a>
      </div>

      <div class="card"><h2>Users</h2>
        <p class="muted">Directory of registered accounts.</p>
        <a href="/users"><button type="button">Open →</button></a>
      </div>

      <div class="card"><h2>API</h2>
        <p class="muted">JSON API with v1 endpoints.</p>
        <a href="/api"><button type="button">Open →</button></a>
      </div>

      <div class="card"><h2>GraphQL</h2>
        <p class="muted">Alternative query interface.</p>
        <a href="/console"><button type="button">Open →</button></a>
      </div>
    </div>
    """

    return layout("Home", body)


# ======================================================================
# /search — Medium reflected XSS + SQLi (?q=)
# ======================================================================

@app.route("/search")
def search():
    term = request.args.get("q", "")

    rows, err = [], None

    if term:
        # VULN: string concatenation → SQL injection
        sql = (
            f"SELECT id,name,description,price FROM products "
            f"WHERE name LIKE '%{term}%' OR description LIKE '%{term}%'"
        )
        rows, err = q_raw(sql)

    result_html = ""

    if term:
        # VULN: q reflected into an HTML attribute without encoding.
        # Only the q parameter is used by this endpoint.
        result_html = f"""
<div class="card">
  <h2>Results for <em>{{{{ q|safe }}}}</em></h2>
  {{% if rows %}}
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Name</th>
        <th>Description</th>
        <th>Price</th>
      </tr>
    </thead>
    <tbody>
      {{% for r in rows %}}
      <tr>
        <td>{{{{ r[0] }}}}</td>
        <td>{{{{ r[1] }}}}</td>
        <td>{{{{ r[2] }}}}</td>
        <td>${{{{ '%.2f'|format(r[3]) }}}}</td>
      </tr>
      {{% endfor %}}
    </tbody>
  </table>
  {{% else %}}
  <p class="muted">No products matched.</p>
  {{% endif %}}
</div>"""

    err_html = (
        f'<div class="card"><h2 class="warn">Query error</h2>'
        f'<pre>{html.escape(err)}</pre></div>'
    ) if err else ""

    body = render_template_string(
        f"""
    <div class="card">
      <h2>Product search</h2>

      <form method="get" action="/search">
        <label for="q">Search term</label>
        <input type="text" id="q" name="q"
               value="{{{{ q|safe }}}}"
               placeholder="laptop, keyboard, ..." autofocus>
        <input type="submit" value="Search">
      </form>

      <h3>Try</h3>

      <pre>laptop

' OR 1=1--

' UNION SELECT 1,username,password,role FROM users--</pre>
    </div>

    {result_html}
    {err_html}
    """,
        q=term,
        rows=rows
    )

    return layout("Search", body)


# ======================================================================
# /users — user listing
# ======================================================================

@app.route("/users")
def users_list():
    rows, _ = q("SELECT id,username,email,role FROM users")

    rows_html = "".join(
        f'<tr><td>{r[0]}</td>'
        f'<td><a href="/user?id={r[0]}">{html.escape(r[1])}</a></td>'
        f'<td>{html.escape(r[2])}</td>'
        f'<td>{html.escape(r[3])}</td></tr>'
        for r in rows
    )

    body = f"""
    <div class="card">
      <h2>Registered users</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Email</th>
            <th>Role</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>
    """

    return layout("Users", body)


# ======================================================================
# /user — user detail; SQLi via ?id=
# ======================================================================

@app.route("/user")
def user_detail():
    uid = request.args.get("id", "1")

    # VULN: uid concatenated directly
    sql = f"SELECT id,username,email,role,bio FROM users WHERE id = {uid}"

    rows, err = q_raw(sql)

    if err:
        body = (
            f'<div class="card">'
            f'<h2 class="warn">Query error</h2>'
            f'<pre>{html.escape(err)}</pre>'
            f'<p class="muted">Query: '
            f'<code>{html.escape(sql)}</code></p>'
            f'</div>'
        )
        return layout("User", body, status=500)

    if not rows:
        body = (
            f'<div class="card">'
            f'<h2>User not found</h2>'
            f'<p class="muted">No user with id = '
            f'<code>{html.escape(uid)}</code>.</p>'
            f'</div>'
        )
        return layout("User", body, status=404)

    rows_html = "".join(
        f'<tr><td>{r[0]}</td>'
        f'<td>{html.escape(r[1])}</td>'
        f'<td>{html.escape(r[2])}</td>'
        f'<td>{html.escape(r[3])}</td></tr>'
        for r in rows
    )

    body = render_template_string(
        f"""
    <div class="card">
      <h2>User <em>{{{{ uid|safe }}}}</em></h2>

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Username</th>
            <th>Email</th>
            <th>Role</th>
          </tr>
        </thead>

        <tbody>{rows_html}</tbody>
      </table>

      <h3>Try</h3>
      <pre>1
1 OR 1=1
1 UNION SELECT 1,username,password,role,bio FROM users--</pre>
    </div>
    """,
        uid=uid
    )

    return layout("User", body)


# ======================================================================
# /login — SQLi auth bypass
# ======================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""

    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")

        # VULN: raw string concatenation
        sql = (
            f"SELECT id,username,role FROM users "
            f"WHERE username='{u}' AND password='{p}'"
        )

        rows, err = q_raw(sql)

        if err:
            msg = (
                f'<div class="card">'
                f'<h2 class="warn">Query error</h2>'
                f'<pre>{html.escape(err)}</pre>'
                f'</div>'
            )

        elif rows:
            session["uid"] = rows[0][0]
            session["user"] = rows[0][1]
            session["role"] = rows[0][2]

            return redirect(url_for("dashboard"))

        else:
            msg = render_template_string(
                '<div class="card">'
                '<h2 class="warn">Invalid credentials</h2>'
                '<p>No account matching <em>{{ u|safe }}</em>.</p>'
                '</div>',
                u=u
            )

    body = f"""
    <div class="card">
      <h2>Sign in</h2>

      <form method="post" action="/login">
        <label for="u">Username</label>
        <input type="text" id="u" name="username" autocomplete="off">

        <label for="p" style="margin-top:12px">Password</label>
        <input type="password" id="p" name="password" autocomplete="off">

        <input type="submit" value="Log in">
      </form>

      <h3>Try</h3>

      <pre>admin / admin123

admin'-- / anything

' OR '1'='1'-- / anything</pre>
    </div>

    {msg}
    """

    return layout("Login", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "")
        e = request.form.get("email", "")
        p = request.form.get("password", "")

        if u:
            with _lock:
                try:
                    get_db().execute(
                        "INSERT INTO users(username,password,email,role,bio) "
                        "VALUES(?,?,?,?,?)",
                        (u, p, e, "user", "")
                    )
                    get_db().commit()
                except Exception:
                    pass

        return redirect(url_for("login"))

    body = """
    <div class="card">
      <h2>Create account</h2>

      <form method="post" action="/register">
        <label for="u">Username</label>
        <input type="text" id="u" name="username">

        <label for="e" style="margin-top:12px">Email</label>
        <input type="email" id="e" name="email">

        <label for="p" style="margin-top:12px">Password</label>
        <input type="password" id="p" name="password">

        <input type="submit" value="Register">
      </form>
    </div>
    """

    return layout("Register", body)


@app.route("/dashboard")
def dashboard():
    if "uid" not in session:
        return redirect(url_for("login"))

    rows, _ = q(
        "SELECT id,author,body,created_at "
        "FROM comments ORDER BY id DESC"
    )

    rows_html = "".join(
        f'<tr><td>{r[0]}</td>'
        f'<td>{html.escape(r[1])}</td>'
        f'<td>{html.escape(r[2])}</td>'
        f'<td>{html.escape(r[3])}</td></tr>'
        for r in rows
    )

    body = f"""
    <div class="card">
      <h2>
        Dashboard — {html.escape(session.get('user', ''))}
        <span class="badge ok">
          {html.escape(session.get('role', ''))}
        </span>
      </h2>

      <p class="muted">
        You are signed in.
        <a href="/logout">Log out</a>
      </p>
    </div>

    <div class="card">
      <h2>Recent comments</h2>

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Author</th>
            <th>Body</th>
            <th>Posted</th>
          </tr>
        </thead>

        <tbody>{rows_html}</tbody>
      </table>
    </div>
    """

    return layout("Dashboard", body)


# ======================================================================
# /profile — reflected XSS via ?name=
# ======================================================================

@app.route("/profile")
def profile():
    name = request.args.get("name", "Guest")

    body = render_template_string(
        """
    <div class="card">
      <h2>Profile</h2>

      <form method="get" action="/profile">
        <label for="n">Display name</label>
        <input type="text" id="n" name="name" value="{{ name|safe }}">
        <input type="submit" value="Save">
      </form>
    </div>

    <div class="card">
      <h2>Welcome back, {{ name|safe }}!</h2>
      <p class="muted">
        Your display name is rendered unescaped.
      </p>
    </div>
    """,
        name=name
    )

    return layout("Profile", body)


# ======================================================================
# /feedback — reflected XSS + /comments — stored XSS
# ======================================================================

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    msg = ""

    if request.method == "POST":
        who = request.form.get("name", "")
        txt = request.form.get("message", "")

        msg = render_template_string(
            '<div class="card">'
            '<h2>Thanks, {{ who|safe }}!</h2>'
            '<pre>{{ txt|safe }}</pre>'
            '</div>',
            who=who,
            txt=txt
        )

    rows, _ = q(
        "SELECT id,author,body,created_at "
        "FROM comments ORDER BY id DESC LIMIT 10"
    )

    rows_html = "".join(
        f'<tr><td>{r[0]}</td>'
        f'<td>{html.escape(r[1])}</td>'
        f'<td>{html.escape(r[2])}</td>'
        f'<td>{html.escape(r[3])}</td></tr>'
        for r in rows
    )

    body = f"""
    <div class="card">
      <h2>Feedback</h2>

      <form method="post" action="/feedback">
        <label for="n">Your name</label>
        <input type="text" id="n" name="name">

        <label for="m" style="margin-top:12px">Message</label>
        <textarea id="m" name="message"></textarea>

        <input type="submit" value="Send">
      </form>
    </div>

    {msg}

    <div class="card">
      <h2>Recent feedback</h2>

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Author</th>
            <th>Body</th>
            <th>Posted</th>
          </tr>
        </thead>

        <tbody>{rows_html}</tbody>
      </table>

      <div class="hint">
        Post a comment via <a href="/comments">/comments</a>
        — comments are stored and rendered to every visitor.
      </div>
    </div>
    """

    return layout("Feedback", body)


@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        who = request.form.get("author", "anon")
        txt = request.form.get("body", "")

        if txt:
            with _lock:
                get_db().execute(
                    "INSERT INTO comments(author,body,created_at) "
                    "VALUES(?,?,?)",
                    (
                        who,
                        txt,
                        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                    )
                )
                get_db().commit()

        return redirect(url_for("comments"))

    rows, _ = q(
        "SELECT id,author,body,created_at "
        "FROM comments ORDER BY id DESC"
    )

    # VULN: stored XSS
    rows_html = "".join(
        f'<tr><td>{r[0]}</td>'
        f'<td>{html.escape(r[1])}</td>'
        f'<td>{{{{ r[2]|safe }}}}</td>'
        f'<td>{html.escape(r[3])}</td></tr>'
        for r in rows
    )

    body = render_template_string(
        f"""
    <div class="card">
      <h2>Leave a comment</h2>

      <form method="post" action="/comments">
        <label for="a">Name</label>
        <input type="text" id="a" name="author">

        <label for="b" style="margin-top:12px">Comment</label>
        <textarea id="b" name="body"></textarea>

        <input type="submit" value="Post">
      </form>
    </div>

    <div class="card">
      <h2>All comments</h2>

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Author</th>
            <th>Body</th>
            <th>Posted</th>
          </tr>
        </thead>

        <tbody>{rows_html}</tbody>
      </table>
    </div>
    """,
        r=rows
    )

    return layout("Comments", body)


# ======================================================================
# /contact
# ======================================================================

@app.route("/contact")
def contact():
    name = request.args.get("name", "")

    body = render_template_string(
        """
    <div class="card">
      <h2>Contact us</h2>

      <p class="muted">
        Email:
        <a href="mailto:hello@vulnlab.local">
          hello@vulnlab.local
        </a>
      </p>

      <form method="get" action="/contact">
        <label for="n">Your name</label>
        <input type="text" id="n" name="name" value="{{ name|safe }}">
        <input type="submit" value="Prefill greeting">
      </form>
    </div>

    {% if name %}
    <div class="card">
      <h2>Hi, {{ name|safe }}!</h2>
      <p class="muted">We'll be in touch shortly.</p>
    </div>
    {% endif %}
    """,
        name=name
    )

    return layout("Contact", body)


# ======================================================================
# /admin — 403 with reflected error
# ======================================================================

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        err = request.args.get("error", "Authentication required")

        body = render_template_string(
            """
        <div class="card">
          <h2>Admin <span class="badge err">403</span></h2>
          <p class="warn">{{ err|safe }}</p>
          <p class="muted">
            You must be signed in as an administrator.
          </p>
          <a href="/login">
            <button type="button">Log in</button>
          </a>
        </div>
        """,
            err=err
        )

        return layout("Admin", body, status=403)

    rows, _ = q("SELECT id,owner,secret FROM secrets")

    rows_html = "".join(
        f'<tr><td>{r[0]}</td>'
        f'<td>{html.escape(r[1])}</td>'
        f'<td>{html.escape(r[2])}</td></tr>'
        for r in rows
    )

    body = f"""
    <div class="card">
      <h2>
        Admin panel
        <span class="badge ok">authenticated</span>
      </h2>

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Owner</th>
            <th>Secret</th>
          </tr>
        </thead>

        <tbody>{rows_html}</tbody>
      </table>
    </div>
    """

    return layout("Admin", body)


# ======================================================================
# /api, /api/v1/status, /api/v1/users, /api/v1/search
# ======================================================================

@app.route("/api")
def api_index():
    return jsonify({
        "name": "VulnLab API",
        "version": "1.0",
        "endpoints": {
            "status": "/api/v1/status",
            "users": "/api/v1/users",
            "search": "/api/v1/search?q=",
            "graphql": "/graphql",
        },
    })


@app.route("/api/v1/status")
def api_status():
    return jsonify({
        "status": "ok",
        "time": datetime.utcnow().isoformat()
    })


@app.route("/api/v1/users")
def api_users():
    uid = request.args.get("id", "")

    if uid:
        # VULN: uid concatenated → SQLi in JSON API
        sql = (
            f"SELECT id,username,email,role "
            f"FROM users WHERE id = {uid}"
        )

        rows, err = q_raw(sql)

        if err:
            return jsonify({
                "error": err,
                "sql": sql
            }), 500

        return jsonify({
            "users": [
                dict(zip(
                    ["id", "username", "email", "role"],
                    r
                ))
                for r in rows
            ]
        })

    rows, _ = q("SELECT id,username,email,role FROM users")

    return jsonify({
        "users": [
            dict(zip(
                ["id", "username", "email", "role"],
                r
            ))
            for r in rows
        ]
    })


@app.route("/api/v1/search")
def api_search():
    term = request.args.get("q", "")

    if not term:
        return jsonify({"error": "missing ?q="}), 400

    # VULN: SQLi + reflected in JSON
    sql = (
        f"SELECT id,name,description,price FROM products "
        f"WHERE name LIKE '%{term}%' OR description LIKE '%{term}%'"
    )

    rows, err = q_raw(sql)

    if err:
        return jsonify({
            "error": err,
            "sql": sql,
            "reflected": term
        }), 500

    return jsonify({
        "query": term,
        "results": [
            {
                "id": r[0],
                "name": r[1],
                "description": r[2],
                "price": r[3]
            }
            for r in rows
        ]
    })


# ======================================================================
# GraphQL — SQLi via user(id:) and search(term:), reflected XSS in UI
# ======================================================================

_OP_RE = re.compile(
    r'\s*(user|search)\s*\((.*?)\)\s*\{([^}]*)\}',
    re.S
)

_ARG_RE = re.compile(
    r'(\w+)\s*:\s*("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[^,]+)'
)


def parse_graphql(query):
    m = _OP_RE.match(query or "")

    if not m:
        return None, {}, []

    op, args_raw, fields_raw = m.group(1), m.group(2), m.group(3)

    fields = [
        f.strip()
        for f in fields_raw.split()
        if f.strip()
    ]

    args = {}

    for k, v in _ARG_RE.findall(args_raw):
        v = v.strip()

        if (
            len(v) >= 2
            and v[0] == v[-1]
            and v[0] in "\"'"
        ):
            v = v[1:-1]

        args[k] = v

    return op, args, fields


@app.route("/graphql", methods=["GET", "POST"])
def graphql():
    if request.method == "GET":
        return jsonify({
            "message": 'POST JSON {"query": "user(id: 1) { username email }"}',
            "examples": [
                "user(id: 1) { username email role }",
                'search(term: "admin") { username email }'
            ],
        })

    data = request.get_json(silent=True) or {}

    query = data.get("query", "") or request.form.get("query", "")

    for k, v in (data.get("variables") or {}).items():
        query = query.replace(f"${k}", str(v))

    op, args, fields = parse_graphql(query)

    if not op:
        return jsonify({
            "errors": [
                {"message": "Could not parse query"}
            ]
        }), 400

    if op == "user":
        uid = args.get("id", "1")

        sql = (
            f"SELECT id,username,email,role "
            f"FROM users WHERE id = {uid}"
        )

        rows, err = q_raw(sql)

        if err:
            return jsonify({
                "errors": [{
                    "message": err,
                    "extensions": {
                        "sql": sql
                    }
                }]
            }), 500

        users = [
            dict(zip(
                ["id", "username", "email", "role"],
                r
            ))
            for r in rows
        ]

        out = [
            {
                k: u[k]
                for k in fields
                if k in u
            }
            for u in users
        ]

        return jsonify({
            "data": {
                "user": out
            }
        })

    if op == "search":
        term = args.get("term", "")

        sql = (
            f"SELECT username,email FROM users "
            f"WHERE username LIKE '%{term}%'"
        )

        rows, err = q_raw(sql)

        if err:
            return jsonify({
                "errors": [{
                    "message": err,
                    "extensions": {
                        "sql": sql
                    }
                }]
            }), 500

        users = [
            dict(zip(
                ["username", "email"],
                r
            ))
            for r in rows
        ]

        out = [
            {
                k: u[k]
                for k in fields
                if k in u
            }
            for u in users
        ]

        return jsonify({
            "data": {
                "search": out
            },
            "extensions": {
                "reflected": term,
                "sql": sql
            }
        })

    return jsonify({
        "errors": [
            {"message": "Unknown operation"}
        ]
    }), 400


@app.route("/console", methods=["GET"])
def console():
    query = request.args.get("query", "")

    resp_pretty = ""
    reflected = ""
    sql_used = ""

    if query:
        with app.test_request_context(
            "/graphql",
            method="POST",
            json={"query": query}
        ):
            r = graphql()

            if isinstance(r, tuple):
                r = r[0]

            try:
                resp_json = json.loads(
                    r.get_data(as_text=True)
                )
            except Exception:
                resp_json = {
                    "error": "unparseable"
                }

        ext = (resp_json or {}).get("extensions") or {}

        reflected = ext.get("reflected", "")
        sql_used = ext.get("sql", "")

        resp_pretty = json.dumps(
            resp_json,
            indent=2
        )

    body = f"""
    <div class="card">
      <h2>GraphQL console</h2>

      <p class="muted">
        POSTs to <code>/graphql</code>. The response is rendered
        below with <code>|safe</code> so any reflected values appear as HTML.
      </p>

      <form method="get" action="/console">
        <label for="q">Query</label>
        <textarea id="q" name="query"
                  spellcheck="false">{html.escape(query)}</textarea>
        <input type="submit" value="Run">
      </form>

      <h3>Try</h3>

      <pre>user(id: 1) {{ username email role }}

search(term: "admin") {{ username email }}

user(id: 1 OR 1=1) {{ username email }}

search(term: "&lt;img src=x onerror=alert(1)&gt;") {{ username }}</pre>
    </div>

    {
        f'<div class="card"><h2>Executed SQL</h2>'
        f'<pre>{html.escape(sql_used)}</pre></div>'
        if sql_used else ''
    }

    {
        f'<div class="card"><h2>Response</h2>'
        f'<pre>{html.escape(resp_pretty)}</pre></div>'
        if resp_pretty else ''
    }

    {
        render_template_string(
            '<div class="card">'
            '<h2>Reflected term</h2>'
            '<pre>You searched for: '
            '<strong>{{ r|safe }}</strong></pre>'
            '</div>',
            r=reflected
        )
        if reflected else ''
    }
    """

    return layout("GraphQL console", body)


# ======================================================================
# NUCLEI-XSS FRIENDLY PAGES
#
# Difficulty labels:
#   [EASY]   = direct reflection, no encoding
#   [MEDIUM] = contextual reflection
#   [HARD]   = stored XSS or needs interaction
# ======================================================================

@app.route("/xss", methods=["GET", "POST"])
def xss_lab():
    # [MEDIUM]
    # Exactly one vulnerable parameter:
    # POST parameter: comment
    #
    # The value is placed into an HTML attribute without encoding.

    comment = request.form.get("comment", "")

    body = f"""
    <div class="card">
      <h2>
        XSS Lab
        <span class="badge warn">[MEDIUM]</span>
      </h2>

      <p class="muted">
        The POST <code>comment</code> parameter is reflected
        into an HTML attribute.
      </p>

      <form method="post" action="/xss">
        <label for="comment">comment</label>
        <textarea id="comment" name="comment"></textarea>
        <input type="submit" value="Submit">
      </form>
    </div>

    <div class="card">
      <h2>Preview</h2>

      <div data-comment="{comment}">
        Comment preview.
      </div>
    </div>
    """

    return layout("XSS Lab", body)


@app.route("/echo")
def echo():
    # [EASY]
    # Exactly one vulnerable parameter:
    # GET parameter: msg

    msg = request.args.get("msg", "")

    return layout(
        "Echo",
        f'<div class="card">'
        f'<h2>Echo <span class="badge warn">[EASY]</span></h2>'
        f'<pre>{msg}</pre>'
        f'</div>'
    )


@app.route("/welcome")
def welcome():
    # [EASY] Reflected XSS via ?name=.
    name = request.args.get("name", "")

    return layout(
        "Welcome",
        f'<div class="card">'
        f'<h1>Welcome, {name}!</h1>'
        f'</div>'
    )


@app.route("/preview")
def preview():
    # [EASY] Raw HTML preview.
    content = request.args.get(
        "html",
        request.args.get("content", "")
    )

    return layout(
        "Preview",
        f'<div class="card">'
        f'<h2>Preview</h2>'
        f'{content}'
        f'</div>'
    )


@app.route("/error")
def error_page():
    # [EASY] Reflected XSS in error message.
    err = request.args.get(
        "error",
        request.args.get("msg", "An error occurred")
    )

    return layout(
        "Error",
        f'<div class="card">'
        f'<h2>Error</h2>'
        f'<p class="warn">{err}</p>'
        f'</div>',
        status=500
    )


@app.route("/nuclei-xss")
def nuclei_xss():
    # [MEDIUM]
    # Exactly one vulnerable parameter:
    # GET parameter: q
    #
    # q is reflected into a JavaScript string without
    # JavaScript-string encoding.

    q_value = request.args.get("q", "")

    body = f"""
    <div class="card">
      <h2>
        Nuclei XSS
        <span class="badge warn">[MEDIUM]</span>
      </h2>

      <p class="muted">
        The <code>q</code> parameter is reflected into a
        JavaScript string.
      </p>

      <form method="get" action="/nuclei-xss">
        <label for="q">Search query</label>
        <input
          type="text"
          id="q"
          name="q"
          value="{html.escape(q_value)}"
          placeholder="search..."
        >
        <input type="submit" value="Search">
      </form>

      <p id="status" class="muted">
        Waiting for a search query.
      </p>
    </div>

    <script>
      const searchQuery = '{q_value}';

      if (searchQuery) {{
          document.getElementById("status").textContent =
              "Searching for: " + searchQuery;
      }}
    </script>
    """

    return layout("Nuclei XSS", body)


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    # [HARD] Stored XSS.
    if request.method == "POST":
        who = request.form.get("name", "anon")
        msg = request.form.get("message", "")

        if msg:
            with _lock:
                get_db().execute(
                    "INSERT INTO comments(author,body,created_at) "
                    "VALUES(?,?,?)",
                    (
                        who,
                        msg,
                        datetime.utcnow().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                )
                get_db().commit()

        return redirect(url_for("guestbook"))

    rows, _ = q(
        "SELECT id,author,body,created_at "
        "FROM comments ORDER BY id DESC"
    )

    rows_html = "".join(
        f'<tr><td>{r[0]}</td>'
        f'<td>{html.escape(r[1])}</td>'
        f'<td>{r[2]}</td>'
        f'<td>{html.escape(r[3])}</td></tr>'
        for r in rows
    )

    body = f"""
    <div class="card">
      <h2>
        Guestbook
        <span class="badge warn">[HARD]</span>
      </h2>

      <form method="post" action="/guestbook">
        <label for="n">Name</label>
        <input type="text" id="n" name="name">

        <label for="m">Message</label>
        <textarea id="m" name="message"></textarea>

        <input type="submit" value="Sign">
      </form>
    </div>

    <div class="card">
      <h2>Entries</h2>

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Author</th>
            <th>Body</th>
            <th>Posted</th>
          </tr>
        </thead>

        <tbody>{rows_html}</tbody>
      </table>
    </div>
    """

    return layout("Guestbook", body)


@app.route("/product")
def product():
    # [MEDIUM] SQLi + reflected XSS via ?id=.
    pid = request.args.get("id", "1")

    sql = (
        f"SELECT id,name,description,price "
        f"FROM products WHERE id = {pid}"
    )

    rows, err = q_raw(sql)

    if err:
        return layout(
            "Product",
            f'<div class="card">'
            f'<h2 class="warn">Query error</h2>'
            f'<pre>{html.escape(err)}</pre>'
            f'</div>',
            status=500
        )

    if not rows:
        return layout(
            "Product",
            f'<div class="card">'
            f'<h2>Not found</h2>'
            f'<p>No product id {pid}</p>'
            f'</div>',
            status=404
        )

    rows_html = "".join(
        f'<tr><td>{r[0]}</td>'
        f'<td>{html.escape(r[1])}</td>'
        f'<td>{html.escape(r[2])}</td>'
        f'<td>${r[3]:.2f}</td></tr>'
        for r in rows
    )

    return layout(
        "Product",
        f'<div class="card">'
        f'<h2>Product <em>{pid}</em></h2>'
        f'<table>{rows_html}</table>'
        f'</div>'
    )


@app.route("/redirect")
def redirect_lab():
    # [MEDIUM] Open redirect.
    url = request.args.get(
        "url",
        request.args.get("next", "/")
    )

    return redirect(url)


@app.route("/jsonp")
def jsonp():
    # [MEDIUM] JSONP with user-controlled callback.
    cb = request.args.get("callback", "callback")
    data = request.args.get("data", "hello")

    return Response(
        f"{cb}({{'data':'{data}'}});",
        mimetype="application/javascript"
    )


@app.route("/api/v1/echo")
def api_echo():
    # [MEDIUM] JSON echo.
    msg = request.args.get(
        "msg",
        request.args.get("q", "")
    )

    if request.args.get("format") == "html":
        return Response(
            f"<html><body><h1>{msg}</h1></body></html>",
            mimetype="text/html"
        )

    return jsonify({
        "echo": msg,
        "reflected": msg
    })


# ======================================================================
# Static / enumerable
# ======================================================================

@app.route("/docs")
def docs():
    body = """
    <div class="card">
      <h2>API documentation</h2>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Path</th>
            <th>Description</th>
          </tr>
        </thead>

        <tbody>
          <tr>
            <td>GET</td>
            <td>/api/v1/status</td>
            <td>Service status</td>
          </tr>

          <tr>
            <td>GET</td>
            <td>/api/v1/users</td>
            <td>
              List users; <code>?id=</code> for a single user
            </td>
          </tr>

          <tr>
            <td>GET</td>
            <td>/api/v1/search</td>
            <td>
              Product search; <code>?q=</code>
            </td>
          </tr>

          <tr>
            <td>GET</td>
            <td>/api/v1/echo</td>
            <td>
              Echo; add <code>?format=html</code>
              to render as HTML
            </td>
          </tr>

          <tr>
            <td>GET/POST</td>
            <td>/graphql</td>
            <td>GraphQL query interface</td>
          </tr>
        </tbody>
      </table>
    </div>
    """

    return layout("Docs", body)


@app.route("/help")
def help_page():
    return layout(
        "Help",
        """
    <div class="card">
      <h2>Help</h2>

      <p class="muted">
        Use the navigation above to explore the lab.
        The following endpoints are available:
      </p>

      <pre>/search  /users  /user  /profile
/xss  /echo  /welcome  /preview  /error  /nuclei-xss
/guestbook  /product  /redirect  /jsonp  /api/v1/echo
/comments  /feedback  /contact
/login  /register  /logout  /dashboard
/admin  /api  /docs  /console
/upload  /backup  /config</pre>
    </div>
    """
    )


@app.route("/about")
def about():
    return layout(
        "About",
        """
    <div class="card">
      <h2>About VulnLab</h2>

      <p class="muted">
        VulnLab is a deliberately vulnerable web application
        used for testing security scanners in CI pipelines.
      </p>
    </div>
    """
    )


@app.route("/upload", methods=["GET", "POST"])
def upload():
    msg = ""

    if request.method == "POST":
        f = request.files.get("file")

        if f:
            # VULN: accepts any filename without sanitisation
            path = os.path.join(
                "/tmp/vulnlab_uploads",
                f.filename or "file"
            )

            os.makedirs(
                "/tmp/vulnlab_uploads",
                exist_ok=True
            )

            f.save(path)

            msg = (
                f'<div class="card">'
                f'<h2>Uploaded</h2>'
                f'<pre>{html.escape(path)}</pre>'
                f'</div>'
            )

    return layout(
        "Upload",
        f"""
    <div class="card">
      <h2>File upload</h2>

      <form method="post"
            action="/upload"
            enctype="multipart/form-data">

        <label for="file">Choose file</label>
        <input type="file" id="file" name="file">

        <input type="submit" value="Upload">
      </form>
    </div>

    {msg}
    """
    )


@app.route("/backup")
def backup():
    return layout(
        "Backups",
        """
    <div class="card">
      <h2>Backup directory</h2>

      <p class="muted">
        Daily snapshots. Restricted — contact admin for access.
      </p>

      <table>
        <thead>
          <tr>
            <th>File</th>
            <th>Date</th>
          </tr>
        </thead>

        <tbody>
          <tr>
            <td>db-2026-01-05.sql</td>
            <td>2026-01-05</td>
          </tr>

          <tr>
            <td>db-2026-01-06.sql</td>
            <td>2026-01-06</td>
          </tr>

          <tr>
            <td>config.tar.gz</td>
            <td>2026-01-07</td>
          </tr>
        </tbody>
      </table>
    </div>
    """,
        status=403
    )


@app.route("/config")
def config():
    return layout(
        "Config",
        """
    <div class="card">
      <h2>
        Configuration
        <span class="badge err">403</span>
      </h2>

      <p class="warn">
        Configuration endpoint is not publicly accessible.
      </p>
    </div>
    """,
        status=403
    )


@app.route("/robots.txt")
def robots():
    return Response(
        """User-agent: *
Disallow: /admin
Disallow: /api
Disallow: /backup
Disallow: /config
Disallow: /console
Disallow: /dashboard
Disallow: /upload
""",
        mimetype="text/plain"
    )


@app.route("/sitemap.xml")
def sitemap():
    urls = [
        "/",
        "/about",
        "/admin",
        "/api",
        "/backup",
        "/comments",
        "/config",
        "/console",
        "/contact",
        "/dashboard",
        "/docs",
        "/feedback",
        "/graphql",
        "/help",
        "/login",
        "/logout",
        "/profile",
        "/register",
        "/search",
        "/upload",
        "/user",
        "/users",
        "/xss",
        "/echo",
        "/welcome",
        "/preview",
        "/error",
        "/nuclei-xss",
        "/guestbook",
        "/product",
        "/redirect",
        "/jsonp",
        "/api/v1/echo"
    ]

    base = request.host_url.rstrip("/")

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    )

    xml += "".join(
        f"  <url><loc>{base}{u}</loc></url>\n"
        for u in urls
    )

    xml += "</urlset>"

    return Response(
        xml,
        mimetype="application/xml"
    )


# ======================================================================

if __name__ == "__main__":
    get_db()

    print("🚨 Vulnerable server on http://localhost:5000")
    print("⚠️  Do not expose to the internet.")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )