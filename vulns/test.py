# vulnerable_app.py
from flask import Flask, request, render_template_string, redirect, url_for, make_response
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = 'insecure_key_for_demo_only'

comments = []

BASE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable XSS Demo</title>
    <style>
        body { font-family: Arial; max-width: 800px; margin: 20px auto; padding: 20px; }
        .comment { border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .warning { background: #ffe6e6; border: 2px solid red; padding: 10px; margin: 20px 0; }
        input, textarea, button { padding: 8px; margin: 5px; }
        textarea { width: 100%; height: 80px; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="warning">
        ⚠️ <strong>INTENTIONALLY VULNERABLE APP</strong> - For security education only!
    </div>
    <h1>XSS Vulnerable Demo</h1>
    <nav>
        <a href="/">Home</a> |
        <a href="/search">Search</a> |
        <a href="/guestbook">Guestbook</a> |
        <a href="/profile">Profile</a>
    </nav>
    <hr>
    {{ content | safe }}
</body>
</html>
"""

# Reflected XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Build raw HTML with user input directly concatenated - NO escaping
    content = (
        '<h2>Search</h2>'
        '<form method="get">'
        f'<input type="text" name="q" value="{query}" placeholder="Search...">'
        '<button type="submit">Search</button>'
        '</form>'
        f'<p>You searched for: <strong>{query}</strong></p>'
        '<p>No results found.</p>'
    )
    # Markup(...) tells Jinja2 "this is safe HTML, don't escape it"
    return render_template_string(BASE_HTML, content=Markup(content))

# Stored XSS
@app.route('/guestbook', methods=['GET', 'POST'])
def guestbook():
    if request.method == 'POST':
        name = request.form.get('name', 'Anonymous')
        message = request.form.get('message', '')
        comments.append({'name': name, 'message': message})
        return redirect(url_for('guestbook'))

    comments_html = ""
    for c in comments:
        comments_html += (
            '<div class="comment">'
            f"<strong>{c['name']}</strong> says:<br>"
            f"{c['message']}"
            '</div>'
        )

    content = (
        '<h2>Guestbook</h2>'
        '<form method="post">'
        '<input type="text" name="name" placeholder="Your name"><br>'
        '<textarea name="message" placeholder="Your message..."></textarea><br>'
        '<button type="submit">Post Comment</button>'
        '</form>'
        '<h3>Comments:</h3>'
        f'{comments_html}'
    )
    return render_template_string(BASE_HTML, content=Markup(content))

# DOM-based XSS + header reflected XSS
@app.route('/profile')
def profile():
    content = """
    <h2>Profile</h2>
    <p>Enter your name to personalize the page:</p>
    <input type="text" id="username" placeholder="Your name">
    <button onclick="greet()">Greet Me</button>
    <div id="greeting"></div>

    <script>
        function greet() {
            var name = document.getElementById('username').value;
            // DOM XSS: innerHTML with user input
            document.getElementById('greeting').innerHTML = '<h3>Hello, ' + name + '!</h3>';
        }
        // Also auto-load from URL hash
        var hash = decodeURIComponent(window.location.hash.substring(1));
        if (hash) {
            document.getElementById('greeting').innerHTML = '<p>' + hash + '</p>';
        }
    </script>

    <p><small>Try hash: <code>#&lt;img src=x onerror=alert(1)&gt;</code></small></p>
    """
    return render_template_string(BASE_HTML, content=Markup(content))

# User-Agent reflected XSS
@app.route('/')
def home():
    ua = request.headers.get('User-Agent', 'Unknown')
    content = (
        '<h2>Welcome</h2>'
        f'<p>Your browser: {ua}</p>'
        '<p>Vulnerable endpoints:</p>'
        '<ul>'
        '<li><a href="/search?q=test">/search?q=</a> - Reflected XSS</li>'
        '<li><a href="/guestbook">/guestbook</a> - Stored XSS</li>'
        '<li><a href="/profile">/profile</a> - DOM XSS</li>'
        '</ul>'
        '<h3>Payloads to try:</h3>'
        '<pre>'
        '&lt;script&gt;alert(1)&lt;/script&gt;\n'
        '&lt;img src=x onerror=alert(1)&gt;\n'
        '&lt;svg onload=alert(1)&gt;\n'
        '</pre>'
    )
    return render_template_string(BASE_HTML, content=Markup(content))

if __name__ == '__main__':
    print("=" * 60)
    print("⚠️  INTENTIONALLY VULNERABLE - DO NOT DEPLOY ⚠️")
    print("http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=5000)