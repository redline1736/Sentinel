#!/usr/bin/env python3
"""
Internal services — never exposed to the public.

    Products API  127.0.0.1:8081   /products?q=...   (SQLi here)
    Sandbox       127.0.0.1:8082   /render?html=...  (reflected XSS here)

Both run in one process, on two ports, via threading.
"""
import os
import sqlite3
import threading
from flask import Flask, request, jsonify, Response

DB = "products.db"


# ===========================================================================
# Products API  — port 8081
# ===========================================================================
products = Flask("products-api")


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    con = sqlite3.connect(DB)
    con.executescript("""
        CREATE TABLE products (
            id       INTEGER PRIMARY KEY,
            name     TEXT,
            category TEXT,
            price    REAL,
            stock    INTEGER
        );
        CREATE TABLE internal_notes (
            id    INTEGER PRIMARY KEY,
            note  TEXT
        );
        INSERT INTO products (name, category, price, stock) VALUES
            ('Aero Keyboard',    'peripherals',  89.99,  42),
            ('Aero Mouse',       'peripherals',  49.50, 118),
            ('Aero Monitor 27"', 'displays',    329.00,  17),
            ('Aero Monitor 32"', 'displays',    549.00,   9),
            ('Aero Dock',        'accessories', 149.00,  23),
            ('Aero Webcam',      'peripherals',  79.00,  61),
            ('Aero Headset',     'audio',       129.00,  37);
        INSERT INTO internal_notes (note) VALUES
            ('warehouse contact: ops@internal.example'),
            ('db backup key: not-a-real-backup-key');
    """)
    con.commit()
    con.close()


@products.route("/")
def products_index():
    return "products-api 1.0\n"


@products.route("/products")
def search():
    q = request.args.get("q", "")

    # ------------------------------------------------------------------
    # INTENTIONALLY VULNERABLE — q is concatenated straight into SQL.
    #   ?q=' UNION SELECT 1,note,note,0,0 FROM internal_notes--
    # dumps the internal_notes table.
    # ------------------------------------------------------------------
    sql = (
        "SELECT id, name, category, price, stock FROM products "
        f"WHERE name LIKE '%{q}%' OR category LIKE '%{q}%'"
    )

    con = sqlite3.connect(DB)
    try:
        rows = con.execute(sql).fetchall()
    except sqlite3.Error as e:
        con.close()
        return f"sql error: {e}\n", 500
    con.close()

    return jsonify([
        {"id": r[0], "name": r[1], "category": r[2],
         "price": r[3], "stock": r[4]}
        for r in rows
    ])


@products.route("/product/<int:pid>")
def product(pid):
    con = sqlite3.connect(DB)
    row = con.execute(
        "SELECT id, name, category, price, stock FROM products WHERE id = ?",
        (pid,),
    ).fetchone()
    con.close()
    if not row:
        return "not found\n", 404
    return jsonify({"id": row[0], "name": row[1], "category": row[2],
                    "price": row[3], "stock": row[4]})


# ===========================================================================
# Product Sandbox  — port 8082
# ===========================================================================
sandbox = Flask("sandbox")


@sandbox.route("/")
def sandbox_index():
    return "sandbox 1.0\n"


@sandbox.route("/render")
def render():
    html = request.args.get("html", "")
    if not html:
        return Response("<p>nothing to render</p>", mimetype="text/html")
    # Reflected XSS — the HTML comes back verbatim.
    return Response(html, mimetype="text/html")


@sandbox.route("/templates")
def templates():
    return Response(
        "<ul><li>product-card</li><li>banner</li><li>promo</li></ul>",
        mimetype="text/html",
    )


# ===========================================================================
# Boot both servers on their own threads.
# ===========================================================================
def serve(app, host, port):
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    init_db()

    t1 = threading.Thread(target=serve, args=(products, "127.0.0.1", 8081),
                          daemon=True)
    t2 = threading.Thread(target=serve, args=(sandbox, "127.0.0.1", 8082),
                          daemon=True)
    t1.start()
    t2.start()

    print("products-api  → http://127.0.0.1:8081")
    print("sandbox       → http://127.0.0.1:8082")
    t1.join()
    t2.join()