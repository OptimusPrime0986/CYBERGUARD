"""ShopEasy: DELIBERATELY VULNERABLE training app (fake data). Each weakness is marked `# VULN:`."""
import sqlite3, threading
from flask import Flask, request, session, redirect
from markupsafe import escape as esc
from common import log_request, shell, money, guide

app = Flask("shop"); app.secret_key = "demo-not-a-secret-2"
BRAND, ACCENT = "ShopEasy", "#c2410c"
NAV = [("Products", "/"), ("Orders", "/orders"), ("Attack guide", "/attack-guide")]
_db, _l = None, threading.RLock()


def seed():
    global _db
    db = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
    db.executescript("""
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
    CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT, description TEXT);
    CREATE TABLE reviews(id INTEGER PRIMARY KEY, product_id INT, author TEXT, body TEXT);
    CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INT, item TEXT, total REAL, address TEXT);
    INSERT INTO users VALUES(1,'carol','carol123','customer'),(2,'dave','dave12345','customer'),(3,'shopadmin','Sh0p!demo','admin');
    INSERT INTO products VALUES(1,'Trail Running Shoes',89.99,'Footwear','Lightweight shoes with grippy soles.'),(2,'Wireless Earbuds',59.00,'Audio','Noise-reducing earbuds, 24h battery.'),
      (3,'Insulated Bottle',24.50,'Outdoor','Keeps drinks cold for 24 hours.'),(4,'Laptop Backpack',45.00,'Bags','Water-resistant, fits 15-inch laptops.'),
      (5,'Desk Lamp',32.75,'Home','Dimmable LED lamp.'),(6,'Yoga Mat',28.00,'Fitness','Non-slip 6mm mat.');
    INSERT INTO reviews VALUES(1,1,'Sam','Great grip, very comfortable.'),(2,2,'Lee','Battery lasts all week.');
    INSERT INTO orders VALUES(1,1,'Wireless Earbuds',59.00,'12 Demo Street, Faketown'),(2,2,'Yoga Mat',28.00,'99 Sample Road, Mockville'),(3,3,'Laptop Backpack',45.00,'1 Admin Way, Testville');""")
    _db = db


seed()


def run(sql, args=()):
    with _l: return _db.execute(sql, args).fetchall()


def page(title, body): return shell(BRAND, ACCENT, NAV, title, body, session.get("name"))


@app.before_request
def _log(): log_request()


def cards(rows):
    return '<div class="grid">' + "".join(f'<div class="card"><span class="tag">{esc(c)}</span><h2><a href="/product?id={i}">{esc(n)}</a></h2><div class="big">{money(p)}</div></div>' for i, n, p, c in rows) + "</div>"


@app.get("/")
def home():
    rows = run("SELECT id, name, price, category FROM products")
    return page("Products", '<div class="hero"><h1>Everyday gear, fair prices.</h1><form action="/search"><input name="q" placeholder="Search products" style="max-width:420px"><button>Search</button></form></div>' + cards(rows)
                + '<p class="muted">Demo logins: carol / carol123 · dave / dave12345</p>')


@app.get("/search")
def search():
    term, err, rows = request.args.get("q", ""), "", []
    sql = "SELECT id, name, price, category FROM products WHERE name LIKE '%%%s%%'" % term   # VULN: SQL injection (UNION: 4 columns)
    try: rows = run(sql)
    except sqlite3.Error as e: err = f'<div class="err">Database error: {esc(e)}</div>'
    return page("Search", f'<h2>Results for: {term}</h2>{err}' + (cards(rows) if rows else '<p class="muted">No products found.</p>'))   # VULN: reflected XSS


@app.get("/product")
def product():
    pid = request.args.get("id", "1")
    try: r = run("SELECT id, name, price, category, description FROM products WHERE id=%s" % pid)   # VULN: numeric SQL injection (no quotes needed)
    except sqlite3.Error as e: return page("Error", f'<div class="err">Database error: {esc(e)}</div>'), 500
    if not r: return page("Not found", '<div class="err">Product not found.</div>'), 404
    i, n, p, c, d = r[0]
    revs = "".join(f'<div class="card"><b>{a}</b><br>{b}</div>' for a, b in run("SELECT author, body FROM reviews WHERE product_id=? ORDER BY id DESC", (i,)))   # VULN: stored XSS
    return page(n, f'<div class="card"><span class="tag">{esc(c)}</span><h2>{esc(n)}</h2><p>{esc(d)}</p><div class="big">{money(p)}</div>'
                f'<form method="post" action="/buy"><input type="hidden" name="item" value="{esc(n)}"><input type="hidden" name="total" value="{p}"><button>Buy now</button></form></div>'
                f'<h2>Reviews</h2>{revs}<div class="card"><form method="post" action="/review"><input type="hidden" name="pid" value="{i}"><label>Name<input name="author"></label><label>Review<textarea name="body" rows="3"></textarea></label><button>Post review</button></form></div>')


@app.post("/review")
def review():
    with _l: _db.execute("INSERT INTO reviews(product_id, author, body) VALUES(?,?,?)", (int(request.form.get("pid", 1)), request.form.get("author", "anon")[:60], request.form.get("body", "")[:500]))
    return redirect("/product?id=" + request.form.get("pid", "1"))


@app.route("/login", methods=["GET", "POST"])
def login():
    err = ""
    if request.method == "POST":
        u, p = request.form.get("username", ""), request.form.get("password", "")
        sql = "SELECT id, username FROM users WHERE username='%s' AND password='%s'" % (u, p)   # VULN: SQL injection (login bypass)
        try:
            rows = run(sql)
            if rows: session["uid"], session["name"] = rows[0]; return redirect("/orders")
            err = "Invalid login."
        except sqlite3.Error as e: err = "Database error: %s" % esc(e)
    return page("Sign in", f'<div class="card" style="max-width:420px;margin:auto"><h2>Sign in</h2>{"<div class=err>"+err+"</div>" if err else ""}<form method="post"><label>Username<input name="username"></label><label>Password<input name="password" type="password"></label><button>Sign in</button></form></div>')


@app.get("/logout")
def logout(): session.clear(); return redirect("/")


@app.post("/buy")
def buy():
    if not session.get("uid"): return redirect("/login")
    with _l:   # VULN: price comes from the client (parameter tampering: business logic, not visible to a WAF)
        _db.execute("INSERT INTO orders(user_id,item,total,address) VALUES(?,?,?,?)", (session["uid"], request.form.get("item", "?")[:80], float(request.form.get("total", 0)), "Saved demo address"))
    return redirect("/orders")


@app.get("/orders")
def orders():
    if not session.get("uid"): return redirect("/login")
    rows = run("SELECT id, item, total FROM orders WHERE user_id=?", (session["uid"],))
    tr = "".join(f'<tr><td><a href="/order?id={i}">#{i}</a></td><td>{esc(n)}</td><td>{money(t)}</td></tr>' for i, n, t in rows)
    return page("Orders", f'<div class="card"><h2>Your orders</h2><table><tr><th>Order</th><th>Item</th><th>Total</th></tr>{tr}</table></div>')


@app.get("/order")
def order():
    if not session.get("uid"): return redirect("/login")
    r = run("SELECT id, item, total, address FROM orders WHERE id=?", (request.args.get("id", 0),))   # VULN: IDOR (no ownership check)
    if not r: return page("Order", '<div class="err">Order not found.</div>'), 404
    i, n, t, a = r[0]
    return page("Order", f'<div class="card"><h2>Order #{i}</h2><p>{esc(n)} · {money(t)}</p><p class="muted">Ship to: {esc(a)}</p></div>')


@app.get("/.git/config")
def exposed_git():
    return app.response_class("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://git.example.invalid/shopeasy.git   ; FAKE\n", mimetype="text/plain")   # VULN: exposed repository metadata


@app.get("/attack-guide")
def attack_guide():
    rows = [("SQL injection: data theft (UNION)", "A03 Injection", "/search?q=%27%20UNION%20SELECT%20id%2Cusername%2Cpassword%2Crole%20FROM%20users--", "Product grid shows usernames and passwords", "403"),
            ("SQL injection: numeric", "A03 Injection", "/product?id=1%20OR%201%3D1", "Query altered without any quote characters", "403"),
            ("SQL injection: login bypass", "A03 Injection", "/login", "POST username  shopadmin'--  → signed in", "403"),
            ("Reflected XSS", "A03 Injection", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "Script runs in the page", "403"),
            ("Stored XSS", "A03 Injection", "/product?id=1", "POST review  <img src=x onerror=alert(1)>  → runs for every visitor", "403 on the POST"),
            ("Exposed repository metadata", "A02 Misconfiguration", "/.git/config", "Returns the (fake) git config: a classic leftover file", "403: CRS blocks restricted-file probes (the configuration scanner also reports it)"),
            ("Insecure direct object reference", "A01 Access control", "/order?id=3", "Shows another customer's order (sign in as carol)", "NOT blocked: application must check ownership."),
            ("Price tampering", "A04 Insecure design", "/product?id=1", "Edit hidden field total=0.01 and press Buy", "NOT blocked: business logic. Server must price orders itself.")]
    return page("Attack guide", guide(rows, "ShopEasy contains textbook flaws so you can see what a web application firewall stops, and what it cannot."))


@app.post("/__reset")
def reset(): seed(); session.clear(); return redirect("/")
