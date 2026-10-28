"""ZenithBank: DELIBERATELY VULNERABLE training app (fake data). Each weakness is marked `# VULN:`."""
import posixpath, sqlite3, threading, traceback
from flask import Flask, request, session, redirect, Response
from markupsafe import escape as esc
from common import log_request, shell, money, guide

app = Flask("bank"); app.secret_key = "demo-not-a-secret"
BRAND, ACCENT = "ZenithBank", "#0f4c81"
NAV = [("Accounts", "/dashboard"), ("Transactions", "/transactions"), ("Transfer", "/transfer"), ("Statements", "/statements"), ("Feedback", "/feedback"), ("Attack guide", "/attack-guide")]
FILES = {"/srv/bank/statements/statement-2026-09.txt": "ZENITHBANK STATEMENT 2026-09\nOpening balance 4,200.00\nClosing balance 4,980.25\n",
         "/srv/bank/statements/statement-2026-08.txt": "ZENITHBANK STATEMENT 2026-08\nOpening balance 3,900.00\nClosing balance 4,200.00\n",
         "/etc/passwd": "root:x:0:0:FAKE-root:/root:/bin/false\nbankapp:x:1000:1000:FAKE-service-account:/srv/bank:/bin/false\n",
         "/srv/bank/config/app.conf": "db_password=FAKE-NOT-REAL\napi_key=FAKE-0000-NOT-REAL\n"}   # fake files; the traversal only ever reaches this dict
_db, _l = None, threading.RLock()


def seed():
    global _db
    db = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
    db.executescript("""
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, full_name TEXT, role TEXT);
    CREATE TABLE accounts(id INTEGER PRIMARY KEY, user_id INT, number TEXT, type TEXT, balance REAL);
    CREATE TABLE transactions(id INTEGER PRIMARY KEY, account_id INT, date TEXT, description TEXT, amount REAL);
    CREATE TABLE feedback(id INTEGER PRIMARY KEY, name TEXT, message TEXT);
    INSERT INTO users VALUES(1,'alice','alice123','Alice Morgan','customer'),(2,'bob','bob12345','Bob Carter','customer'),(3,'admin','Adm1n!demo','Bank Administrator','admin');
    INSERT INTO accounts VALUES(1,1,'ZB-1001-0001','Checking',4980.25),(2,1,'ZB-1001-0002','Savings',12500.00),(3,2,'ZB-2002-0001','Checking',830.10),(4,3,'ZB-9000-0001','Operations',250000.00);
    INSERT INTO transactions VALUES(1,1,'2026-10-20','Salary - Acme Corp',3200),(2,1,'2026-10-21','Grocery Mart',-84.30),(3,1,'2026-10-22','Electric utility',-61.45),
      (4,1,'2026-10-23','Coffee House',-4.80),(5,2,'2026-10-01','Interest',12.50),(6,3,'2026-10-19','Rent payment',-950),(7,3,'2026-10-20','Salary - Globex',1800);
    INSERT INTO feedback VALUES(1,'Priya','Love the new mobile app!'),(2,'Tom','Branch staff were very helpful.');""")
    _db = db


seed()


def run(sql, args=()):
    with _l: return _db.execute(sql, args).fetchall()


def uid(): return session.get("uid")
def page(title, body): return shell(BRAND, ACCENT, NAV, title, body, session.get("name"))
def need_login(): return redirect("/login")


@app.before_request
def _log(): log_request()


@app.get("/")
def home():
    return page("Welcome", '<div class="hero"><h1>Banking made simple.</h1><p>Check balances, move money and download statements, securely, anywhere.</p><a class="btn" style="background:#fff;color:#0f4c81" href="/login">Sign in</a></div>'
                '<div class="grid"><div class="card"><h2>Accounts</h2><p class="muted">Checking and savings in one place.</p></div><div class="card"><h2>Transfers</h2><p class="muted">Send money in seconds.</p></div><div class="card"><h2>Statements</h2><p class="muted">Download monthly statements.</p></div></div>'
                '<p class="muted">Demo logins: alice / alice123 · bob / bob12345</p>')


@app.route("/login", methods=["GET", "POST"])
def login():
    err = ""
    if request.method == "POST":
        u, p = request.form.get("username", ""), request.form.get("password", "")
        sql = "SELECT id, username, full_name, role FROM users WHERE username='%s' AND password='%s'" % (u, p)   # VULN: SQL injection (string-built query)
        try:
            rows = run(sql)
            if rows:
                session["uid"], session["name"] = rows[0][0], rows[0][2]
                return redirect("/dashboard")
            err = "Invalid username or password."
        except sqlite3.Error as e:
            err = "Database error: %s<br><code>%s</code>" % (esc(e), esc(sql))   # VULN: verbose error leaks the query
    return page("Sign in", f'<div class="card" style="max-width:420px;margin:auto"><h2>Sign in</h2>{"<div class=err>"+err+"</div>" if err else ""}'
                '<form method="post"><label>Username<input name="username" autofocus></label><label>Password<input name="password" type="password"></label><button>Sign in</button></form></div>')


@app.get("/logout")
def logout(): session.clear(); return redirect("/")


@app.get("/dashboard")
def dashboard():
    if not uid(): return need_login()
    rows = run("SELECT id, number, type, balance FROM accounts WHERE user_id=?", (uid(),))
    cards = "".join(f'<div class="card"><span class="tag">{esc(t)}</span><div class="muted">{esc(n)}</div><div class="big">{money(b)}</div><a href="/account?id={i}">View account</a></div>' for i, n, t, b in rows)
    return page("Accounts", f'<h2>Welcome back, {esc(session["name"])}</h2><div class="grid">{cards}</div>')


@app.get("/account")
def account():
    if not uid(): return need_login()
    r = run("SELECT a.id,a.number,a.type,a.balance,u.full_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.id=?", (request.args.get("id", 0),))   # VULN: no ownership check (IDOR / broken access control)
    if not r: return page("Account", '<div class="err">Account not found.</div>'), 404
    i, n, t, b, owner = r[0]
    tx = "".join(f"<tr><td>{esc(d)}</td><td>{esc(ds)}</td><td>{money(a)}</td></tr>" for d, ds, a in run("SELECT date, description, amount FROM transactions WHERE account_id=? ORDER BY date DESC", (i,)))
    return page("Account", f'<div class="card"><span class="tag">{esc(t)}</span> <b>{esc(n)}</b><div class="muted">Owner: {esc(owner)}</div><div class="big">{money(b)}</div></div><div class="card"><table><tr><th>Date</th><th>Description</th><th>Amount</th></tr>{tx}</table></div>')


@app.get("/transactions")
def transactions():
    if not uid(): return need_login()
    term, err, rows = request.args.get("q", ""), "", []
    sql = ("SELECT date, description, amount FROM transactions WHERE account_id IN (SELECT id FROM accounts WHERE user_id=%d) "
           "AND description LIKE '%%%s%%' ORDER BY date DESC" % (uid(), term))   # VULN: SQL injection (UNION-based data theft works)
    try: rows = run(sql)
    except sqlite3.Error as e: err = f'<div class="err">Database error: {esc(e)}</div>'
    head = f'<p class="muted">Results for: {term}</p>' if term else ""   # VULN: reflected XSS (unescaped input)
    tr = "".join(f"<tr><td>{d}</td><td>{ds}</td><td>{a}</td></tr>" for d, ds, a in rows)   # VULN: stored XSS (descriptions are unescaped)
    return page("Transactions", f'<div class="card"><h2>Search transactions</h2><form><input name="q" value="{esc(term)}" placeholder="e.g. coffee"><button>Search</button></form>{head}{err}<table><tr><th>Date</th><th>Description</th><th>Amount</th></tr>{tr}</table></div>')


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not uid(): return need_login()
    msg = ""
    if request.method == "POST":
        try:
            frm, to, amt, memo = int(request.form["from_id"]), request.form["to_number"], float(request.form["amount"]), request.form.get("memo", "")
        except (KeyError, ValueError):
            frm = None
        if frm is None or not run("SELECT 1 FROM accounts WHERE id=?", (frm,)): msg = '<div class="err">Invalid transfer details.</div>'
        else:   # VULN: no ownership check on the source account, no CSRF token, negative amounts accepted (business-logic flaws a WAF cannot see)
            with _l:
                _db.execute("UPDATE accounts SET balance=balance-? WHERE id=?", (amt, frm))
                _db.execute("UPDATE accounts SET balance=balance+? WHERE number=?", (amt, to))
                _db.execute("INSERT INTO transactions(account_id,date,description,amount) VALUES(?, '2026-10-25', ?, ?)", (frm, "Transfer to %s: %s" % (to, memo), -amt))
            msg = f'<div class="ok">Transferred {money(amt)} to {esc(to)}.</div>'
    opts = "".join(f'<option value="{i}">{esc(n)} ({esc(t)})</option>' for i, n, t in run("SELECT id, number, type FROM accounts WHERE user_id=?", (uid(),)))
    return page("Transfer", f'<div class="card" style="max-width:520px"><h2>Transfer money</h2>{msg}<form method="post"><label>From<select name="from_id">{opts}</select></label>'
                '<label>To account number<input name="to_number" value="ZB-2002-0001"></label><label>Amount<input name="amount" value="25.00"></label><label>Memo<input name="memo"></label><button>Send</button></form></div>')


@app.get("/statements")
def statements():
    if not uid(): return need_login()
    li = "".join(f'<li><a href="/statement?file={f}">{f}</a></li>' for f in ("statement-2026-09.txt", "statement-2026-08.txt"))
    return page("Statements", f'<div class="card"><h2>Monthly statements</h2><ul>{li}</ul></div>')


@app.get("/statement")
def statement():
    if not uid(): return need_login()
    path = posixpath.normpath("/srv/bank/statements/" + request.args.get("file", ""))   # VULN: path traversal (../ escapes the statements folder)
    if path in FILES: return Response(FILES[path], mimetype="text/plain")
    return Response("No such statement.", status=404, mimetype="text/plain")


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        with _l: _db.execute("INSERT INTO feedback(name, message) VALUES(?,?)", (request.form.get("name", "anon")[:60], request.form.get("message", "")[:500]))
        return redirect("/feedback")
    items = "".join(f'<div class="card"><b>{n}</b><br>{m}</div>' for n, m in run("SELECT name, message FROM feedback ORDER BY id DESC"))   # VULN: stored XSS
    return page("Feedback", f'<div class="card" style="max-width:520px"><h2>Leave feedback</h2><form method="post"><label>Name<input name="name"></label><label>Message<textarea name="message" rows="3"></textarea></label><button>Post</button></form></div>{items}')


@app.get("/report")
def report():
    if not uid(): return need_login()
    n = int(request.args.get("id", "1"))      # VULN: unhandled error for non-numbers; the handler below prints a stack trace
    return page("Report", f'<div class="card"><h2>Monthly report #{n}</h2><p class="muted">No activity.</p></div>')


@app.errorhandler(Exception)
def _boom(e):
    return Response("Internal error\n\n" + traceback.format_exc(), status=500, mimetype="text/plain")   # VULN: leaks stack trace and file paths


@app.get("/attack-guide")
def attack_guide():
    q = "%27%20UNION%20SELECT%20username%2Cpassword%2C0%20FROM%20users--"
    rows = [("SQL injection: login bypass", "A03 Injection", "/login", "POST username  admin'--  with any password → signed in as admin", "403 before the form is processed"),
            ("SQL injection: data theft (UNION)", "A03 Injection", f"/transactions?q={q}", "Table lists every username and password (sign in first)", "403"),
            ("Reflected XSS", "A03 Injection", "/transactions?q=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E", "Script runs in the page (sign in first)", "403"),
            ("Stored XSS", "A03 Injection", "/feedback", "POST message  <img src=x onerror=alert(1)>  → runs for every visitor", "403 on the POST"),
            ("Path traversal", "A01 Access control", "/statement?file=../../../etc/passwd", "Returns (fake) system file (sign in first)", "403"),
            ("Verbose error / stack trace", "A10 Exceptional conditions", "/report?id=abc", "Visitor sees a Python stack trace with file paths (sign in first)", "Not a rule match: CyberGuard's generic error pages replace the 500 body with a plain message"),
            ("Insecure direct object reference", "A01 Access control", "/account?id=3", "Shows another customer's account (sign in as alice)", "NOT blocked: a WAF cannot know who owns what. Fix in application code."),
            ("Transfer from someone else's account / negative amount", "A04 Insecure design", "/transfer", "POST from_id=3 or amount=-500 succeeds", "NOT blocked: business-logic flaw. Fix in application code.")]
    return page("Attack guide", guide(rows, "ZenithBank contains textbook flaws so you can see what a web application firewall stops, and what it cannot."))


@app.post("/__reset")
def reset(): seed(); session.clear(); return redirect("/")
