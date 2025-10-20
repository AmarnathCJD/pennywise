# app.py
import os
import sqlite3
from flask import Flask, g, render_template, request, redirect, url_for

# database file relative to this script
DATABASE = os.path.join(os.path.dirname(__file__), 'xss_lab.db')
app = Flask(__name__)
app.secret_key = "dev-secret"  # only for local lab

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        # sqlite3.connect will create the DB file if it doesn't exist
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    """Create comments table if it doesn't exist."""
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        comment TEXT
    )
    """)
    db.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def home():
    return render_template('base.html')

# Reflected XSS example: search page reflects the 'q' parameter UNSAFELY
@app.route('/search')
def search():
    # NOTE: we intentionally render user input with |safe in template to demonstrate vulnerability
    q = request.args.get('q', '')
    results = [
        f"Result for {q} - item 1",
        f"Result for {q} - item 2"
    ]
    return render_template('search.html', q=q, results=results)

# Stored XSS example: comment posting -> persisted in SQLite, later rendered UNSAFELY
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    db = get_db()
    if request.method == 'POST':
        name = request.form.get('name', 'anon')
        comment = request.form.get('comment', '')
        # naive insert (no sanitization) to demonstrate stored XSS
        db.execute("INSERT INTO comments (name, comment) VALUES (?, ?)", (name, comment))
        db.commit()
        return redirect(url_for('comments'))
    cur = db.execute("SELECT id, name, comment FROM comments ORDER BY id DESC LIMIT 50")
    rows = cur.fetchall()
    return render_template('comments.html', comments=rows)

# DOM-based XSS demo page (client-side vulnerability)
@app.route('/dom')
def dom():
    # this page contains JS that will read location.hash and insert into DOM unsafely
    return render_template('dom.html')

if __name__ == '__main__':
    # Ensure DB directory exists (defensive)
    db_dir = os.path.dirname(DATABASE)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    # Initialize database inside app context to avoid decorator/lifecycle issues
    with app.app_context():
        init_db()

    # WARNING: only run in local dev environment. Do NOT enable debug=True on exposed systems.
    app.run(host='127.0.0.1', port=5000)
