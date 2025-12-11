"""
Vulnerable Test Server for PennyWise.
Provides intentionally vulnerable endpoints for testing the scanner.

WARNING: This is for testing purposes only. Never expose this to the internet!
"""

from aiohttp import web
import aiohttp_jinja2
import jinja2
import sqlite3
import os
import asyncio
from pathlib import Path

# Create a simple SQLite database for testing
DB_PATH = Path(__file__).parent / "test_vulns.db"


def init_database():
    """Initialize the test database with sample data."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            category TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert sample data
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        users = [
            ('admin', 'admin123', 'admin@test.com', 'admin'),
            ('user1', 'password1', 'user1@test.com', 'user'),
            ('user2', 'password2', 'user2@test.com', 'user'),
            ('guest', 'guest', 'guest@test.com', 'guest'),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            users
        )
        
        products = [
            ('Laptop', 'High performance laptop', 999.99, 'electronics'),
            ('Phone', 'Smartphone with great camera', 699.99, 'electronics'),
            ('Book', 'Programming guide', 49.99, 'books'),
            ('Headphones', 'Wireless headphones', 199.99, 'electronics'),
        ]
        cursor.executemany(
            "INSERT INTO products (name, description, price, category) VALUES (?, ?, ?, ?)",
            products
        )
        
        comments = [
            (1, 'This is a test comment'),
            (2, 'Another comment here'),
            (1, '<script>alert("stored xss")</script>'),
        ]
        cursor.executemany(
            "INSERT INTO comments (user_id, content) VALUES (?, ?)",
            comments
        )
    
    conn.commit()
    conn.close()


# HTML Templates for vulnerable pages
TEMPLATES = {
    'index': '''
<!DOCTYPE html>
<html>
<head>
    <title>PennyWise Test Server - Vulnerable Sandbox</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }
        h1 { color: #00d4ff; }
        .container { max-width: 800px; margin: 0 auto; }
        .endpoint { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #00d4ff; }
        .endpoint h3 { margin: 0 0 10px 0; color: #00d4ff; }
        .endpoint p { margin: 5px 0; color: #aaa; }
        .vuln-type { background: #e94560; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        a { color: #00d4ff; }
        .warning { background: #e94560; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎪 PennyWise Vulnerable Sandbox</h1>
        <div class="warning">
            ⚠️ <strong>WARNING:</strong> This server contains intentional security vulnerabilities for testing purposes only.
            Never expose this to the internet!
        </div>
        
        <h2>Available Vulnerable Endpoints:</h2>
        
        <div class="endpoint">
            <h3>SQL Injection Test</h3>
            <span class="vuln-type">SQLi</span>
            <p>Test SQL injection vulnerabilities</p>
            <p><a href="/sandbox/sqli?id=1">/sandbox/sqli?id=1</a></p>
            <p><a href="/sandbox/sqli/search?q=laptop">/sandbox/sqli/search?q=laptop</a></p>
            <p><a href="/sandbox/sqli/login">/sandbox/sqli/login</a> (POST form)</p>
        </div>
        
        <div class="endpoint">
            <h3>XSS Test</h3>
            <span class="vuln-type">XSS</span>
            <p>Test Cross-Site Scripting vulnerabilities</p>
            <p><a href="/sandbox/xss/reflected?name=test">/sandbox/xss/reflected?name=test</a></p>
            <p><a href="/sandbox/xss/stored">/sandbox/xss/stored</a> (Stored XSS in comments)</p>
            <p><a href="/sandbox/xss/dom">/sandbox/xss/dom</a> (DOM-based XSS)</p>
        </div>
        
        <div class="endpoint">
            <h3>CSRF Test</h3>
            <span class="vuln-type">CSRF</span>
            <p>Test Cross-Site Request Forgery vulnerabilities</p>
            <p><a href="/sandbox/csrf/transfer">/sandbox/csrf/transfer</a> (No CSRF protection)</p>
        </div>
        
        <div class="endpoint">
            <h3>Authentication Test</h3>
            <span class="vuln-type">AUTH</span>
            <p>Test authentication vulnerabilities</p>
            <p><a href="/sandbox/auth/login">/sandbox/auth/login</a> (Weak auth)</p>
            <p><a href="/sandbox/auth/admin">/sandbox/auth/admin</a> (Broken access control)</p>
        </div>
        
        <div class="endpoint">
            <h3>IDOR Test</h3>
            <span class="vuln-type">IDOR</span>
            <p>Test Insecure Direct Object Reference</p>
            <p><a href="/sandbox/idor/user?id=1">/sandbox/idor/user?id=1</a></p>
            <p><a href="/sandbox/idor/document?doc_id=1">/sandbox/idor/document?doc_id=1</a></p>
        </div>
        
        <div class="endpoint">
            <h3>Command Injection Test</h3>
            <span class="vuln-type">RCE</span>
            <p>Test command injection vulnerabilities</p>
            <p><a href="/sandbox/rce/ping?host=localhost">/sandbox/rce/ping?host=localhost</a></p>
        </div>
    </div>
</body>
</html>
''',

    'sqli_result': '''
<!DOCTYPE html>
<html>
<head><title>Product Details</title>
<style>body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}.product{{background:#16213e;padding:20px;border-radius:8px;}}</style>
</head>
<body>
    <h1>Product Details</h1>
    <div class="product">
        <p><strong>ID:</strong> {id}</p>
        <p><strong>Name:</strong> {name}</p>
        <p><strong>Description:</strong> {description}</p>
        <p><strong>Price:</strong> ${price}</p>
    </div>
    <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
</body>
</html>
''',

    'sqli_search': '''
<!DOCTYPE html>
<html>
<head><title>Search Results</title>
<style>body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}.results{{background:#16213e;padding:20px;border-radius:8px;}}</style>
</head>
<body>
    <h1>Search Results for: {query}</h1>
    <div class="results">
        {results}
    </div>
    <form action="/sandbox/sqli/search" method="GET">
        <input type="text" name="q" placeholder="Search products..." style="padding:10px;width:300px;">
        <button type="submit" style="padding:10px 20px;">Search</button>
    </form>
    <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
</body>
</html>
''',

    'sqli_login': '''
<!DOCTYPE html>
<html>
<head><title>Login</title>
<style>
body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}
.login-form{{background:#16213e;padding:30px;border-radius:8px;max-width:400px;}}
input{{display:block;margin:10px 0;padding:10px;width:100%;box-sizing:border-box;}}
button{{padding:10px 20px;background:#00d4ff;border:none;cursor:pointer;}}
.error{{color:#e94560;}}
.success{{color:#00ff88;}}
</style>
</head>
<body>
    <h1>Login (SQLi Vulnerable)</h1>
    <div class="login-form">
        <form action="/sandbox/sqli/login" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        {message}
    </div>
    <p style="margin-top:20px;color:#888;">Try: username = admin' -- and any password</p>
    <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
</body>
</html>
''',

    'xss_reflected': '''
<!DOCTYPE html>
<html>
<head><title>Welcome</title>
<style>body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}</style>
</head>
<body>
    <h1>Welcome, {name}!</h1>
    <form action="/sandbox/xss/reflected" method="GET">
        <input type="text" name="name" placeholder="Enter your name" style="padding:10px;">
        <button type="submit" style="padding:10px 20px;">Submit</button>
    </form>
    <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
</body>
</html>
''',

    'xss_stored': '''
<!DOCTYPE html>
<html>
<head><title>Comments</title>
<style>
body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}
.comment{{background:#16213e;padding:15px;margin:10px 0;border-radius:8px;}}
textarea{{width:100%;padding:10px;height:100px;}}
button{{padding:10px 20px;background:#00d4ff;border:none;cursor:pointer;margin-top:10px;}}
</style>
</head>
<body>
    <h1>Comments (Stored XSS)</h1>
    <div class="comments">
        {comments}
    </div>
    <h3>Add a comment:</h3>
    <form action="/sandbox/xss/stored" method="POST">
        <textarea name="comment" placeholder="Write your comment..."></textarea>
        <button type="submit">Post Comment</button>
    </form>
    <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
</body>
</html>
''',

    'xss_dom': '''
<!DOCTYPE html>
<html>
<head><title>DOM XSS Test</title>
<style>body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}</style>
</head>
<body>
    <h1>DOM-based XSS Test</h1>
    <div id="output"></div>
    <form onsubmit="return false;">
        <input type="text" id="userInput" placeholder="Enter text" style="padding:10px;">
        <button onclick="updateOutput()" style="padding:10px 20px;">Update</button>
    </form>
    <script>
        // Vulnerable: Using innerHTML with user input from URL hash
        var hash = window.location.hash.substring(1);
        if(hash) {
            document.getElementById('output').innerHTML = decodeURIComponent(hash);
        }
        
        function updateOutput() {
            var input = document.getElementById('userInput').value;
            // Vulnerable: Direct innerHTML assignment
            document.getElementById('output').innerHTML = input;
        }
    </script>
    <p style="margin-top:20px;color:#888;">Try: /sandbox/xss/dom#&lt;img src=x onerror=alert(1)&gt;</p>
    <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
</body>
</html>
''',

    'csrf_transfer': '''
<!DOCTYPE html>
<html>
<head><title>Money Transfer</title>
<style>
body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}
.form{{background:#16213e;padding:30px;border-radius:8px;max-width:400px;}}
input{{display:block;margin:10px 0;padding:10px;width:100%;box-sizing:border-box;}}
button{{padding:10px 20px;background:#00d4ff;border:none;cursor:pointer;}}
.success{{color:#00ff88;background:#16213e;padding:15px;border-radius:8px;}}
</style>
</head>
<body>
    <h1>Money Transfer (No CSRF Protection)</h1>
    <div class="form">
        <form action="/sandbox/csrf/transfer" method="POST">
            <input type="text" name="to_account" placeholder="Recipient Account" required>
            <input type="number" name="amount" placeholder="Amount" required>
            <button type="submit">Transfer</button>
        </form>
        {message}
    </div>
    <p style="margin-top:20px;color:#888;">This form has no CSRF token protection!</p>
    <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
</body>
</html>
''',

    'auth_login': '''
<!DOCTYPE html>
<html>
<head><title>Auth Login</title>
<style>
body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}
.form{{background:#16213e;padding:30px;border-radius:8px;max-width:400px;}}
input{{display:block;margin:10px 0;padding:10px;width:100%;box-sizing:border-box;}}
button{{padding:10px 20px;background:#00d4ff;border:none;cursor:pointer;}}
</style>
</head>
<body>
    <h1>Login (Weak Auth)</h1>
    <div class="form">
        <form action="/sandbox/auth/login" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        {message}
    </div>
    <p style="margin-top:20px;color:#888;">Hint: admin/admin123, user1/password1</p>
    <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
</body>
</html>
''',

    'idor_user': '''
<!DOCTYPE html>
<html>
<head><title>User Profile</title>
<style>body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}.profile{{background:#16213e;padding:20px;border-radius:8px;}}</style>
</head>
<body>
    <h1>User Profile (IDOR Vulnerable)</h1>
    <div class="profile">
        <p><strong>ID:</strong> {id}</p>
        <p><strong>Username:</strong> {username}</p>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Role:</strong> {role}</p>
    </div>
    <p style="margin-top:20px;color:#888;">Try changing the id parameter to access other users!</p>
    <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
</body>
</html>
'''
}


# Route Handlers
async def sandbox_index(request):
    """Main sandbox index page."""
    return web.Response(text=TEMPLATES['index'], content_type='text/html')


async def sqli_product(request):
    """SQL Injection vulnerable endpoint - product lookup."""
    product_id = request.query.get('id', '1')
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT id, name, description, price FROM products WHERE id = {product_id}"
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()
        
        if result:
            html = TEMPLATES['sqli_result'].format(
                id=result[0],
                name=result[1],
                description=result[2],
                price=result[3]
            )
        else:
            html = f"<h1>Product not found</h1><p>Query: {query}</p>"
    except Exception as e:
        # VULNERABLE: Exposing SQL errors
        html = f"<h1>Database Error</h1><pre>SQL Error: {str(e)}\nQuery: {query}</pre>"
    
    conn.close()
    return web.Response(text=html, content_type='text/html')


async def sqli_search(request):
    """SQL Injection vulnerable endpoint - search."""
    query_param = request.query.get('q', '')
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{query_param}%'"
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        
        results_html = ""
        for row in results:
            results_html += f"<p>ID: {row[0]} | {row[1]} - ${row[2]}</p>"
        
        if not results_html:
            results_html = "<p>No products found</p>"
        
        html = TEMPLATES['sqli_search'].format(query=query_param, results=results_html)
    except Exception as e:
        html = f"<h1>Database Error</h1><pre>SQL Error: {str(e)}\nQuery: {query}</pre>"
    
    conn.close()
    return web.Response(text=html, content_type='text/html')


async def sqli_login(request):
    """SQL Injection vulnerable login."""
    if request.method == 'POST':
        data = await request.post()
        username = data.get('username', '')
        password = data.get('password', '')
        
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        # VULNERABLE: SQL Injection in login
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                message = f'<p class="success">Login successful! Welcome, {user[1]} (Role: {user[4]})</p>'
            else:
                message = '<p class="error">Invalid credentials</p>'
        except Exception as e:
            message = f'<p class="error">SQL Error: {str(e)}</p>'
        
        conn.close()
        return web.Response(
            text=TEMPLATES['sqli_login'].format(message=message),
            content_type='text/html'
        )
    
    return web.Response(
        text=TEMPLATES['sqli_login'].format(message=''),
        content_type='text/html'
    )


async def xss_reflected(request):
    """Reflected XSS vulnerable endpoint."""
    name = request.query.get('name', 'Guest')
    
    # VULNERABLE: No sanitization of user input
    html = TEMPLATES['xss_reflected'].format(name=name)
    return web.Response(text=html, content_type='text/html')


async def xss_stored(request):
    """Stored XSS vulnerable endpoint."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    if request.method == 'POST':
        data = await request.post()
        comment = data.get('comment', '')
        
        # VULNERABLE: Storing unsanitized user input
        cursor.execute("INSERT INTO comments (user_id, content) VALUES (1, ?)", (comment,))
        conn.commit()
    
    # Fetch and display comments without sanitization
    cursor.execute("SELECT content FROM comments ORDER BY id DESC")
    comments = cursor.fetchall()
    
    # VULNERABLE: Rendering unsanitized content
    comments_html = ""
    for (content,) in comments:
        comments_html += f'<div class="comment">{content}</div>'
    
    conn.close()
    return web.Response(
        text=TEMPLATES['xss_stored'].format(comments=comments_html),
        content_type='text/html'
    )


async def xss_dom(request):
    """DOM-based XSS vulnerable endpoint."""
    return web.Response(text=TEMPLATES['xss_dom'], content_type='text/html')


async def csrf_transfer(request):
    """CSRF vulnerable endpoint - no token protection."""
    message = ''
    
    if request.method == 'POST':
        data = await request.post()
        to_account = data.get('to_account', '')
        amount = data.get('amount', '')
        
        # VULNERABLE: No CSRF token validation
        message = f'<div class="success">Transfer of ${amount} to account {to_account} completed!</div>'
    
    return web.Response(
        text=TEMPLATES['csrf_transfer'].format(message=message),
        content_type='text/html'
    )


async def auth_login(request):
    """Weak authentication endpoint."""
    message = ''
    
    if request.method == 'POST':
        data = await request.post()
        username = data.get('username', '')
        password = data.get('password', '')
        
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        # Using parameterized query here, but password is stored in plaintext
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        
        if user:
            # VULNERABLE: Setting insecure cookie
            response = web.Response(
                text=TEMPLATES['auth_login'].format(message=f'<p class="success">Welcome {user[1]}!</p>'),
                content_type='text/html'
            )
            response.set_cookie('session', f'user={user[1]};role={user[4]}', httponly=False)
            conn.close()
            return response
        else:
            message = '<p class="error">Invalid credentials</p>'
        
        conn.close()
    
    return web.Response(
        text=TEMPLATES['auth_login'].format(message=message),
        content_type='text/html'
    )


async def auth_admin(request):
    """Broken access control endpoint."""
    # VULNERABLE: No proper access control check
    session = request.cookies.get('session', '')
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head><title>Admin Panel</title>
    <style>body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}</style>
    </head>
    <body>
        <h1>Admin Panel (Broken Access Control)</h1>
        <p>Session: {session}</p>
        <p style="color:#00ff88;">You have accessed the admin panel!</p>
        <p>This page should require proper authentication and authorization.</p>
        <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
    </body>
    </html>
    '''.format(session=session)
    
    return web.Response(text=html, content_type='text/html')


async def idor_user(request):
    """IDOR vulnerable endpoint - user profile."""
    user_id = request.query.get('id', '1')
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # VULNERABLE: No access control, any user ID can be accessed
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if user:
        html = TEMPLATES['idor_user'].format(
            id=user[0],
            username=user[1],
            email=user[2],
            role=user[3]
        )
    else:
        html = "<h1>User not found</h1>"
    
    conn.close()
    return web.Response(text=html, content_type='text/html')


async def idor_document(request):
    """IDOR vulnerable endpoint - document access."""
    doc_id = request.query.get('doc_id', '1')
    
    # VULNERABLE: No access control check
    documents = {
        '1': {'title': 'Public Document', 'content': 'This is a public document.'},
        '2': {'title': 'Private Report', 'content': 'SECRET: Q4 earnings report...'},
        '3': {'title': 'Confidential Data', 'content': 'Employee SSN: 123-45-6789...'},
    }
    
    doc = documents.get(doc_id, {'title': 'Not Found', 'content': 'Document not found'})
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>{doc["title"]}</title>
    <style>body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}.doc{{background:#16213e;padding:20px;border-radius:8px;}}</style>
    </head>
    <body>
        <h1>{doc["title"]}</h1>
        <div class="doc"><p>{doc["content"]}</p></div>
        <p style="margin-top:20px;color:#888;">Try: doc_id=2 or doc_id=3</p>
        <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
    </body>
    </html>
    '''
    
    return web.Response(text=html, content_type='text/html')


async def rce_ping(request):
    """Command injection vulnerable endpoint."""
    host = request.query.get('host', 'localhost')
    
    # VULNERABLE: Command injection
    import subprocess
    
    try:
        # VULNERABLE: Direct command execution with user input
        result = subprocess.run(
            f'ping -n 1 {host}' if os.name == 'nt' else f'ping -c 1 {host}',
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>Ping Tool</title>
    <style>body{{font-family:Arial;margin:40px;background:#1a1a2e;color:#eee;}}pre{{background:#16213e;padding:20px;border-radius:8px;overflow:auto;}}</style>
    </head>
    <body>
        <h1>Network Ping Tool (Command Injection)</h1>
        <form action="/sandbox/rce/ping" method="GET">
            <input type="text" name="host" value="{host}" style="padding:10px;width:300px;">
            <button type="submit" style="padding:10px 20px;">Ping</button>
        </form>
        <pre>{output}</pre>
        <p style="color:#888;">Try: localhost & whoami</p>
        <p><a href="/sandbox" style="color:#00d4ff;">← Back</a></p>
    </body>
    </html>
    '''
    
    return web.Response(text=html, content_type='text/html')


def create_sandbox_app() -> web.Application:
    """Create the vulnerable sandbox application."""
    app = web.Application()
    
    # Initialize database
    init_database()
    
    # Add routes
    app.router.add_get('/sandbox', sandbox_index)
    app.router.add_get('/sandbox/', sandbox_index)
    
    # SQL Injection routes
    app.router.add_get('/sandbox/sqli', sqli_product)
    app.router.add_get('/sandbox/sqli/search', sqli_search)
    app.router.add_get('/sandbox/sqli/login', sqli_login)
    app.router.add_post('/sandbox/sqli/login', sqli_login)
    
    # XSS routes
    app.router.add_get('/sandbox/xss/reflected', xss_reflected)
    app.router.add_get('/sandbox/xss/stored', xss_stored)
    app.router.add_post('/sandbox/xss/stored', xss_stored)
    app.router.add_get('/sandbox/xss/dom', xss_dom)
    
    # CSRF routes
    app.router.add_get('/sandbox/csrf/transfer', csrf_transfer)
    app.router.add_post('/sandbox/csrf/transfer', csrf_transfer)
    
    # Auth routes
    app.router.add_get('/sandbox/auth/login', auth_login)
    app.router.add_post('/sandbox/auth/login', auth_login)
    app.router.add_get('/sandbox/auth/admin', auth_admin)
    
    # IDOR routes
    app.router.add_get('/sandbox/idor/user', idor_user)
    app.router.add_get('/sandbox/idor/document', idor_document)
    
    # RCE routes
    app.router.add_get('/sandbox/rce/ping', rce_ping)
    
    return app


async def run_sandbox_server(host: str = '127.0.0.1', port: int = 8888):
    """Run the vulnerable sandbox server."""
    app = create_sandbox_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    
    print(f"\n🎪 PennyWise Vulnerable Sandbox running at http://{host}:{port}/sandbox")
    print("⚠️  WARNING: This server contains intentional vulnerabilities. For testing only!\n")
    
    await site.start()
    
    # Keep running
    while True:
        await asyncio.sleep(3600)


if __name__ == '__main__':
    asyncio.run(run_sandbox_server())
