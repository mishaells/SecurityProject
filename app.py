"""
Secure Web Application - Security Vulnerabilities Demo & Mitigation
====================================================================
This app demonstrates common web security vulnerabilities and their fixes.
Each section is clearly labeled with VULNERABLE and SECURE versions.
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib  # Used for INSECURE MD5 hashing (demonstration only)
import bcrypt   # Used for SECURE password hashing
import bleach   # Used for XSS input sanitization
import os
import ssl

app = Flask(__name__)

# ============================================================
# SECRET KEY - Used to sign session cookies securely
# In production, this should be a long random string stored
# in an environment variable, never hardcoded
# ============================================================
app.secret_key = os.urandom(24)

# ============================================================
# COOKIE SECURITY FLAGS
# HttpOnly: JavaScript cannot read the session cookie
#           This protects against XSS stealing the session token
# Secure:   Cookie only sent over HTTPS, not plain HTTP
#           This protects against network eavesdropping
# SameSite: Helps prevent CSRF attacks
# ============================================================
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DATABASE = 'database.db'


# ============================================================
# DATABASE SETUP
# Creates tables for users and comments
# ============================================================
def init_db():
    """Initialize the SQLite database with users and comments tables."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Users table - stores user accounts and roles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')

    # Comments table - used to demonstrate XSS vulnerability
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        content TEXT NOT NULL,
        mode TEXT NOT NULL DEFAULT 'secure'
    )
''')

    # Create a default admin account for RBAC demonstration
    # Password: admin123 (hashed with bcrypt)
    admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('admin', admin_password.decode('utf-8'), 'admin')
        )
    except sqlite3.IntegrityError:
        pass  # Admin already exists

    conn.commit()
    conn.close()


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    """Home page - redirects to login if not logged in."""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# ------------------------------------------------------------
# REGISTRATION
# ------------------------------------------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration page.
    
    VULNERABLE version uses:
    - String concatenation in SQL (SQL Injection risk)
    - MD5 for password hashing (weak, easily cracked)
    
    SECURE version uses:
    - Parameterized queries (prevents SQL Injection)
    - bcrypt for password hashing (strong, slow, salted)
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        mode = request.form.get('mode', 'secure')  # 'vulnerable' or 'secure'

        conn = get_db()
        cursor = conn.cursor()

        if mode == 'vulnerable':
            # ================================================
            # VULNERABLE: MD5 hashing + string SQL (demo only)
            # MD5 is fast → attackers can crack billions/second
            # String SQL → attacker can manipulate the query
            # ================================================
            md5_password = hashlib.md5(password.encode()).hexdigest()
            try:
                # VULNERABLE SQL - string concatenation
                cursor.execute(
                    "INSERT INTO users (username, password) VALUES ('" +
                    username + "', '" + md5_password + "')"
                )
                conn.commit()
                flash('Registered (VULNERABLE mode - MD5 used!)', 'warning')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'danger')

        else:
            # ================================================
            # SECURE: bcrypt hashing + parameterized queries
            # bcrypt is slow by design → makes brute force hard
            # gensalt() adds random salt → same password = different hash
            # Parameterized queries → user input never touches SQL structure
            # ================================================
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            try:
                # SECURE SQL - parameterized query
                cursor.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hashed.decode('utf-8'))
                )
                conn.commit()
                flash('Registered successfully (SECURE mode - bcrypt used)!', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'danger')

        conn.close()

    return render_template('register.html')


# ------------------------------------------------------------
# LOGIN
# ------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page.

    VULNERABLE version:
    - Uses string-concatenated SQL → allows SQL Injection bypass
      Example payload: ' OR '1'='1 → logs in without real password

    SECURE version:
    - Uses parameterized queries
    - Verifies password with bcrypt.checkpw()
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        mode = request.form.get('mode', 'secure')

        conn = get_db()
        cursor = conn.cursor()

        if mode == 'vulnerable':
            # ================================================
            # VULNERABLE SQL INJECTION
            # If attacker enters: ' OR '1'='1' --
            # The query becomes:
            # SELECT * FROM users WHERE username='' OR '1'='1' --' AND password='...'
            # '1'='1' is always true → bypasses login!
            # ================================================
            md5_password = hashlib.md5(password.encode()).hexdigest()

            query = (
                "SELECT * FROM users WHERE username='" +
                username +
                "' AND password='" +
                md5_password +
                "'"
            )
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                    session['username'] = user['username']
                    session['role'] = user['role']
                    flash('Logged in (VULNERABLE mode)!', 'warning')
                    return redirect(url_for('dashboard'))
            
            flash('Invalid credentials.', 'danger')

        else:
            # ================================================
            # SECURE: Parameterized query + bcrypt verification
            # User input is passed as data, never as SQL code
            # Even if attacker types SQL, it's treated as plain text
            # ================================================
            cursor.execute(
                "SELECT * FROM users WHERE username=?",
                (username,)
            )
            user = cursor.fetchone()

            if user:
                # bcrypt.checkpw safely compares the password to stored hash
                stored_hash = user['password'].encode('utf-8')
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    session['username'] = user['username']
                    session['role'] = user['role']
                    flash('Logged in securely!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid credentials.', 'danger')
            else:
                flash('Invalid credentials.', 'danger')

        conn.close()

    return render_template('login.html')


# ------------------------------------------------------------
# DASHBOARD
# ------------------------------------------------------------

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    """
    Main dashboard - only accessible to logged-in users.
    Also demonstrates XSS vulnerability and fix via comments.

    VULNERABLE: Renders user comments as raw HTML → scripts execute
    SECURE: Sanitizes with bleach → scripts rendered as plain text
    """
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    # Handle new comment submission
    if request.method == 'POST':
        comment = request.form['comment']
        mode = request.form.get('mode', 'secure')

        if mode == 'vulnerable':
            cursor.execute(
                "INSERT INTO comments (username, content, mode) VALUES (?, ?, ?)",
                (session['username'], comment, 'vulnerable')
            )
            flash('Comment added (VULNERABLE - no sanitization)!', 'warning')

        else:
            clean_comment = bleach.clean(comment, tags=[], strip=True)
            cursor.execute(
                "INSERT INTO comments (username, content, mode) VALUES (?, ?, ?)",
                (session['username'], clean_comment, 'secure')
            )
            flash('Comment added safely (SECURE - sanitized)!', 'success')

        conn.commit()

    # Load all comments after POST or GET
    cursor.execute("SELECT * FROM comments WHERE username=?", (session['username'],))
    comments = cursor.fetchall()
    conn.close()

    return render_template('dashboard.html', comments=comments)
# ------------------------------------------------------------
# ADMIN PAGE - Access Control / RBAC Demo
# ------------------------------------------------------------

@app.route('/admin')
def admin():
    """
    Admin-only page to demonstrate Role-Based Access Control (RBAC).

    VULNERABLE: No check → any logged-in user can access /admin
    SECURE: Checks session role → only 'admin' role allowed
    
    To test vulnerability: log in as regular user and visit /admin
    To test fix: the role check below blocks non-admins
    """
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    # ================================================
    # SECURE ACCESS CONTROL CHECK
    # Without this, ANY logged-in user could access admin
    # With this, only users with role='admin' can proceed
    # ================================================
    if session.get('role') != 'admin':
        flash('Access denied! Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template('admin.html', users=users)


# ------------------------------------------------------------
# LOGOUT
# ------------------------------------------------------------

@app.route('/logout')
def logout():
    """Clear the session and log the user out."""
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


# ============================================================
# MAIN - Run with SSL for HTTPS (Encryption requirement)
# ssl_context='adhoc' generates a self-signed certificate
# In production: use a real certificate from Let's Encrypt
# ============================================================
if __name__ == '__main__':
    init_db()
    # Running with SSL enables HTTPS → all data encrypted in transit
    # This protects session tokens and passwords from network sniffing
    app.run(debug=True, ssl_context='adhoc', host='0.0.0.0', port=5000)
