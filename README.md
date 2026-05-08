# 🔒 Secure Web Application - Security Vulnerabilities Demo

A Flask web application that demonstrates and mitigates common web security vulnerabilities, built as a course project.

---

## 📋 Overview

This application implements a user management system (register, login, dashboard) and demonstrates **5 common security vulnerabilities** with both their vulnerable and secure versions side by side.

### Vulnerabilities Covered:
| # | Vulnerability | Status |
|---|---|---|
| 1 | SQL Injection | ✅ Demonstrated & Fixed |
| 2 | Weak Password Storage (MD5) | ✅ Demonstrated & Fixed |
| 3 | Cross-Site Scripting (XSS) | ✅ Demonstrated & Fixed |
| 4 | Broken Access Control (RBAC) | ✅ Demonstrated & Fixed |
| 5 | Encryption / HTTPS | ✅ Implemented |

---

## 🚀 How to Run

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/secure-web-app.git
cd secure-web-app
```

### 2. Install Dependencies
```bash
pip install flask bcrypt bleach pyopenssl
```

### 3. Run the Application
```bash
python app.py
```

### 4. Open in Browser
```
https://localhost:5000
```
> ⚠️ Your browser will warn about a self-signed certificate — click "Advanced" and proceed. This is expected in a local development environment.

### Default Admin Account:
- **Username:** admin
- **Password:** admin123

---

## 🧪 How to Test Each Security Feature

### 1. SQL Injection
1. Go to the **Login** page
2. Select **"Vulnerable"** mode
3. Enter username: `' OR '1'='1' --`
4. Enter any password
5. You will bypass login without valid credentials ⚠️
6. Switch to **"Secure"** mode — the same attack fails ✅

### 2. Weak Password Storage (MD5 vs bcrypt)
1. Go to the **Register** page
2. Register a user in **"Vulnerable"** mode (uses MD5)
3. Register another user in **"Secure"** mode (uses bcrypt)
4. Open `database.db` with any SQLite viewer
5. Compare the hashes — MD5 is short and crackable; bcrypt is long and salted ✅

### 3. XSS (Cross-Site Scripting)
1. Log in and go to the **Dashboard**
2. In the comments box, type: `<script>alert('XSS!')</script>`
3. Select **"Vulnerable"** mode → the script executes (alert pops up) ⚠️
4. Select **"Secure"** mode → the script is shown as plain text ✅

### 4. Access Control (RBAC)
1. Register a **regular user** account and log in
2. Manually visit: `https://localhost:5000/admin`
3. You will be blocked and redirected ✅
4. Log in as **admin / admin123**
5. Visit `/admin` — access granted ✅

### 5. Encryption / HTTPS
- The app runs over **HTTPS** using a self-signed SSL certificate
- All data (passwords, session tokens) is encrypted in transit
- Session cookies are set with `HttpOnly` and `Secure` flags

---

## 📁 Project Structure
```
secure_app/
├── app.py              ← Main application with all security logic
├── README.md           ← This file
├── security_report.pdf ← Written security report
├── templates/
│   ├── base.html       ← Base layout template
│   ├── login.html      ← Login page with SQL injection demo
│   ├── register.html   ← Register page with password hashing demo
│   ├── dashboard.html  ← Dashboard with XSS demo and comments
│   └── admin.html      ← Admin-only page for RBAC demo
└── static/
    └── style.css       ← Application styling
```

---

## 📦 Dependencies
- `flask` — Web framework
- `bcrypt` — Secure password hashing
- `bleach` — XSS input sanitization
- `pyopenssl` — Self-signed SSL for HTTPS

---

## ⚠️ Disclaimer
The vulnerable features in this application are for **educational purposes only**. Never deploy the vulnerable versions in a real production environment.
