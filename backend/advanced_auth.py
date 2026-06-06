"""
NetWatch Advanced Authentication System
- JWT Tokens with Refresh Tokens
- 2FA OTP via Email
- Brute Force Protection (Memory-based)
- Session Management
- Activity Logging
- Rate Limiting (Memory-based)
"""

import os
import re
import secrets
import smtplib
import random
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from typing import Optional, Dict, List
import sqlite3
import jwt
import bcrypt
from db_core import get_db_connection, USE_SUPABASE
from fastapi import HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field

# ============================================
# CONFIGURATION
# ============================================
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
REFRESH_TOKEN_EXPIRE_DAYS = 7
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# Email Configuration
SMTP_CONFIG = {
    "server": "smtp.gmail.com",
    "port": 587,
    "username": os.getenv("SMTP_EMAIL", ""),
    "password": os.getenv("SMTP_PASSWORD", "")
}

DB_PATH = "data/netwatch.db"

# Memory cache for rate limiting
memory_cache = {}

# ============================================
# DATABASE SETUP
# ============================================

def init_auth_db():
    """Initialize all auth tables.

    In Supabase/PostgreSQL mode the tables are created once via
    supabase_setup.sql (run in the Supabase SQL Editor), so we skip the
    SQLite-specific DDL below (it uses AUTOINCREMENT, which Postgres rejects).
    """
    if USE_SUPABASE:
        print("[Auth] Supabase mode - tables managed via supabase_setup.sql")
        return

    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            role TEXT DEFAULT 'viewer',
            is_active INTEGER DEFAULT 1,
            is_verified INTEGER DEFAULT 1,
            two_factor_enabled INTEGER DEFAULT 0,
            two_factor_secret TEXT,
            created_at REAL,
            updated_at REAL,
            last_login REAL,
            last_ip TEXT,
            login_count INTEGER DEFAULT 0
        )
    ''')
    
    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_id TEXT NOT NULL,
            refresh_token TEXT NOT NULL,
            device_info TEXT,
            ip_address TEXT,
            created_at REAL,
            expires_at REAL,
            is_revoked INTEGER DEFAULT 0
        )
    ''')
    
    # OTP codes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            purpose TEXT DEFAULT 'login',
            expires_at REAL,
            used INTEGER DEFAULT 0,
            created_at REAL
        )
    ''')
    
    # Login attempts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            username TEXT,
            success INTEGER,
            attempted_at REAL
        )
    ''')
    
    # Activity logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp REAL
        )
    ''')
    
    # Password resets table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            expires_at REAL,
            used INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()
    print("[Auth] Database initialized")

# ============================================
# MODELS
# ============================================

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    username_or_email: str
    password: str
    two_factor_code: Optional[str] = None
    remember_me: bool = False
    device_info: Optional[str] = None

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)

class OTPVerify(BaseModel):
    email: str
    code: str
    purpose: str = "login"

# ============================================
# UTILITY FUNCTIONS
# ============================================

def generate_user_id() -> str:
    return f"usr_{secrets.token_hex(8)}"

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def generate_otp() -> str:
    return f"{random.randint(100000, 999999)}"

def generate_token(data: dict, expires_delta: timedelta, secret: str = SECRET_KEY) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, secret, algorithm=ALGORITHM)

def verify_token(token: str, secret: str = SECRET_KEY) -> Optional[Dict]:
    try:
        return jwt.decode(token, secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None

def generate_refresh_token(user_id: str) -> str:
    return generate_token({"sub": user_id, "type": "refresh"}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), REFRESH_SECRET_KEY)

def is_rate_limited(key: str, limit: int = 5, window: int = 300) -> bool:
    """Check rate limit (memory-based)"""
    now = datetime.now().timestamp()
    
    if key not in memory_cache:
        memory_cache[key] = []
    
    memory_cache[key] = [t for t in memory_cache[key] if now - t < window]
    
    if len(memory_cache[key]) >= limit:
        return True
    
    memory_cache[key].append(now)
    return False

def log_activity(user_id: str, action: str, details: str, ip: str, user_agent: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO activity_logs (user_id, action, details, ip_address, user_agent, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, action, details, ip, user_agent, datetime.now().timestamp()))
    conn.commit()
    conn.close()

def send_email(to_email: str, subject: str, body: str):
    if not SMTP_CONFIG["username"] or not SMTP_CONFIG["password"]:
        print(f"[EMAIL] Would send to {to_email}: {subject}")
        return True
    
    try:
        msg = MIMEText(body, 'html')
        msg['Subject'] = subject
        msg['From'] = SMTP_CONFIG["username"]
        msg['To'] = to_email
        
        with smtplib.SMTP(SMTP_CONFIG["server"], SMTP_CONFIG["port"]) as server:
            server.starttls()
            server.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"[EMAIL] Error: {e}")
        return False

# ============================================
# USER MANAGEMENT
# ============================================

def create_user(user_data: UserCreate, ip: str) -> Dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', 
                   (user_data.username, user_data.email))
    if cursor.fetchone():
        conn.close()
        return {"success": False, "error": "Username or email already exists"}
    
    if not re.search(r'[A-Z]', user_data.password):
        return {"success": False, "error": "Password must contain uppercase letter"}
    if not re.search(r'[a-z]', user_data.password):
        return {"success": False, "error": "Password must contain lowercase letter"}
    if not re.search(r'\d', user_data.password):
        return {"success": False, "error": "Password must contain number"}
    
    user_id = generate_user_id()
    password_hash = hash_password(user_data.password)
    
    cursor.execute('''
        INSERT INTO users (user_id, username, email, password_hash, full_name, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'viewer', ?, ?)
    ''', (user_id, user_data.username, user_data.email, password_hash, 
          user_data.full_name, datetime.now().timestamp(), datetime.now().timestamp()))
    
    conn.commit()
    conn.close()
    
    log_activity(user_id, "account_created", f"Account created from IP {ip}", ip, "system")
    
    return {"success": True, "message": "User created successfully", "user_id": user_id}

def authenticate_user(username_or_email: str, password: str, ip: str) -> Optional[Dict]:
    if is_rate_limited(f"login_{ip}", limit=5, window=300):
        return {"success": False, "error": "Too many attempts. Try again later."}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT user_id, username, email, password_hash, role, is_active, two_factor_enabled
        FROM users WHERE username = ? OR email = ?
    ''', (username_or_email, username_or_email))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return {"success": False, "error": "Invalid credentials"}
    
    user_id, username, email, password_hash, role, is_active, two_factor_enabled = user
    
    if not is_active:
        return {"success": False, "error": "Account is disabled"}
    
    if not verify_password(password, password_hash):
        return {"success": False, "error": "Invalid credentials"}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET login_count = login_count + 1, last_login = ?, last_ip = ? WHERE user_id = ?',
                   (datetime.now().timestamp(), ip, user_id))
    conn.commit()
    conn.close()
    
    log_activity(user_id, "login_success", f"Successful login from IP {ip}", ip, "")
    
    return {
        "success": True,
        "user_id": user_id,
        "username": username,
        "email": email,
        "role": role,
        "requires_2fa": bool(two_factor_enabled)
    }

def send_otp(email: str, purpose: str = "login") -> Dict:
    if is_rate_limited(f"otp_{email}", limit=3, window=300):
        return {"success": False, "error": "Too many OTP requests"}
    
    code = generate_otp()
    expires_at = datetime.now().timestamp() + 600
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO otp_codes (email, code, purpose, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (email, code, purpose, expires_at, datetime.now().timestamp()))
    conn.commit()
    conn.close()
    
    otp_html = f"""
    <html>
    <body>
        <h2>NetWatch Verification Code</h2>
        <p>Your verification code is: <strong>{code}</strong></p>
        <p>This code will expire in 10 minutes.</p>
    </body>
    </html>
    """
    
    send_email(email, f"NetWatch {purpose.upper()} Code", otp_html)
    return {"success": True, "message": "OTP sent"}

def verify_otp(email: str, code: str, purpose: str = "login") -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id FROM otp_codes 
        WHERE email = ? AND code = ? AND purpose = ? AND used = 0 AND expires_at > ?
        ORDER BY id DESC LIMIT 1
    ''', (email, code, purpose, datetime.now().timestamp()))
    
    otp = cursor.fetchone()
    
    if otp:
        cursor.execute('UPDATE otp_codes SET used = 1 WHERE id = ?', (otp[0],))
        conn.commit()
        conn.close()
        return True
    
    conn.close()
    return False

def create_session(user_id: str, refresh_token: str, device_info: str, ip: str) -> str:
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.now().timestamp() + (REFRESH_TOKEN_EXPIRE_DAYS * 86400)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sessions (session_id, user_id, refresh_token, device_info, ip_address, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (session_id, user_id, refresh_token, device_info, ip, datetime.now().timestamp(), expires_at))
    conn.commit()
    conn.close()
    
    return session_id

def get_session(session_id: str) -> Optional[Dict]:
    """Get session details"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT session_id, user_id, refresh_token, device_info, ip_address, expires_at, is_revoked
        FROM sessions WHERE session_id = ?
    ''', (session_id,))
    session = cursor.fetchone()
    conn.close()
    
    if session:
        return {
            "session_id": session[0],
            "user_id": session[1],
            "refresh_token": session[2],
            "device_info": session[3],
            "ip_address": session[4],
            "expires_at": session[5],
            "is_revoked": session[6]
        }
    return None

def revoke_session(session_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE sessions SET is_revoked = 1 WHERE session_id = ?', (session_id,))
    conn.commit()
    conn.close()

def revoke_all_sessions(user_id: str, exclude_session_id: str = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if exclude_session_id:
        cursor.execute('UPDATE sessions SET is_revoked = 1 WHERE user_id = ? AND session_id != ?',
                       (user_id, exclude_session_id))
    else:
        cursor.execute('UPDATE sessions SET is_revoked = 1 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

def request_password_reset(email: str) -> Dict:
    if is_rate_limited(f"reset_{email}", limit=3, window=3600):
        return {"success": False, "error": "Too many reset requests"}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return {"success": True, "message": "If email exists, reset link sent"}
    
    reset_token = secrets.token_urlsafe(32)
    expires_at = datetime.now().timestamp() + 3600
    
    cursor.execute('''
        INSERT INTO password_resets (email, token, expires_at)
        VALUES (?, ?, ?)
    ''', (email, reset_token, expires_at))
    conn.commit()
    conn.close()
    
    reset_link = f"http://localhost:8000/Frontend/reset_password.html?token={reset_token}&email={email}"
    
    reset_html = f"""
    <html>
    <body>
        <h2>Password Reset</h2>
        <p>Click <a href="{reset_link}">here</a> to reset your password.</p>
        <p>This link expires in 1 hour.</p>
    </body>
    </html>
    """
    
    send_email(email, "NetWatch Password Reset", reset_html)
    return {"success": True, "message": "Password reset link sent"}

def confirm_password_reset(token: str, new_password: str) -> Dict:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT email FROM password_resets 
        WHERE token = ? AND used = 0 AND expires_at > ?
        ORDER BY id DESC LIMIT 1
    ''', (token, datetime.now().timestamp()))
    
    reset = cursor.fetchone()
    
    if not reset:
        conn.close()
        return {"success": False, "error": "Invalid or expired reset token"}
    
    email = reset[0]
    
    if len(new_password) < 8:
        return {"success": False, "error": "Password must be at least 8 characters"}
    
    password_hash = hash_password(new_password)
    cursor.execute('UPDATE users SET password_hash = ? WHERE email = ?', (password_hash, email))
    cursor.execute('UPDATE password_resets SET used = 1 WHERE token = ?', (token,))
    
    conn.commit()
    conn.close()
    
    return {"success": True, "message": "Password reset successful"}

async def get_optional_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):
    if not credentials:
        return None
    try:
        return await get_current_user(request, credentials)
    except:
        return None

# ============================================
# FASTAPI DEPENDENCIES
# ============================================

security = HTTPBearer(auto_error=False)

async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    token = credentials.credentials
    payload = verify_token(token)
    
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    
    if payload.get("exp") and payload["exp"] < datetime.now().timestamp():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    
    user_id = payload.get("sub")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT user_id, username, email, role, is_active FROM users WHERE user_id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not user[4]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    
    return {
        "user_id": user[0],
        "username": user[1],
        "email": user[2],
        "role": user[3]
    }

async def get_current_admin(current_user: Dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user

# Initialize database
init_auth_db()

# ============================================
# DEFAULT ADMIN — credentials loaded from environment (NOT hardcoded)
# ============================================
# Set ADMIN_USERNAME / ADMIN_PASSWORD / ADMIN_EMAIL in the environment to
# control the admin login. If ADMIN_PASSWORD is unset, a documented dev
# default is used for first run and a warning is printed telling you to
# change it. The literal below is only a fallback for a fresh install — the
# real source of truth is the env var and, after creation, the DB hash.
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_EMAIL    = os.getenv("ADMIN_EMAIL", "admin@netwatch.com")
_ENV_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")          # None if not set
_DEV_DEFAULT_PASSWORD = "Admin@123"                         # first-run fallback
ADMIN_PASSWORD = _ENV_ADMIN_PASSWORD or _DEV_DEFAULT_PASSWORD

conn = get_db_connection()
cursor = conn.cursor()
cursor.execute('SELECT user_id FROM users WHERE username = ?', (ADMIN_USERNAME,))
if not cursor.fetchone():
    admin_id = generate_user_id()
    admin_hash = hash_password(ADMIN_PASSWORD)
    cursor.execute('''
        INSERT INTO users (user_id, username, email, password_hash, full_name, role, is_verified, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'admin', 1, ?, ?)
    ''', (admin_id, ADMIN_USERNAME, ADMIN_EMAIL, admin_hash, 'System Administrator',
          datetime.now().timestamp(), datetime.now().timestamp()))
    conn.commit()
    print("=" * 60)
    print(f"[Auth] Default admin created — username: {ADMIN_USERNAME}")
    if _ENV_ADMIN_PASSWORD:
        print("[Auth] Password: (loaded from ADMIN_PASSWORD env var)")
    else:
        print(f"[Auth] Password: {_DEV_DEFAULT_PASSWORD}  ← DEV DEFAULT, change it!")
        print("[Auth] Set ADMIN_PASSWORD env var to override before first run.")
    print("=" * 60)
conn.close()