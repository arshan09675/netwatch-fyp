import sqlite3
import bcrypt
import os

print("=" * 50)
print("NetWatch - Admin Fix Tool")
print("=" * 50)

# Database path
db_path = 'data/netwatch.db'

# Check if database exists
if not os.path.exists(db_path):
    print(f"❌ Database not found: {db_path}")
    print("Make sure you are in the backend folder")
    exit()

print(f"✅ Database found: {db_path}")

# Connect to database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Create users table if not exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        is_active INTEGER,
        is_verified INTEGER,
        created_at REAL
    )
''')
print("✅ Users table ready")

# Delete old admin
cursor.execute("DELETE FROM users WHERE username = 'admin'")
print("✅ Old admin deleted")

# Create new admin with proper hash
password = "Admin@123"
salt = bcrypt.gensalt(rounds=12)
password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

import time
user_id = f"adm_{int(time.time())}"

cursor.execute('''
    INSERT INTO users (user_id, username, email, password_hash, role, is_active, is_verified, created_at)
    VALUES (?, ?, ?, ?, 'admin', 1, 1, ?)
''', (user_id, 'admin', 'admin@netwatch.com', password_hash, time.time()))

conn.commit()
conn.close()

print("=" * 50)
print("✅ SUCCESS! Admin created!")
print("=" * 50)
print("Username: admin")
print("Password: Admin@123")
print("=" * 50)