import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), '..', 'mock_site', 'instance', 'mock_site.db')
conn = sqlite3.connect(db_path)
cur = conn.cursor()

# Check and update users table
cols_users = [c[1] for c in cur.execute('PRAGMA table_info(users)').fetchall()]
if 'is_admin' not in cols_users:
    cur.execute('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0')
    print("Added is_admin to users")
if 'active' not in cols_users:
    cur.execute('ALTER TABLE users ADD COLUMN active BOOLEAN DEFAULT 1')
    print("Added active to users")
if 'profile_token' not in cols_users:
    cur.execute('ALTER TABLE users ADD COLUMN profile_token VARCHAR(64) DEFAULT NULL')
    print("Added profile_token to users")

# Make Santhosh admin as well so user can access dashboard and SOC immediately
cur.execute("UPDATE users SET is_admin=1 WHERE username='Santhosh'")
print(f"Updated Santhosh is_admin: {cur.rowcount} rows")

# Check and update documents table
cols_docs = [c[1] for c in cur.execute('PRAGMA table_info(documents)').fetchall()]
if 'file_token' not in cols_docs:
    cur.execute("ALTER TABLE documents ADD COLUMN file_token VARCHAR(64) DEFAULT ''")
    print("Added file_token to documents")
if 'admin_note' not in cols_docs:
    cur.execute('ALTER TABLE documents ADD COLUMN admin_note TEXT DEFAULT NULL')
    print("Added admin_note to documents")
if 'verified_by' not in cols_docs:
    cur.execute('ALTER TABLE documents ADD COLUMN verified_by INTEGER DEFAULT NULL')
    print("Added verified_by to documents")

conn.commit()
print("Migration finished!")
