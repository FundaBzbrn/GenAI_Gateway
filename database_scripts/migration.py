"""
GenAI Security Gateway - Migration Veritabanı Betiği

Bu betik 'migration.py', veritabanı (PostgreSQL veya SQLite) üzerinde şema güncellemeleri,
kurulum veya veri onarımı gibi yönetimsel işlemleri gerçekleştirmek için kullanılır.
"""
import sqlite3
import os

DB_PATH = "genai_gateway.db"

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"Skipping migration, {DB_PATH} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check current columns
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]

    added = False
    
    if "email" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
        added = True
    if "phone" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
        added = True
    if "full_name" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN full_name TEXT DEFAULT ''")
        added = True
    if "profile_photo" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_photo TEXT")
        added = True
    if "role" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        added = True
        # Mevcut kullanıcıları admin yap!
        cursor.execute("UPDATE users SET role = 'admin'")

    if added:
        conn.commit()
        print("✅ Migration applied successfully.")
    else:
        print("⚡ Migration already applied.")
        
    conn.close()

if __name__ == "__main__":
    migrate()
