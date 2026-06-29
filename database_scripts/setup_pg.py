"""
GenAI Security Gateway - Setup Pg Veritabanı Betiği

Bu betik 'setup_pg.py', veritabanı (PostgreSQL veya SQLite) üzerinde şema güncellemeleri,
kurulum veya veri onarımı gibi yönetimsel işlemleri gerçekleştirmek için kullanılır.
"""
import asyncio
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
load_dotenv() # Load .env BEFORE importing DatabaseManager

from app.services.database_manager import DatabaseManager

async def setup_pg():
    print("USE_SQLITE from env:", DatabaseManager.__module__)
    
    # Initialize DB (creates tables)
    await DatabaseManager.initialize()
    
    pwd_hash = '$2b$12$P3p11jHbxMkXCgSYbZu5UOPUTT5JyD56Kw7O2T4fFV4Vftswxxacq'
    
    # Create super_admin_fidan
    pool = DatabaseManager._pool
    if pool:
        print("Connected to PostgreSQL pool successfully!")
        async with pool.acquire() as conn:
            # Check if user exists
            existing = await conn.fetchrow("SELECT id FROM users WHERE username = $1", "super_admin_fidan")
            if not existing:
                await conn.execute("""
                    INSERT INTO users (username, email, password_hash, role, created_at)
                    VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
                """, "super_admin_fidan", "admin@example.com", pwd_hash, "super_admin")
                print("Inserted super_admin_fidan into PostgreSQL successfully!")
            else:
                await conn.execute("""
                    UPDATE users SET password_hash = $1 WHERE username = $2
                """, pwd_hash, "super_admin_fidan")
                print("Updated super_admin_fidan password in PostgreSQL successfully!")
    else:
        print("Failed to get PostgreSQL pool! Check if USE_SQLITE is true.")

if __name__ == "__main__":
    asyncio.run(setup_pg())
