"""
GenAI Security Gateway - Alter Db Veritabanı Betiği

Bu betik 'alter_db.py', veritabanı (PostgreSQL veya SQLite) üzerinde şema güncellemeleri,
kurulum veya veri onarımı gibi yönetimsel işlemleri gerçekleştirmek için kullanılır.
"""
import asyncio
import asyncpg
import os
from dotenv import load_dotenv

load_dotenv()

async def migrate_db():
    try:
        conn = await asyncpg.connect(
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "genai_gateway"),
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432"))
        )
        print("Connected to DB.")
        
        # Check if users.company_id exists
        try:
            await conn.execute("ALTER TABLE users ADD COLUMN company_id INTEGER REFERENCES companies(id);")
            print("Added company_id to users.")
        except asyncpg.exceptions.DuplicateColumnError:
            print("users.company_id already exists.")
            
        # Check if security_logs.company_id exists
        try:
            await conn.execute("ALTER TABLE security_logs ADD COLUMN company_id INTEGER REFERENCES companies(id);")
            print("Added company_id to security_logs.")
        except asyncpg.exceptions.DuplicateColumnError:
            print("security_logs.company_id already exists.")

        await conn.close()
    except Exception as e:
        print(f"Error during migration: {e}")

if __name__ == "__main__":
    asyncio.run(migrate_db())
