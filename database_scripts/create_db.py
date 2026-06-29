"""
GenAI Security Gateway - Create Db Veritabanı Betiği

Bu betik 'create_db.py', veritabanı (PostgreSQL veya SQLite) üzerinde şema güncellemeleri,
kurulum veya veri onarımı gibi yönetimsel işlemleri gerçekleştirmek için kullanılır.
"""
import asyncio
import asyncpg
import os
from dotenv import load_dotenv

load_dotenv()

async def create_database():
    try:
        # Connect to the default 'postgres' database to create the new one
        conn = await asyncpg.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            database="postgres",
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "")
        )
        # Check if it exists
        exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname='genai_gateway'")
        if not exists:
            await conn.execute("CREATE DATABASE genai_gateway")
            print("Database created successfully.")
        else:
            print("Database already exists.")
        await conn.close()
    except Exception as e:
        print(f"FAILED to create DB: {e}")

if __name__ == "__main__":
    asyncio.run(create_database())
