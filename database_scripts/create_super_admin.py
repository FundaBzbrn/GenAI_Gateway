"""
GenAI Security Gateway - Create Super Admin Veritabanı Betiği

Bu betik 'create_super_admin.py', veritabanı (PostgreSQL veya SQLite) üzerinde şema güncellemeleri,
kurulum veya veri onarımı gibi yönetimsel işlemleri gerçekleştirmek için kullanılır.
"""
import asyncio
from dotenv import load_dotenv
load_dotenv()

from app.services.database_manager import DatabaseManager
from app.controllers.auth_controller import get_password_hash

async def create_admin():
    await DatabaseManager.initialize()
    pwd = get_password_hash("123456")
    
    pool = DatabaseManager._pool
    if pool:
        async with pool.acquire() as conn:
            existing = await conn.fetchrow("SELECT id FROM users WHERE username = $1", "admin")
            if not existing:
                await conn.execute("""
                    INSERT INTO users (username, email, password_hash, role, created_at)
                    VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
                """, "admin", "admin@genai.com", pwd, "super_admin")
            else:
                await conn.execute("UPDATE users SET password_hash = $1 WHERE username = $2", pwd, "admin")
                
        print("✅ Super Admin hesabı PostgreSQL veritabanında oluşturuldu/güncellendi!")
    else:
        print("❌ PostgreSQL bağlantısı kurulamadı.")

if __name__ == "__main__":
    asyncio.run(create_admin())
