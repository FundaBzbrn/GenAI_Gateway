import os
import logging
# pyrefly: ignore [missing-import]
import asyncpg
# pyrefly: ignore [missing-import]
import aiosqlite
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# SQLite fallback: PostgreSQL yoksa SQLite kullan (geliştirme ortamı için)
USE_SQLITE = os.getenv("USE_SQLITE", "true").lower() == "true"
SQLITE_PATH = os.getenv("SQLITE_PATH", "genai_gateway.db")


class DatabaseManager:
    """
    GenAI Security Gateway - Veritabanı Katmanı
    Tüm analiz sonuçlarını security_logs tablosuna kaydeder.
    PostgreSQL (üretim) veya SQLite (geliştirme) kullanır.
    """

    _pool: Optional[asyncpg.Pool] = None
    _sqlite_initialized: bool = False

    # ─── TABLO OLUŞTURMA SQL ───────────────────────────────────────────────────
    CREATE_COMPANIES_TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            domain TEXT,
            created_at TEXT NOT NULL
        )
    """

    CREATE_TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS security_logs (
            log_id              TEXT PRIMARY KEY,
            user_id             TEXT NOT NULL,
            company_id          INTEGER,
            masked_prompt       TEXT,
            action              TEXT NOT NULL,
            category            TEXT NOT NULL,
            stopped_at_layer    TEXT,
            ai_confidence_score REAL DEFAULT 0.0,
            latency_ms          INTEGER DEFAULT 0,
            created_at          TEXT NOT NULL,
            justification       TEXT,
            bypass_status       TEXT,
            FOREIGN KEY (company_id) REFERENCES companies(id)
        )
    """

    CREATE_USERS_TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            phone TEXT,
            full_name TEXT DEFAULT '',
            profile_photo TEXT,
            role TEXT DEFAULT 'employee',
            company_id INTEGER,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            department TEXT DEFAULT '',
            FOREIGN KEY (company_id) REFERENCES companies(id)
        )
    """

    CREATE_FEEDBACK_TABLE_SQL = """
        CREATE TABLE IF NOT EXISTS feedback_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id TEXT NOT NULL,
            feedback_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (log_id) REFERENCES security_logs(log_id)
        )
    """

    # ─── PostgreSQL BAĞLANTISI ─────────────────────────────────────────────────
    @classmethod
    async def init_postgres(cls):
        """PostgreSQL bağlantı havuzu oluşturur."""
        try:
            cls._pool = await asyncpg.create_pool(
                host=os.getenv("DB_HOST", "localhost"),
                port=int(os.getenv("DB_PORT", "5432")),
                database=os.getenv("DB_NAME", "genai_gateway"),
                user=os.getenv("DB_USER", "postgres"),
                password=os.getenv("DB_PASSWORD", ""),
                min_size=2,
                max_size=10,
            )
            async with cls._pool.acquire() as conn:
                pg_create_companies = """
                    CREATE TABLE IF NOT EXISTS companies (
                        id SERIAL PRIMARY KEY,
                        name TEXT NOT NULL,
                        domain TEXT,
                        created_at TEXT NOT NULL
                    )
                """
                await conn.execute(pg_create_companies)
                
                pg_create_logs = """
                    CREATE TABLE IF NOT EXISTS security_logs (
                        log_id              TEXT PRIMARY KEY,
                        user_id             TEXT NOT NULL,
                        company_id          INTEGER,
                        masked_prompt       TEXT,
                        action              TEXT NOT NULL,
                        category            TEXT NOT NULL,
                        stopped_at_layer    TEXT,
                        ai_confidence_score REAL DEFAULT 0.0,
                        latency_ms          INTEGER DEFAULT 0,
                        created_at          TEXT NOT NULL,
                        justification       TEXT,
                        bypass_status       TEXT,
                        FOREIGN KEY (company_id) REFERENCES companies(id)
                    )
                """
                await conn.execute(pg_create_logs)
                # Alter postgres table if columns do not exist
                try:
                    await conn.execute("ALTER TABLE security_logs ADD COLUMN IF NOT EXISTS justification TEXT")
                except Exception:
                    pass
                try:
                    await conn.execute("ALTER TABLE security_logs ADD COLUMN IF NOT EXISTS bypass_status TEXT")
                except Exception:
                    pass
                
                # Note: AUTOINCREMENT is sqlite specific, PostgreSQL uses SERIAL
                pg_create_users = """
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT,
                        phone TEXT,
                        full_name TEXT DEFAULT '',
                        profile_photo TEXT,
                        role TEXT DEFAULT 'employee',
                        company_id INTEGER,
                        password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        department TEXT DEFAULT '',
                        FOREIGN KEY (company_id) REFERENCES companies(id)
                    )
                """
                await conn.execute(pg_create_users)
                try:
                    await conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS department TEXT DEFAULT ''")
                except Exception:
                    pass
                
                pg_create_feedback = """
                    CREATE TABLE IF NOT EXISTS feedback_logs (
                        id SERIAL PRIMARY KEY,
                        log_id TEXT NOT NULL,
                        feedback_type TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (log_id) REFERENCES security_logs(log_id)
                    )
                """
                await conn.execute(pg_create_feedback)
            logger.info("✅ PostgreSQL bağlantısı ve tablo başarıyla hazırlandı.")
        except Exception as e:
            logger.error(f"❌ PostgreSQL bağlantı hatası: {e}")
            cls._pool = None

    # ─── SQLite BAŞLATMA ───────────────────────────────────────────────────────
    @classmethod
    async def init_sqlite(cls):
        """SQLite veritabanını ve tabloyu oluşturur."""
        try:
            async with aiosqlite.connect(SQLITE_PATH) as db:
                await db.execute(cls.CREATE_COMPANIES_TABLE_SQL)
                await db.execute(cls.CREATE_TABLE_SQL)
                await db.execute(cls.CREATE_USERS_TABLE_SQL)
                try:
                    await db.execute('ALTER TABLE users ADD COLUMN department TEXT DEFAULT ""')
                except Exception:
                    pass
                # Yeni sütunları ekle (hata almamak için try-except)
                try:
                    await db.execute('ALTER TABLE security_logs ADD COLUMN justification TEXT')
                except Exception:
                    pass
                try:
                    await db.execute('ALTER TABLE security_logs ADD COLUMN bypass_status TEXT')
                except Exception:
                    pass
                await db.execute(cls.CREATE_FEEDBACK_TABLE_SQL)
                await db.commit()
            cls._sqlite_initialized = True
            logger.info(f"✅ SQLite veritabanı hazırlandı: {SQLITE_PATH}")
        except Exception as e:
            logger.error(f"❌ SQLite başlatma hatası: {e}")

    # ─── GENEL BAŞLATMA ───────────────────────────────────────────────────────
    @classmethod
    async def initialize(cls):
        """Uygulama başlarken çağrılır. DB tipine göre başlatma yapar."""
        if USE_SQLITE:
            await cls.init_sqlite()
        else:
            await cls.init_postgres()
            
        await cls.seed_super_admin()

    @classmethod
    async def seed_super_admin(cls):
        """Sistemin kurucusu (Süper Admin) yoksa oluşturur."""
        try:
            super_admin = await cls.get_user_by_username("superadmin")
            if not super_admin:
                # passlib'i direkt dahil etmek yerine buraya import ekleyelim veya plain_hash atalım
                # ancak DB katmanında hash yapmamak daha iyi, o yüzden varsayılan olarak basir bir bcrypt stringi
                # koyacağız veya doğrudan auth controller üzerinden bu seed fonksiyonunu çağırabiliriz.
                # Daha temiz olması için varsayılan şifre "superadmin123" olacak. 
                # (bcrypt hash'i $2b$12$aKcyv8Dz6YPlBbVQY2fnxul23gm95AzMeTm/3NzrRKf3F3WrdMFxi -> 'superadmin123')
                default_hash = "$2b$12$aKcyv8Dz6YPlBbVQY2fnxul23gm95AzMeTm/3NzrRKf3F3WrdMFxi"
                await cls.create_user(
                    username="superadmin",
                    password_hash=default_hash,
                    full_name="Funda & Fidan (Kurucu)",
                    role="super_admin"
                )
                logger.info("👑 Süper Admin hesabı tohumlandı. (Kullanıcı: superadmin, Şifre: superadmin123)")
        except Exception as e:
            logger.error(f"❌ Süper admin tohumlama hatası: {e}")

    # ─── LOG KAYDETME ─────────────────────────────────────────────────────────
    @classmethod
    async def log_security_event(
        cls,
        log_id: str,
        user_id: str,
        masked_prompt: str,
        action: str,
        category: str,
        stopped_at_layer: str,
        ai_score: float,
        latency_ms: int,
        company_id: Optional[int] = None,
        justification: Optional[str] = None,
        bypass_status: Optional[str] = None
    ):
        """Güvenlik olayını asenkron olarak veritabanına yazar."""
        created_at = datetime.now().isoformat()

        if USE_SQLITE:
            await cls._log_sqlite(
                log_id, user_id, company_id, masked_prompt, action,
                category, stopped_at_layer, ai_score, latency_ms, created_at,
                justification, bypass_status
            )
        else:
            await cls._log_postgres(
                log_id, user_id, company_id, masked_prompt, action,
                category, stopped_at_layer, ai_score, latency_ms, created_at,
                justification, bypass_status
            )

    @classmethod
    async def _log_sqlite(cls, log_id, user_id, company_id, masked_prompt, action,
                          category, stopped_at_layer, ai_score, latency_ms, created_at,
                          justification=None, bypass_status=None):
        try:
            async with aiosqlite.connect(SQLITE_PATH) as db:
                await db.execute(
                    """INSERT INTO security_logs
                       (log_id, user_id, company_id, masked_prompt, action, category,
                        stopped_at_layer, ai_confidence_score, latency_ms, created_at,
                        justification, bypass_status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (log_id, user_id, company_id, masked_prompt, action, category,
                     stopped_at_layer, ai_score, latency_ms, created_at,
                     justification, bypass_status)
                )
                await db.commit()
                logger.info(f"📝 Log kaydedildi → {log_id} | {action} ({category})")
        except Exception as e:
            logger.error(f"❌ SQLite log hatası: {e}")

    @classmethod
    async def _log_postgres(cls, log_id, user_id, company_id, masked_prompt, action,
                             category, stopped_at_layer, ai_score, latency_ms, created_at,
                             justification=None, bypass_status=None):
        if not cls._pool:
            logger.warning("⚠️ PostgreSQL bağlantısı yok, log atlanıyor.")
            return
        try:
            async with cls._pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO security_logs
                       (log_id, user_id, company_id, masked_prompt, action, category,
                        stopped_at_layer, ai_confidence_score, latency_ms, created_at,
                        justification, bypass_status)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)""",
                    log_id, user_id, company_id, masked_prompt, action, category,
                    stopped_at_layer, ai_score, latency_ms, created_at,
                    justification, bypass_status
                )
                logger.info(f"📝 Log kaydedildi → {log_id} | {action} ({category})")
        except Exception as e:
            logger.error(f"❌ PostgreSQL log hatası: {e}")

    @classmethod
    async def update_log_status(cls, log_id: str, action: str, bypass_status: str) -> bool:
        """Logun karar (action) ve bypass durumunu günceller."""
        query = "UPDATE security_logs SET action = ?, bypass_status = ? WHERE log_id = ?" if USE_SQLITE else "UPDATE security_logs SET action = $1, bypass_status = $2 WHERE log_id = $3"
        try:
            if USE_SQLITE:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    await db.execute(query, (action, bypass_status, log_id))
                    await db.commit()
            else:
                async with cls._pool.acquire() as conn:
                    await conn.execute(query, action, bypass_status, log_id)
            logger.info(f"🔄 Log durumu güncellendi: {log_id} → {action} ({bypass_status})")
            return True
        except Exception as e:
            logger.error(f"❌ Log durumu güncelleme hatası: {e}")
            return False

    # ─── LOG LİSTELEME ────────────────────────────────────────────────────────
    @classmethod
    async def get_logs(cls, limit: int = 50, action_filter: Optional[str] = None,
                       category_filter: Optional[str] = None,
                       company_id: Optional[int] = None,
                       user_id: Optional[str] = None) -> list:
        """Log kayıtlarını filtreli olarak getirir."""
        if USE_SQLITE:
            return await cls._get_logs_sqlite(limit, action_filter, category_filter, company_id, user_id)
        else:
            return await cls._get_logs_postgres(limit, action_filter, category_filter, company_id, user_id)

    @classmethod
    async def _get_logs_sqlite(cls, limit, action_filter, category_filter, company_id, user_id=None) -> list:
        try:
            query = "SELECT * FROM security_logs WHERE 1=1"
            params = []
            if company_id is not None:
                query += " AND company_id = ?"
                params.append(company_id)
            if user_id is not None:
                query += " AND user_id = ?"
                params.append(user_id)
            if action_filter:
                query += " AND action = ?"
                params.append(action_filter.upper())
            if category_filter:
                query += " AND category = ?"
                params.append(category_filter)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            async with aiosqlite.connect(SQLITE_PATH) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
                    return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"❌ SQLite log okuma hatası: {e}")
            return []

    @classmethod
    async def _get_logs_postgres(cls, limit, action_filter, category_filter, company_id, user_id=None) -> list:
        if not cls._pool:
            return []
        try:
            query = "SELECT * FROM security_logs WHERE 1=1"
            params = []
            i = 1
            if company_id is not None:
                query += f" AND company_id = ${i}"
                params.append(company_id)
                i += 1
            if user_id is not None:
                query += f" AND user_id = ${i}"
                params.append(user_id)
                i += 1
            if action_filter:
                query += f" AND action = ${i}"
                params.append(action_filter.upper())
                i += 1
            if category_filter:
                query += f" AND category = ${i}"
                params.append(category_filter)
                i += 1
            query += f" ORDER BY created_at DESC LIMIT ${i}"
            params.append(limit)

            async with cls._pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"❌ PostgreSQL log okuma hatası: {e}")
            return []

    # ─── FEEDBACK KAYDETME ────────────────────────────────────────────────────
    @classmethod
    async def save_feedback(cls, log_id: str, correct_label: str) -> bool:
        """False positive bildirimi için log kaydını günceller."""
        # Şimdilik log'a feedback_label sütunu yok, ileride eklenebilir.
        # Şimdilik sadece logluyoruz.
        logger.info(f"📣 Feedback alındı → log_id={log_id}, correct_label={correct_label}")
        return True

    # ─── İSTATİSTİKLER ────────────────────────────────────────────────────────
    @classmethod
    async def get_stats(cls, company_id: Optional[int] = None, user_id: Optional[str] = None) -> dict:
        """Dashboard için özet istatistikleri döner."""
        if USE_SQLITE:
            return await cls._get_stats_sqlite(company_id, user_id)
        return await cls._get_stats_postgres(company_id, user_id)

    @classmethod
    async def _get_stats_sqlite(cls, company_id, user_id=None) -> dict:
        try:
            async with aiosqlite.connect(SQLITE_PATH) as db:
                conditions = []
                params = []
                if company_id is not None:
                    conditions.append("company_id = ?")
                    params.append(company_id)
                if user_id is not None:
                    conditions.append("user_id = ?")
                    params.append(user_id)
                
                where_clause = (" WHERE " + " AND ".join(conditions)) if conditions else ""
                
                async with db.execute(f"SELECT COUNT(*) FROM security_logs{where_clause}", params) as c:
                    total = (await c.fetchone())[0]
                
                block_conditions = ["action='BLOCK'"] + conditions
                block_where = " WHERE " + " AND ".join(block_conditions)
                async with db.execute(f"SELECT COUNT(*) FROM security_logs{block_where}", params) as c:
                    blocked = (await c.fetchone())[0]
                
                allow_conditions = ["action='ALLOW'"] + conditions
                allow_where = " WHERE " + " AND ".join(allow_conditions)
                async with db.execute(f"SELECT COUNT(*) FROM security_logs{allow_where}", params) as c:
                    allowed = (await c.fetchone())[0]
                
                async with db.execute(f"SELECT AVG(latency_ms) FROM security_logs{where_clause}", params) as c:
                    avg_latency = (await c.fetchone())[0] or 0
                    
                return {
                    "total_requests": total,
                    "blocked": blocked,
                    "allowed": allowed,
                    "avg_latency_ms": round(avg_latency, 1),
                }
        except Exception as e:
            logger.error(f"❌ Stats hatası: {e}")
            return {"error": str(e)}

    @classmethod
    async def _get_stats_postgres(cls, company_id, user_id=None) -> dict:
        if not cls._pool:
            return {"total_requests": 0, "blocked": 0, "allowed": 0, "avg_latency_ms": 0}
        try:
            async with cls._pool.acquire() as conn:
                conditions = []
                params = []
                i = 1
                if company_id is not None:
                    conditions.append(f"company_id = ${i}")
                    params.append(company_id)
                    i += 1
                if user_id is not None:
                    conditions.append(f"user_id = ${i}")
                    params.append(user_id)
                    i += 1

                where_clause = (" WHERE " + " AND ".join(conditions)) if conditions else ""

                total = await conn.fetchval(f"SELECT COUNT(*) FROM security_logs{where_clause}", *params)
                
                block_conditions = ["action='BLOCK'"] + conditions
                block_where = " WHERE " + " AND ".join(block_conditions)
                blocked = await conn.fetchval(f"SELECT COUNT(*) FROM security_logs{block_where}", *params)
                
                allow_conditions = ["action='ALLOW'"] + conditions
                allow_where = " WHERE " + " AND ".join(allow_conditions)
                allowed = await conn.fetchval(f"SELECT COUNT(*) FROM security_logs{allow_where}", *params)
                
                avg_latency = await conn.fetchval(f"SELECT AVG(latency_ms) FROM security_logs{where_clause}", *params) or 0
                return {
                    "total_requests": total,
                    "blocked": blocked,
                    "allowed": allowed,
                    "avg_latency_ms": round(float(avg_latency), 1),
                }
        except Exception as e:
            logger.error(f"❌ PostgreSQL stats hatası: {e}")
            return {"error": str(e)}

    # ─── KULLANICI (AUTH) YÖNETİMİ ──────────────────────────────────────────────
    @classmethod
    async def create_company(cls, name: str, domain: str = None) -> Optional[int]:
        """Yeni bir şirket oluşturur ve ID'sini döner."""
        created_at = datetime.now().isoformat()
        if USE_SQLITE:
            try:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    cursor = await db.execute(
                        "INSERT INTO companies (name, domain, created_at) VALUES (?, ?, ?)",
                        (name, domain, created_at)
                    )
                    await db.commit()
                    return cursor.lastrowid
            except Exception as e:
                logger.error(f"❌ Şirket oluşturma hatası (SQLite): {e}")
                return None
        else:
            if not cls._pool: return None
            try:
                async with cls._pool.acquire() as conn:
                    row = await conn.fetchrow(
                        "INSERT INTO companies (name, domain, created_at) VALUES ($1, $2, $3) RETURNING id",
                        name, domain, created_at
                    )
                    return row["id"]
            except Exception as e:
                logger.error(f"❌ Şirket oluşturma hatası (PostgreSQL): {e}")
                return None

    @classmethod
    async def get_all_companies(cls) -> list:
        if USE_SQLITE:
            try:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    db.row_factory = aiosqlite.Row
                    async with db.execute("SELECT * FROM companies ORDER BY name") as cursor:
                        rows = await cursor.fetchall()
                        return [dict(row) for row in rows]
            except Exception as e:
                return []
        else:
            if not cls._pool: return []
            try:
                async with cls._pool.acquire() as conn:
                    rows = await conn.fetch("SELECT * FROM companies ORDER BY name")
                    return [dict(row) for row in rows]
            except Exception as e:
                return []

    @classmethod
    async def create_user(
        cls, 
        username: str, 
        password_hash: str, 
        email: str = None, 
        phone: str = None, 
        full_name: str = "", 
        role: str = "employee",
        company_id: int = None,
        department: str = "",
        profile_photo: str = ""
    ) -> bool:
        """Yeni bir kullanıcı oluşturur."""
        created_at = datetime.now().isoformat()
        if USE_SQLITE:
            try:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    await db.execute(
                        """INSERT INTO users (username, password_hash, email, phone, full_name, role, company_id, created_at, department, profile_photo)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (username, password_hash, email, phone, full_name, role, company_id, created_at, department, profile_photo)
                    )
                    await db.commit()
                return True
            except Exception as e:
                logger.error(f"❌ Kullanıcı oluşturma hatası (SQLite): {e}")
                return False
        else:
            if not cls._pool: return False
            try:
                async with cls._pool.acquire() as conn:
                    await conn.execute(
                        """INSERT INTO users (username, password_hash, email, phone, full_name, role, company_id, created_at, department, profile_photo)
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)""",
                        username, password_hash, email, phone, full_name, role, company_id, created_at, department, profile_photo
                    )
                return True
            except Exception as e:
                logger.error(f"❌ Kullanıcı oluşturma hatası (PostgreSQL): {e}")
                return False

    @classmethod
    async def get_user_by_username(cls, username: str) -> Optional[dict]:
        """Kullanıcı ismine göre kullanıcı bilgisini getirir."""
        if USE_SQLITE:
            try:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    db.row_factory = aiosqlite.Row
                    async with db.execute("SELECT * FROM users WHERE username = ?", (username,)) as cursor:
                        row = await cursor.fetchone()
                        return dict(row) if row else None
            except Exception as e:
                logger.error(f"❌ Kullanıcı getirme hatası: {e}")
                return None
        else:
            if not cls._pool: return None
            try:
                async with cls._pool.acquire() as conn:
                    row = await conn.fetchrow("SELECT * FROM users WHERE username = $1", username)
                    return dict(row) if row else None
            except Exception as e:
                logger.error(f"❌ Kullanıcı getirme hatası: {e}")
                return None

    @classmethod
    async def update_user_profile(cls, username: str, update_data: dict) -> bool:
        """Kullanıcı profil verilerini (email, phone, full_name, profile_photo) günceller."""
        if not update_data: return True
        
        sets = []
        values = []
        for i, (k, v) in enumerate(update_data.items()):
            sets.append(f"{k} = {'?' if USE_SQLITE else f'${i+1}'}")
            values.append(v)
            
        values.append(username)
        where_clause = f"username = {'?' if USE_SQLITE else f'${len(values)}'}"
        
        query = f"UPDATE users SET {', '.join(sets)} WHERE {where_clause}"
        
        try:
            if USE_SQLITE:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    await db.execute(query, tuple(values))
                    await db.commit()
            else:
                async with cls._pool.acquire() as conn:
                    await conn.execute(query, *values)
            return True
        except Exception as e:
            logger.error(f"❌ Profil güncelleme hatası: {e}")
            return False

    @classmethod
    async def update_user_password(cls, username: str, password_hash: str) -> bool:
        """Kullanıcının şifresini günceller."""
        query = "UPDATE users SET password_hash = ? WHERE username = ?" if USE_SQLITE else "UPDATE users SET password_hash = $1 WHERE username = $2"
        try:
            if USE_SQLITE:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    await db.execute(query, (password_hash, username))
                    await db.commit()
            else:
                async with cls._pool.acquire() as conn:
                    await conn.execute(query, password_hash, username)
            return True
        except Exception as e:
            logger.error(f"❌ Şifre güncelleme hatası: {e}")
            return False

    # ─── FEEDBACK KAYDETME ─────────────────────────────────────────────────────
    @classmethod
    async def log_feedback(cls, log_id: str, feedback_type: str) -> bool:
        """
        Yanlış pozitif / yanlış negatif bildirimini kaydet.
        
        Parameters:
        - log_id: İlgili log kaydının ID'si
        - feedback_type: 'false_positive' veya 'false_negative'
        """
        created_at = datetime.now().isoformat()
        
        if USE_SQLITE:
            try:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    await db.execute(
                        """INSERT INTO feedback_logs (log_id, feedback_type, created_at)
                           VALUES (?, ?, ?)""",
                        (log_id, feedback_type, created_at)
                    )
                    await db.commit()
                logger.info(f"📢 Feedback kaydedildi (SQLite): {log_id} | {feedback_type}")
                return True
            except Exception as e:
                logger.error(f"❌ Feedback kaydetme hatası (SQLite): {e}")
                return False
        else:
            if not cls._pool:
                return False
            try:
                async with cls._pool.acquire() as conn:
                    await conn.execute(
                        """INSERT INTO feedback_logs (log_id, feedback_type, created_at)
                           VALUES ($1, $2, $3)""",
                        log_id, feedback_type, created_at
                    )
                logger.info(f"📢 Feedback kaydedildi (PostgreSQL): {log_id} | {feedback_type}")
                return True
            except Exception as e:
                logger.error(f"❌ Feedback kaydetme hatası (PostgreSQL): {e}")
                return False
            return False

    # ─── KAPATMA / CLEANUP ─────────────────────────────────────────────────────
    @classmethod
    async def get_users_by_company(cls, company_id: int) -> list:
        """Belirtilen şirkete ait tüm kullanıcıları getirir."""
        if USE_SQLITE:
            try:
                async with aiosqlite.connect(SQLITE_PATH) as db:
                    db.row_factory = aiosqlite.Row
                    async with db.execute("SELECT id, username, email, phone, role, full_name, created_at FROM users WHERE company_id = ? ORDER BY role", (company_id,)) as cursor:
                        rows = await cursor.fetchall()
                        return [dict(row) for row in rows]
            except Exception as e:
                logger.error(f"❌ Kullanıcı listeleme hatası (SQLite): {e}")
                return []
        else:
            if not cls._pool: return []
            try:
                async with cls._pool.acquire() as conn:
                    rows = await conn.fetch("SELECT id, username, email, phone, role, full_name, created_at FROM users WHERE company_id = $1 ORDER BY role", company_id)
                    return [dict(row) for row in rows]
            except Exception as e:
                logger.error(f"❌ Kullanıcı listeleme hatası (PostgreSQL): {e}")
                return []

    @classmethod
    async def close(cls):
        """Tüm veritabanı bağlantılarını düzgün kapatır (graceful shutdown)."""
        try:
            if not USE_SQLITE and cls._pool:
                await cls._pool.close()
                cls._pool = None
                logger.info("✅ PostgreSQL bağlantı havuzu kapatıldı")
            elif USE_SQLITE:
                # SQLite ile aiosqlite kendiliğinden kapatılır, sadece flagı reset et
                cls._sqlite_initialized = False
                logger.info("✅ SQLite bağlantıları kapatıldı")
        except Exception as e:
            logger.error(f"❌ Veritabanı kapatılırken hata: {e}", exc_info=True)