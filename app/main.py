from fastapi import FastAPI, Query, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import time
import logging
import os
from typing import Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# .env dosyasını yükle (API anahtarları ve veritabanı ayarlarını bellek içine alır)
load_dotenv()

# Proje içi denetleyici (controller) ve servislerin sisteme dahil edilmesi
from app.controllers import security_controller, auth_controller, admin_controller, file_controller
from app.services.database_manager import DatabaseManager
from app.config_manager import ConfigManager, RulesConfig
from app.services.layer2_deberta import Layer2DeBERTa

# Loglama ayarları yapılandırılıyor (Tarih, Hata Seviyesi, Dosya Adı ve Mesaj formatında)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger(__name__)

# Sunucunun kontrollü (graceful) kapatılıp kapatılmadığını takip eden bayrak
_shutdown_event = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Uygulamanın yaşam döngüsü (lifespan) yöneticisi.
    Sistem ayağa kalkarken modelleri ve veritabanını başlatır, 
    kapanırken bağlantıları güvenli şekilde sonlandırır.
    """
    global _shutdown_event
    _shutdown_event = False
    logger.info("🚀 GenAI Security Gateway başlatılıyor...")
    try:
        # Layer 2 (DeBERTa) modelini belleğe yükle (İlk sorguda gecikme yaşanmaması için)
        Layer2DeBERTa.load_model()
        # Veritabanı bağlantı havuzunu (connection pool) oluştur
        await DatabaseManager.initialize()
        logger.info("✅ Sistem hazır!")
    except Exception as e:
        logger.error(f"❌ Başlatma hatası: {e}", exc_info=True)
        raise

    # Uygulama çalıştığı sürece burada bekler (yield)
    yield

    # Sunucu kapanma sinyali aldığında burası çalışır
    _shutdown_event = True
    logger.info("🛑 GenAI Security Gateway kapatılıyor...")
    try:
        # Askıda kalan veritabanı işlemlerini güvenlice tamamla ve bağlantıyı kopart
        await DatabaseManager.close()
        logger.info("✅ Veritabanı bağlantıları kapatıldı")
    except Exception as e:
        logger.error(f"❌ Kapatılırken hata: {e}", exc_info=True)
    logger.info("✅ Sistem tamamen kapatıldı")


# ── FastAPI Uygulaması (Ana Omurga) ────────────────────────────────────────────
app = FastAPI(
    title="GenAI Security Gateway",
    description="""
## Üretken Yapay Zeka Sistemleri İçin Çok Katmanlı Akıllı Güvenlik Ağ Geçidi

Kullanıcılar ile yapay zeka modelleri arasında konumlanan, 3 katmanlı güvenlik proxy'si.

### Katmanlar:
- **Katman 1 (Refleks):** Regex blacklist + PII maskeleme — `<5ms`
- **Katman 2 (Zeka):** DeBERTa AI prompt injection tespiti — `~100ms`
- **Katman 3 (Bilgelik):** GPT-4o-mini LLM Judge — `~500ms` (sadece gri bölge)

### Geliştirici: Funda Bozburun & Fidan Akyürek | İstanbul Topkapı Üniversitesi
    """,
    version="1.0.0",
    lifespan=lifespan  # Yaşam döngüsü fonksiyonunu FastAPI'ye bağla
)

# ── CORS Ayarları (Önyüzün Arka Yüze Sorunsuz Erişimi İçin) ────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Geliştirme ortamı için tüm kaynaklara izin veriliyor (Prod'da kısıtlanmalı)
    allow_credentials=True,
    allow_methods=["*"],  # GET, POST, PUT vb. tüm HTTP metotlarına izin ver
    allow_headers=["*"],  # İstemciden gelen tüm başlıklara izin ver
)

# ── Oturum (Session) Yönetimi ──────────────────────────────────────────────────
# OAuth veya durum bazlı işlemler için gerekli gizli anahtar
app.add_middleware(SessionMiddleware, secret_key=os.getenv("JWT_SECRET", "super-secret-oauth-session-key"))


# ── Rotaların (Endpoints) Sisteme Eklenmesi ────────────────────────────────────
# Farklı işlevlere sahip denetleyicileri kendi URL önekleriyle (prefix) bağla
app.include_router(security_controller.router, prefix="/api/v1")
app.include_router(auth_controller.router, prefix="/api/v1/auth")
app.include_router(admin_controller.router, prefix="/api/v1/admin")
app.include_router(file_controller.router, prefix="/api/v1")


@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    """
    Sistemin ayakta olup olmadığını kontrol eden 'Canlılık' (Health Check) ucu.
    Yük dengeleyiciler (Load Balancers) buraya istek atarak sunucuyu denetler.
    """
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "model_loaded": False,  # Modelin yüklenme durumunu gösterir
        "message": "GenAI Security Gateway is running."
    }


# ── Kullanıcıya Özel Rotalar ───────────────────────────────────────────────────
@app.get("/api/v1/user/stats", tags=["User"])
async def get_user_stats(payload: dict = Depends(auth_controller.verify_token)):
    """
    Giriş yapmış (Token'ı doğrulanmış) kullanıcının şahsi istatistiklerini getirir.
    Kaç prompt atmış, kaçı engellenmiş vb. bilgileri döner.
    """
    username = payload.get("sub")
    stats = await DatabaseManager.get_stats(user_id=username)
    return stats


@app.get("/api/v1/user/logs", tags=["User"])
async def get_user_logs(
    limit: int = Query(default=50, ge=1, le=500),
    action: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    payload: dict = Depends(auth_controller.verify_token)
):
    """
    Giriş yapmış kullanıcının kendi gönderdiği log kayıtlarını listeler.
    Filtreleme (örn: Sadece BLOCK olanlar) yapılabilir.
    """
    username = payload.get("sub")
    logs = await DatabaseManager.get_logs(
        limit=limit,
        action_filter=action,
        category_filter=category,
        user_id=username
    )
    return {"count": len(logs), "logs": logs}


# ── Genel Log ve İstatistik Rotaları (Adminler İçin) ───────────────────────────
@app.get("/api/v1/logs", tags=["Logs"])
async def get_logs(
    limit: int = Query(default=50, ge=1, le=500, description="Kaç kayıt dönsün"),
    action: Optional[str] = Query(default=None, description="ALLOW veya BLOCK"),
    category: Optional[str] = Query(default=None, description="Safe, Injection, Blacklist, PII..."),
):
    """
    Tüm güvenlik log kayıtlarını (Kullanıcı fark etmeksizin) filtreli olarak listeler.
    Admin paneline veri sağlamak için tasarlanmıştır.
    """
    logs = await DatabaseManager.get_logs(
        limit=limit,
        action_filter=action,
        category_filter=category,
    )
    return {"count": len(logs), "logs": logs}


@app.get("/api/v1/stats", tags=["Logs"])
async def get_stats():
    """
    Dashboard'daki grafikler ve KPI kartları için genel sistem istatistiklerini (toplam istek, gecikme vs.) döner.
    """
    stats = await DatabaseManager.get_stats()
    return stats


# ── Geri Bildirim Rotası ───────────────────────────────────────────────────────
@app.post("/api/v1/feedback", tags=["Feedback"])
async def submit_feedback(log_id: str, correct_label: str):
    """
    Sistemin yanlış karar verdiği (False Positive/Negative) durumları raporlamak için kullanılır.
    Kullanıcı arayüzünden 'Yanlış Karar' butonuna basıldığında tetiklenir.
    """
    success = await DatabaseManager.save_feedback(log_id, correct_label)
    return {"success": success, "message": f"Feedback kaydedildi: {log_id} → {correct_label}"}

# ── Dinamik Kural Ayarları ─────────────────────────────────────────────────────
@app.get("/api/v1/rules", tags=["Rules"])
async def get_rules():
    """
    Sistemdeki mevcut güvenlik ayarlarını (Threshold, aktif layer'lar vb.) JSON olarak okur.
    """
    return ConfigManager.load_config()

@app.post("/api/v1/rules", tags=["Rules"])
async def update_rules(config: RulesConfig):
    """
    Admin panelinden gelen yeni güvenlik kurallarını (örn: Layer 2'yi kapat) alır ve kaydeder.
    """
    success = ConfigManager.save_config(config)
    if success:
        return {"success": True, "message": "Ayarlar güncellendi."}
    return {"success": False, "message": "Ayarlar kaydedilemedi."}

@app.post("/api/v1/start-frontend", tags=["System"])
async def start_frontend():
    """
    Ayrı bir process (süreç) olarak Streamlit tabanlı önyüzü başlatır.
    Port 8501'de zaten çalışıyorsa mevcut URL'yi döner.
    """
    import subprocess
    import socket
    try:
        # Streamlit'in (8501) zaten açık olup olmadığını kontrol et
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('localhost', 8501)) == 0:
                return {"success": True, "message": "Frontend zaten çalışıyor.", "url": "http://localhost:8501"}
        
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        venv_python = os.path.join(base_dir, ".venv", "Scripts", "python.exe")
        app_script = os.path.join(base_dir, "streamlit_app.py")
        
        # Streamlit uygulamasını arka planda asenkron olarak tetikle
        subprocess.Popen(
            [venv_python, "-m", "streamlit", "run", app_script], 
            cwd=base_dir,
            creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
        )
        return {"success": True, "message": "Frontend başlatıldı.", "url": "http://localhost:8501"}
    except Exception as e:
        logger.error(f"Frontend başlatılamadı: {e}")
        return {"success": False, "message": f"Hata: {e}"}

# ── Frontend (Dashboard) Sunumu ────────────────────────────────────────────────
# / (kök) ve /dashboard adreslerine istek geldiğinde statik frontend klasöründeki index.html'i göster.
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
app.mount("/dashboard", StaticFiles(directory="frontend", html=True), name="dashboard")
