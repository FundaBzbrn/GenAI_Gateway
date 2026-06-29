import json
import os
from pydantic import BaseModel
from typing import List

# Konfigürasyon dosyasının kaydedileceği veya okunacağı dizin/yol belirleniyor.
# Mevcut dosyanın ('config_manager.py') bulunduğu dizinin içine 'config.json' adı verilir.
CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")

class RulesConfig(BaseModel):
    """
    Güvenlik kurallarının şemasını tutan Pydantic modelidir.
    Hangi güvenlik katmanlarının açık olduğu, eşik değerleri ve yasaklı kelime listesi gibi
    uygulama düzeyinde kritik kararlar burada tanımlanır ve valide edilir.
    """
    layer_regex: bool = True       # Katman 1 (Statik Regex ve Blacklist Kontrolü) aktif mi?
    layer_deberta: bool = False    # Katman 2 (DeBERTa AI modeli). Windows MKL uyumsuzluğu ihtimaline karşı geçici olarak pasif tutuluyor.
    layer_llm: bool = True         # Katman 3 (LLM Judge - GPT-4o-mini). Gri bölge analizi aktif mi?
    ai_threshold: float = 0.75     # DeBERTa modeli için Güven Eşiği (Bu eşiğin üzeri zararlı kabul edilir)
    # Varsayılan yasaklı kelime (Blacklist) havuzu
    blacklist: List[str] = ["bomba", "intihar", "hack", "sql_injection", "bypass"]

class ConfigManager:
    """
    'config.json' dosyasını okuyan ve yazan yönetici sınıftır.
    Sistemin ayarlarını diskte tutarak, sunucu yeniden başlatıldığında bile 
    admin panelinden yapılan son ayarların korunmasını sağlar.
    """

    @staticmethod
    def load_config() -> RulesConfig:
        """
        Diskteki konfigürasyon dosyasını okur.
        Eğer dosya henüz oluşturulmamışsa (ilk kurulum), varsayılan ayarları yükler,
        diske kaydeder ve geri döner.
        """
        # Dosya yoksa varsayılan değerleri oluştur
        if not os.path.exists(CONFIG_FILE):
            default_cfg = RulesConfig()
            ConfigManager.save_config(default_cfg)
            return default_cfg
        
        try:
            # JSON dosyasını okuyup RulesConfig modeline çevir
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return RulesConfig(**data)
        except Exception as e:
            # Okuma sırasında bir hata (örneğin bozuk JSON formatı) olursa konsola yaz ve varsayılanları dön
            print(f"Config yüklenirken hata oluştu: {e}")
            return RulesConfig()
            
    @staticmethod
    def save_config(config: RulesConfig) -> bool:
        """
        Yeni bir ayar değişikliği (örneğin adminin arayüzden yeni bir kelime yasaklaması)
        geldiğinde, güncel durumu diskteki JSON dosyasına yazar.
        """
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                # Pydantic modelini dictionary'e çevirip JSON olarak diske güzel bir formatta (indent=4) kaydet
                json.dump(config.model_dump(), f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Config kaydedilirken hata oluştu: {e}")
            return False
