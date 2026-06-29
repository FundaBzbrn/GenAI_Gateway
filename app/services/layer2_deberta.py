import logging
try:
    from transformers import pipeline  # type: ignore
except ImportError:
    pipeline = None

# Loglama ayarları (Uygulamanın durumunu konsoldan takip etmek için)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Layer2DeBERTa:
    """
    GenAI Security Gateway - Katman 2 (Zeka)
    DeBERTa-v3 modelini kullanarak anlamsal saldırı (Prompt Injection) tespiti yapar.
    """
    
    _classifier = None
    # Tezinizde bahsedilen ProtectAI'ın önceden eğitilmiş (pre-trained) modeli
    _model_name = "protectai/deberta-v3-base-prompt-injection-v2"
    
    # Kullanıcı tarafından eğitilmiş yerel (fine-tuned) modelin yolu
    import os
    _local_model_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "models", "fine_tuned_deberta")

    @classmethod
    def load_model(cls):
        """
        Modeli hafızaya yükler. API ayağa kalktığında bir kere çalıştırılması performansı artırır.
        WINDOWS MKL CRASH FIX: KMP_DUPLICATE_LIB_OK=TRUE eklendi.
        """
        if cls._classifier is None:
            import os
            # Windows NumPy/MKL crash workaround
            os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
            
            try:
                if pipeline is None:
                    raise ImportError("transformers kütüphanesi kurulu değil")
                
                # Önce kullanıcıya ait ince ayar yapılmış (fine-tuned) model var mı kontrol et
                if os.path.exists(cls._local_model_path):
                    logger.info(f"⏳ Katman 2 (DeBERTa) yükleniyor [FINE-TUNED YEREL MODEL]: {cls._local_model_path}")
                    cls._classifier = pipeline("text-classification", model=cls._local_model_path)
                else:
                    logger.info(f"⏳ Katman 2 (DeBERTa) yükleniyor [VARSAYILAN MODEL]: {cls._model_name}")
                    cls._classifier = pipeline("text-classification", model=cls._model_name)
                    
                logger.info("✅ Katman 2 (DeBERTa) başarıyla yüklendi!")
            except Exception as e:
                logger.error(f"❌ Katman 2 yüklenirken hata oluştu: {e}")
                cls._classifier = None  # Fail-open mode

    _cache = {}

    @classmethod
    def predict_score(cls, text: str) -> float:
        """
        Metni analiz edip 0.0 (Güvenli) ile 1.0 (Kesin Saldırı) arasında bir skor döner.
        """
        # Önbellekte varsa hemen dön (Performans için)
        if text in cls._cache:
            return cls._cache[text]

        if cls._classifier is None:
            cls.load_model()
            
        # Eğer model hala yüklenemediyse (örn: internet sorunu), sistemi kilitlememek için 0.0 dön (Fail-Open)
        if cls._classifier is None:
            logger.warning("Katman 2 atlanıyor: Model aktif değil!")
            return 0.0

        # Performans: Çok uzun metinleri (örn: PDF) DeBERTa'ya göndermeden önce kırp (İlk 1000 ve Son 1000 karakter)
        process_text = text
        if len(process_text) > 2000:
            process_text = process_text[:1000] + " ... [TRUNCATED] ... " + process_text[-1000:]

        # Modeli çalıştır ve sonucu al
        result = cls._classifier(process_text)
        
        # Sonuç genellikle [{'label': 'INJECTION', 'score': 0.99}] formatındadır
        score = 0.0
        for res in result:
            if res['label'] == 'INJECTION':
                score = res['score']
            elif res['label'] == 'SAFE':
                score = 1.0 - res['score']
                
        final_score = round(score, 3)
        
        # Önbelleği sınırla (Memory Leak önlemek için)
        if len(cls._cache) > 5000:
            cls._cache.clear()
            
        cls._cache[text] = final_score
        return final_score