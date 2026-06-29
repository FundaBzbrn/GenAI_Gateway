import re
import json
import os
from dataclasses import dataclass

@dataclass
class Layer1Result:
    """
    Katman 1 (Regex & Blacklist) taramasının sonucunu taşıyan Veri Sınıfı (Data Class).
    Tarama işlemi bittikten sonra sonuçlar bir sözlük (dictionary) yerine 
    bu sınıfa dönüştürülerek Controller'a daha güvenli ve tip destekli (type-hinted) iletilir.
    """
    is_blocked: bool                # İşlem doğrudan engellendi mi? (Artık kullanılmıyor, Fail-Open mantığına geçildi)
    has_pii: bool                   # Metin içinde T.C. Kimlik, Kredi Kartı gibi PII verisi bulundu mu?
    processed_text: str             # Eğer PII bulunduysa, "12*******34" şeklinde maskelenmiş temiz metin.
    detected_entities: list[str] = None  # Hangi PII türleri bulundu? (Örn: ["T.C. Kimlik No", "Email"])
    blacklist_hits: list[str] = None     # Metinde yakalanan yasaklı kelimeler (Bağlam analizi için Layer 3'e gönderilecek)


class Layer1Regex:
    """
    GenAI Security Gateway - Katman 1 (Hızlı Refleks Katmanı)
    Amacı: Gelen metni 5 milisaniyenin altında çok hızlı bir statik taramadan geçirmek.
    İşlevleri:
    1. Metin içindeki Yasaklı Kelimeleri (Blacklist) bulmak (ancak doğrudan engellemez, bağlama bırakır).
    2. DLP (Data Loss Prevention) uygulayarak, dışarı çıkmaması gereken hassas verileri yıldızlayarak (****) maskelemek.
    """

    # Yasaklı kelimeler (Blacklist) dışarıdan yükleniyor. 
    # Bu liste Admin panelinden de anlık olarak güncellenebilir.
    from app.services.core_blacklist import CORE_BLACKLIST
    
    DYNAMIC_BLACKLIST_PATH = os.path.join(os.path.dirname(__file__), "dynamic_blacklist.json")
    
    @classmethod
    def get_blacklist(cls):
        dynamic_list = []
        if os.path.exists(cls.DYNAMIC_BLACKLIST_PATH):
            try:
                with open(cls.DYNAMIC_BLACKLIST_PATH, "r", encoding="utf-8") as f:
                    dynamic_list = json.load(f)
            except Exception:
                pass
        return cls.CORE_BLACKLIST + dynamic_list

    @classmethod
    async def learn_from_attack(cls, prompt: str):
        """
        Gelen saldırı promptunu LLM Yargıca (Gemini) gönderir.
        LLM, cümlenin içinden günlük kelimeleri (isim, nesne vb.) atarak
        SADECE siber saldırı/manipülasyon (exploit, bypass, hack) kelimelerini çıkarır.
        Sistem bu teknik kelimeleri dynamic_blacklist.json dosyasına ekler.
        """
        try:
            from app.services.layer3_llm_judge import Layer3LLMJudge
            client, model_name, key_info = Layer3LLMJudge._get_client()
            
            if not client:
                return # API Key yoksa öğrenme yapma
                
            system_instruction = (
                "You are an expert cybersecurity AI. Your task is to extract ONLY the malicious, technical, "
                "or rule-breaking keywords from the given attack prompt. Ignore normal names, daily words (like fatma, otel, para), "
                "or stop words. Return ONLY a comma-separated list of the extracted keywords in lowercase. "
                "If there are no specific malicious keywords, return 'NONE'."
            )
            
            response = await client.aio.models.generate_content(
                model=model_name,
                contents=prompt,
                config={
                    "system_instruction": system_instruction,
                    "temperature": 0.1
                }
            )
            
            result = response.text.strip().lower()
            if result == "none" or not result:
                return
            
            # LLM'in verdiği kelimeleri virgülle ayır, boşlukları temizle
            extracted_words = [w.strip() for w in result.split(",") if len(w.strip()) > 2]
            
            if not extracted_words:
                return
                
            dynamic_list = []
            if os.path.exists(cls.DYNAMIC_BLACKLIST_PATH):
                try:
                    with open(cls.DYNAMIC_BLACKLIST_PATH, "r", encoding="utf-8") as f:
                        dynamic_list = json.load(f)
                except Exception:
                    pass
                    
            added = False
            for nw in extracted_words:
                if nw not in dynamic_list and nw not in cls.CORE_BLACKLIST:
                    dynamic_list.append(nw)
                    added = True
                    
            if added:
                with open(cls.DYNAMIC_BLACKLIST_PATH, "w", encoding="utf-8") as f:
                    json.dump(dynamic_list, f, ensure_ascii=False, indent=2)
                    
        except Exception as e:
            # LLM hatası olursa sistemi kilitleme, sessizce geç
            pass

    # --- PII (Hassas Veri) Tespit Desenleri (Düzenli İfadeler - Regular Expressions) ---
    
    # T.C. Kimlik Numarası Formatı: 11 haneli, aralarda boşluk olabilir.
    TC_PATTERN = re.compile(r'\b[1-9](?:[\s]*\d){10}\b')
    
    # Kredi Kartı Numarası Formatı: 16 haneli (kullanıcılar araya boşluk veya tire koymuş olabilir)
    CC_PATTERN = re.compile(r'\b(?:\d[ -]*?){15,16}\b')
    
    # Standart E-posta Adresi Formatı (isim@domain.com vb.)
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
    
    # Türkiye Formatlı Cep Telefonu Formatı: (+90, 0, parantezler, boşluklar vb.)
    PHONE_PATTERN = re.compile(r'\b(?:\+90|0090|0)?[\s]*\(?5\d{2}\)?[\s.-]*\d{3}[\s.-]*\d{2}[\s.-]*\d{2}\b')
    
    # IBAN Formatı: TR ile başlar ve devamında 24 karakter içerir (aralarda boşluk olabilir).
    IBAN_PATTERN = re.compile(r'\bTR[\s]*\d{2}(?:[\s]*[0-9A-Z]){22}\b', re.IGNORECASE)

    @classmethod
    def scan(cls, text: str, dynamic_blacklist: list = None) -> Layer1Result:
        """
        Gelen istem (prompt) üzerinde PII maskeleme ve yasaklı kelime taraması yapar.
        Eğer dinamik bir blacklist verilirse (admin arayüzünden gelen), mevcut listeyle birleştirir.
        """
        has_pii = False
        processed_text = text
        detected_entities = []
        blacklist_hits = []

        # ---------------------------------------------------------------------
        # 1. YASAKLI KELİME (BLACKLIST) KONTROLÜ
        # ---------------------------------------------------------------------
        # Metni küçük harfe çevirerek büyük-küçük harf duyarlılığını ortadan kaldırıyoruz.
        text_lower = text.lower()
        words_to_check = cls.get_blacklist() + (dynamic_blacklist if dynamic_blacklist is not None else [])
        
        if words_to_check:
            # Optimizasyon: Binlerce kelimeyi tek tek aramak yerine, tüm kelimeleri birleştirip 
            # tek bir dev Regex oluşturuyoruz. (Örn: \b(bomba|hack|intihar)\b)
            # \b kullanımı çok önemlidir: "hack" kelimesi aranırken "hacker" veya "hackathon" kelimesini yakalamamızı engeller.
            pattern_str = r'\b(' + '|'.join(map(re.escape, map(str.lower, words_to_check))) + r')\b'
            combined_pattern = re.compile(pattern_str)
            
            # Eşleşen kelimeleri bir küme (set) içine alarak tekrarlardan kurtuluyoruz
            matches = set(combined_pattern.findall(text_lower))
            blacklist_hits.extend(list(matches))
        
        # NOT: Önceden blacklist yakalandığında sistem direkt BLOCK kararı veriyordu.
        # Artık doğrudan engellemek yerine eşleşmeleri kaydediyoruz, Katman 3 (LLM) cümleyi okuyup
        # "bomba nasıl yapılır?" ile "bomba gibi bir şarkı" arasındaki farkı anlayarak son kararı verecek.

        # ---------------------------------------------------------------------
        # 2. HASSAS VERİ (PII) MASKELEME - DATA LOSS PREVENTION (DLP)
        # ---------------------------------------------------------------------
        
        # Alt fonksiyonlar: Her bir Regex eşleşmesinde veriyi nasıl gizleyeceğimizi belirliyoruz.
        def mask_tc(match):
            tc = match.group(0)
            return f"{tc[:2]}*******{tc[-2:]}"  # İlk ve son 2 hane açık kalır (Örn: 12*******34)

        def mask_cc(match):
            cc = match.group(0)
            clean_cc = re.sub(r'[- ]', '', cc) # Boşlukları ve tireleri temizle
            return f"****-****-****-{clean_cc[-4:]}" # Sadece son 4 hanesi kalsın

        def mask_email(match):
            email = match.group(0)
            parts = email.split('@')
            if len(parts[0]) > 2:
                return f"{parts[0][:2]}***@{parts[1]}" # İsmin bir kısmı gizlenir
            return f"***@{parts[1]}"

        def mask_phone(match):
            return "***-***-****" # Telefon numarası tamamen gizlenir

        def mask_iban(match):
            iban = match.group(0)
            return f"{iban[:4]}****{iban[-4:]}" # Sadece başı ve sonu görünür

        # Her bir desen (pattern) için metni sırayla tarayıp bulduğu yerleri yıldızlandırıyoruz.
        if cls.TC_PATTERN.search(processed_text):
            has_pii = True
            processed_text = cls.TC_PATTERN.sub(mask_tc, processed_text)
            detected_entities.append("T.C. Kimlik No")

        if cls.CC_PATTERN.search(processed_text):
            has_pii = True
            processed_text = cls.CC_PATTERN.sub(mask_cc, processed_text)
            detected_entities.append("Kredi Kartı")

        if cls.EMAIL_PATTERN.search(processed_text):
            has_pii = True
            processed_text = cls.EMAIL_PATTERN.sub(mask_email, processed_text)
            detected_entities.append("E-posta Adresi")

        if cls.PHONE_PATTERN.search(processed_text):
            has_pii = True
            processed_text = cls.PHONE_PATTERN.sub(mask_phone, processed_text)
            detected_entities.append("Telefon Numarası")

        if cls.IBAN_PATTERN.search(processed_text):
            has_pii = True
            processed_text = cls.IBAN_PATTERN.sub(mask_iban, processed_text)
            detected_entities.append("IBAN")

        # İşlemler tamamlandı, sonucu döndürüyoruz.
        return Layer1Result(
            is_blocked=False,  # Artık hiçbir şeyi katı bir şekilde direkt engellemiyoruz
            has_pii=has_pii, 
            processed_text=processed_text,
            detected_entities=detected_entities,
            blacklist_hits=blacklist_hits if blacklist_hits else None
        )