import logging
import time
from typing import Optional
from google.genai import types
from pydantic import BaseModel, Field
from app.services.llm_proxy import LLMProxy

logger = logging.getLogger(__name__)

class Layer1_5_Result(BaseModel):
    has_pii: bool = Field(description="True if any personal or sensitive information was found")
    processed_text: str = Field(description="The original text, but with sensitive entities replaced by [MASK]")
    detected_entities: list[str] = Field(description="List of entities found, e.g. ['Person Name', 'Address']")

class Layer1_5_Anonymizer:
    """
    GenAI Security Gateway - Katman 1.5 (AI DLP / Anonymizer)
    
    Regex'in (Katman 1) kaçırabileceği karmaşık, biçimsiz veya anlamsal (semantic) 
    kişisel verileri (PII), şirket sırlarını, özel adres ve isimleri 
    LLM (Gemini) kullanarak bulup maskeler.
    """
    
    @classmethod
    async def scan(cls, text: str) -> Layer1_5_Result:
        start_time = time.time()
        
        # Eğer metin çok kısaysa ve kelime içermiyorsa API çağrısına gerek yok
        if len(text.strip()) < 3:
            return Layer1_5_Result(has_pii=False, processed_text=text, detected_entities=[])
            
        client = LLMProxy.get_client("gemini-flash-lite-latest")
        if not client:
            logger.warning("Katman 1.5: Yapay zeka servisi kota aşımı nedeniyle kullanılamıyor, bypass ediliyor.")
            return Layer1_5_Result(has_pii=False, processed_text=text, detected_entities=[])
            
        try:
            system_instruction = (
                "Sen çok katı bir Veri Sızıntısı Önleme (DLP) analistisin.\n"
                "Sana verilen metindeki T.C. Kimlik numaralarını, Kredi Kartlarını, İsim-Soyisimleri, "
                "Telefon numaralarını, E-posta adreslerini, açık adresleri, ticari/şirket sırlarını ve şifreleri bul.\n"
                "Bulduğun her bir hassas veriyi '***' ile değiştir (yıldızlayarak maskele).\n"
                "Eğer metinde hiçbir hassas veri yoksa metni olduğu gibi bırak ve 'has_pii' değerini false yap.\n"
                "Sadece istenilen JSON formatında yanıt dön."
            )
            
            config = types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=Layer1_5_Result,
                system_instruction=system_instruction,
                temperature=0.0 # Deterministic output
            )
            
            response = await client.aio.models.generate_content(
                model='gemini-flash-lite-latest',
                contents=text,
                config=config
            )
            
            # Response validation (in case of JSON decode errors)
            if not response.text:
                return Layer1_5_Result(has_pii=False, processed_text=text, detected_entities=[])
                
            import json
            data = json.loads(response.text)
            
            result = Layer1_5_Result(**data)
            
            elapsed = int((time.time() - start_time) * 1000)
            if result.has_pii:
                logger.info(f"🛡️ AI Anonymizer PII buldu! ({elapsed}ms) Entities: {result.detected_entities}")
            else:
                logger.debug(f"✅ AI Anonymizer temiz buldu. ({elapsed}ms)")
                
            return result
            
        except Exception as e:
            logger.error(f"Katman 1.5 (AI Anonymizer) Hatası: {e}")
            # Fail-open mantığı: LLM çökerse sistemi kilitlememek için orijinal metni dön
            return Layer1_5_Result(has_pii=False, processed_text=text, detected_entities=[])
