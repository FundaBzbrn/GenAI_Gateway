from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import uuid

# İstemciden (Client) gelen istek modeli
class PromptRequest(BaseModel):
    text: str = Field(..., description="Analiz edilecek kullanıcı metni")
    user_id: str = Field(..., description="İsteği yapan kullanıcının benzersiz kimliği")
    conversation_history: list[dict] = Field(default_factory=list, description="Geçmiş sohbet mesajları [{'role': 'user'|'model', 'content': '...'}, ...]")
    is_test: bool = Field(default=False, description="Sadece API Limitini harcamamak için yük testlerinde True yapılır")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="İstek zamanı")
    bypass_justification: Optional[str] = Field(None, description="Bypass için sunulan gerekçe")
    bypass_action: Optional[str] = Field(None, description="Bypass aksiyonu ('bypass' veya 'request_approval')")
    company_id: Optional[int] = Field(None, description="Kullanıcının bağlı olduğu şirket ID'si (JWT token'dan gelir)")

# API'nin dışarıya döneceği standart yanıt modeli
class PromptResponse(BaseModel):
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="İşlem takip numarası")
    status: str = Field(..., description="'ALLOW', 'BLOCK', 'DLP_ALERT' veya 'PENDING'")
    category: str = Field(default="Safe", description="Tehdit türü (örn: PII, Injection)")
    processed_text: Optional[str] = Field(None, description="Maskelenmiş güvenli metin (DLP çalıştıysa)")
    llm_response: Optional[str] = Field(None, description="Yapay zeka modelinin cevabı")
    active_layers: dict = Field(default_factory=dict, description="Hangi katmanların testte aktif olduğu {'layer1': bool, 'layer2': bool, 'layer3': bool}")
    reason: Optional[str] = Field(None, description="Engellenme sebebi (varsa)")
    latency_ms: Optional[int] = Field(None, description="İşlem süresi")
    detected_entities: Optional[List[str]] = Field(None, description="Tespit edilen hassas veri türleri")
    justification: Optional[str] = Field(None, description="Bypass gerekçesi")
    bypass_status: Optional[str] = Field(None, description="Bypass durumu")