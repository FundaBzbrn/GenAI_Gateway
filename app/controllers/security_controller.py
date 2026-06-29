"""
GenAI Security Gateway - Güvenlik Kontrolcüsü (Security Controller)

Uygulamanın kalbidir. Kullanıcılardan veya dış sistemlerden gelen tüm metin (prompt) 
istekleri ilk olarak bu dosyaya düşer. Gelen istekler sırasıyla:
1. Katman 1 (Regex & Blacklist)
2. Katman 2 (DeBERTa AI Modeli)
3. Katman 3 (LLM Judge)
kontrollerinden geçirilir ve sonuç veritabanına kaydedilir.
Sistem "Fail-Open" veya "Fail-Closed" mantığına göre karar vererek istemciye döner.
"""

import time
import uuid
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Depends, Request
from app.models.schemas import PromptRequest, PromptResponse
from app.services.layer1_regex import Layer1Regex, Layer1Result
from app.services.layer1_5_anonymizer import Layer1_5_Anonymizer
from app.services.layer2_deberta import Layer2DeBERTa
from app.services.layer3_llm_judge import Layer3LLMJudge
from app.services.database_manager import DatabaseManager
from app.services.llm_proxy import LLMProxy
from app.config_manager import ConfigManager

# Basit bellek-içi önbellek (In-Memory Cache). 
# Aynı prompt tekrar gelirse saniyesinde dönmek için kullanılır.
from typing import Dict, Any
_PROMPT_CACHE: Dict[str, dict] = {}

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/analyze", response_model=PromptResponse, tags=["Security Analysis"])
async def analyze_prompt(request: PromptRequest, http_req: Request = None):
    """
    Kullanıcıdan gelen prompt'u 3 katmanlı güvenlik analizinden (Fail-Fast) geçirir.

    - Katman 1 (Refleks): Regex blacklist + PII maskeleme — <5ms
    - Katman 2 (Zeka): DeBERTa AI prompt injection tespiti — ~100ms
    - Katman 3 (Bilgelik): GPT-4o-mini LLM Judge (sadece gri bölgede) — ~500ms
    """
    start_time = time.time()
    log_id = str(uuid.uuid4())
    ai_score = 0.0
    stopped_at_layer = "None"

    # Başlangıçta metni orijinal haliyle işleme al
    processed_text = request.text

    # Config ayarlarını çek
    config = ConfigManager.load_config()

    # JWT token varsa company_id ve user_id JWT'den al (güvenilirlik için)
    if http_req:
        auth_header = http_req.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                import jwt as pyjwt
                from app.controllers.auth_controller import SECRET_KEY, ALGORITHM
                token_str = auth_header.split(" ", 1)[1]
                jwt_payload = pyjwt.decode(token_str, SECRET_KEY, algorithms=[ALGORITHM])
                # JWT'den gelen company_id request'teki değeri override eder
                if jwt_payload.get("company_id"):
                    request.company_id = jwt_payload["company_id"]
                # JWT'den gelen username (sub) request user_id'yi override eder
                if jwt_payload.get("sub"):
                    request.user_id = jwt_payload["sub"]
            except Exception as jwt_err:
                logger.debug(f"JWT okuma atlandı: {jwt_err}")

    # JWT yoksa veya company_id set edilmemişse veritabanından kullanıcı adına göre şirketi bul
    if not request.company_id and request.user_id:
        user_info = await DatabaseManager.get_user_by_username(request.user_id)
        if user_info and user_info.get("company_id"):
            request.company_id = user_info["company_id"]

    # ══════════════════════════════════════════════════════════
    # ÖNBELLEK (CACHE) KONTROLÜ
    # Aynı soru daha önce geldiyse yapay zekayı hiç yormadan anında dön
    # ══════════════════════════════════════════════════════════
    if not request.bypass_action and not request.is_test and request.text in _PROMPT_CACHE:
        cached = _PROMPT_CACHE[request.text]
        latency = int((time.time() - start_time) * 1000)
        
        await DatabaseManager.log_security_event(
            log_id=log_id, user_id=request.user_id,
            masked_prompt=request.text, action=cached["status"],
            category=cached["category"], stopped_at_layer="Cache (Önbellek)",
            ai_score=cached["ai_score"], latency_ms=latency,
            company_id=request.company_id
        )
        logger.info(f"⚡ CACHE HIT (Önbellek) | user={request.user_id} | {latency}ms")
        
        return PromptResponse(
            log_id=log_id, status=cached["status"], category=cached["category"],
            reason=cached.get("reason"),
            processed_text=request.text,
            llm_response=cached["llm_response"],
            active_layers={"layer1": config.layer_regex, "layer2": config.layer_deberta, "layer3": config.layer_llm},
            latency_ms=latency,
            detected_entities=cached.get("detected_entities", [])
        )

    # ══════════════════════════════════════════════════════════
    # BYPASS VEYA ONAY TALEBİ KONTROLÜ
    # ══════════════════════════════════════════════════════════
    if request.bypass_action == "bypass":
        if not request.bypass_justification:
            raise HTTPException(status_code=400, detail="Bypass için gerekçe belirtilmelidir.")
        
        # DLP sonucunu maskelemek için regex çalıştır (loglarda maskeli saklamak için)
        temp_result = Layer1Regex.scan(processed_text, config.blacklist)
        masked_prompt = temp_result.processed_text
        
        latency = int((time.time() - start_time) * 1000)
        await DatabaseManager.log_security_event(
            log_id=log_id, user_id=request.user_id,
            masked_prompt=masked_prompt, action="ALLOW",
            category="PII_BYPASS", stopped_at_layer="None",
            ai_score=0.0, latency_ms=latency,
            company_id=request.company_id,
            justification=request.bypass_justification,
            bypass_status="Bypassed (Red Flag)"
        )
        
        logger.warning(f"🔴 RED FLAG BYPASS [PII_BYPASS] user={request.user_id} | Gerekçe={request.bypass_justification} | {latency}ms")
        
        if request.is_test:
            llm_response_text = "TEST_MODE_ACTIVE: API limiti korunması için yapay zeka cevabı atlandı."
        else:
            llm_response_text = await LLMProxy.generate_response(request.text, request.conversation_history)
            
        return PromptResponse(
            log_id=log_id, status="ALLOW", category="PII_BYPASS",
            processed_text=request.text,  # Bypass edildiği için orijinal metin
            llm_response=llm_response_text,
            active_layers={"layer1": config.layer_regex, "layer2": config.layer_deberta, "layer3": config.layer_llm},
            latency_ms=latency,
            justification=request.bypass_justification,
            bypass_status="Bypassed (Red Flag)"
        )

    elif request.bypass_action == "request_approval":
        if not request.bypass_justification:
            raise HTTPException(status_code=400, detail="Onay talebi için gerekçe belirtilmelidir.")
        
        temp_result = Layer1Regex.scan(processed_text, config.blacklist)
        masked_prompt = temp_result.processed_text
        
        latency = int((time.time() - start_time) * 1000)
        await DatabaseManager.log_security_event(
            log_id=log_id, user_id=request.user_id,
            masked_prompt=masked_prompt, action="PENDING",
            category="PII_PENDING", stopped_at_layer="None",
            ai_score=0.0, latency_ms=latency,
            company_id=request.company_id,
            justification=request.bypass_justification,
            bypass_status="Pending Approval"
        )
        
        logger.info(f"📨 ONAY BEKLİYOR [PII_PENDING] user={request.user_id} | Gerekçe={request.bypass_justification}")
        
        return PromptResponse(
            log_id=log_id, status="PENDING", category="PII_PENDING",
            processed_text=masked_prompt,
            llm_response="İsteğiniz yönetici onayına gönderildi. Onaylandıktan sonra işlenecektir.",
            active_layers={"layer1": config.layer_regex, "layer2": config.layer_deberta, "layer3": config.layer_llm},
            latency_ms=latency,
            justification=request.bypass_justification,
            bypass_status="Pending Approval"
        )

    # ══════════════════════════════════════════════════════════
    # KATMAN 1: REFLEKS (Regex & DLP - PII Maskeleme)
    # ══════════════════════════════════════════════════════════
    if request.bypass_action == "auto_mask":
        processed_text = request.text
        regex_result = Layer1Result(is_blocked=False, has_pii=False, processed_text=processed_text)
        final_processed_text = processed_text
        has_pii_final = False
        detected_entities = []
        logger.info(f"✅ OTO-MASKE ONAYI [auto_mask] user={request.user_id} | Layer 1 atlanıyor.")
    elif config.layer_regex:
        regex_result = Layer1Regex.scan(processed_text, config.blacklist)

        # ══════════════════════════════════════════════════════════
        # KATMAN 1.5: BLACKLIST BAĞLAM ANALİZİ (Akıllı Filtreleme)
        # Yasaklı kelime bulunduysa → hemen engellemek yerine LLM Judge ile
        # anlam bağlamını kontrol et. "bomba nedir?" → SAFE, "bomba yap" → UNSAFE
        # ══════════════════════════════════════════════════════════
        if regex_result.blacklist_hits:
            matched_str = ', '.join(regex_result.blacklist_hits)
            logger.info(f"🔍 Blacklist eşleşmesi: [{matched_str}] — Bağlam analizi başlatılıyor...")
            
            if config.layer_llm and not request.is_test:
                # LLM Judge ile bağlam analizi yap
                blacklist_verdict = await Layer3LLMJudge.evaluate_blacklist_context(
                    text=processed_text,
                    matched_words=regex_result.blacklist_hits,
                    history=request.conversation_history
                )
                
                if blacklist_verdict == "UNSAFE":
                    # ❌ LLM Judge onayladı: gerçekten zararlı niyet
                    stopped_at_layer = "Layer1+Layer3"
                    latency = int((time.time() - start_time) * 1000)
                    await DatabaseManager.log_security_event(
                        log_id=log_id, user_id=request.user_id,
                        masked_prompt=processed_text, action="BLOCK",
                        category="Blacklist", stopped_at_layer=stopped_at_layer,
                        ai_score=0.0, latency_ms=latency,
                        company_id=request.company_id
                    )
                    logger.warning(f"🚫 BLOCK [Layer1+Layer3/Blacklist] user={request.user_id} | kelimeler=[{matched_str}] | {latency}ms")
                    
                    block_explanation = await LLMProxy.generate_block_explanation(
                        prompt=request.text,
                        category="Blacklist",
                        reason=f"Yasaklı kelime tespit edildi ve bağlam analizi zararlı niyet buldu: {matched_str}"
                    )
                    
                    return PromptResponse(
                        log_id=log_id, status="BLOCK", category="Blacklist",
                        reason=f"Yasaklı kelime tespit edildi ve bağlam analizi zararlı niyet buldu: {matched_str}",
                        llm_response=block_explanation,
                        active_layers={"layer1": config.layer_regex, "layer2": config.layer_deberta, "layer3": config.layer_llm},
                        latency_ms=latency
                    )
                else:
                    # ✅ LLM Judge: Eğitim/bilgi amaçlı sorgu — devam et
                    logger.info(f"✅ Blacklist kelimesi [{matched_str}] bulundu ama bağlam GÜVENLİ. Devam ediliyor.")
            else:
                # LLM Judge kapalı veya test modu → fail-secure: engelle
                stopped_at_layer = "Layer1"
                latency = int((time.time() - start_time) * 1000)
                await DatabaseManager.log_security_event(
                    log_id=log_id, user_id=request.user_id,
                    masked_prompt=processed_text, action="BLOCK",
                    category="Blacklist", stopped_at_layer=stopped_at_layer,
                    ai_score=0.0, latency_ms=latency,
                    company_id=request.company_id
                )
                logger.warning(f"🚫 BLOCK [Layer1/Blacklist] user={request.user_id} | LLM Judge kapalı, fail-secure | {latency}ms")
                
                block_explanation = None
                if not request.is_test:
                    block_explanation = await LLMProxy.generate_block_explanation(
                        prompt=request.text,
                        category="Blacklist",
                        reason="Yasaklı kelime tespit edildi."
                    )
                
                return PromptResponse(
                    log_id=log_id, status="BLOCK", category="Blacklist",
                    reason="Yasaklı kelime tespit edildi.",
                    llm_response=block_explanation,
                    active_layers={"layer1": config.layer_regex, "layer2": config.layer_deberta, "layer3": config.layer_llm},
                    latency_ms=latency
                )

        # ══════════════════════════════════════════════════════════
        # KATMAN 1.5: YAPAY ZEKA ANONYMİZER
        # Regex'in kaçırdığı özel isimleri, adresleri vb. maskeler
        # ══════════════════════════════════════════════════════════
        if not request.is_test:
            anonymizer_result = await Layer1_5_Anonymizer.scan(regex_result.processed_text)
            final_processed_text = anonymizer_result.processed_text
            has_pii_final = regex_result.has_pii or anonymizer_result.has_pii
            
            # Entity'leri birleştir
            detected_entities = regex_result.detected_entities.copy() if regex_result.detected_entities else []
            if anonymizer_result.detected_entities:
                for e in anonymizer_result.detected_entities:
                    if e not in detected_entities:
                        detected_entities.append(e)
        else:
            final_processed_text = regex_result.processed_text
            has_pii_final = regex_result.has_pii
            detected_entities = regex_result.detected_entities

        # PII varsa maskele, durdur ve DLP_ALERT döner
        if has_pii_final:
            stopped_at_layer = "Layer1.5" if anonymizer_result.has_pii else "Layer1"
            latency = int((time.time() - start_time) * 1000)
            await DatabaseManager.log_security_event(
                log_id=log_id, user_id=request.user_id,
                masked_prompt=final_processed_text, action="BLOCK",
                category="PII", stopped_at_layer=stopped_at_layer,
                ai_score=0.0, latency_ms=latency,
                company_id=request.company_id,
                bypass_status="Blocked (DLP Alert)"
            )
            logger.warning(f"🔒 DLP ALERT [Layer1.5/PII] user={request.user_id} | {latency}ms")
            
            return PromptResponse(
                log_id=log_id, status="DLP_ALERT", category="PII",
                reason="KVKK veya kurum politikalarına aykırı hassas veri tespit edildi.",
                processed_text=final_processed_text,
                active_layers={"layer1": config.layer_regex, "layer2": config.layer_deberta, "layer3": config.layer_llm},
                latency_ms=latency,
                detected_entities=detected_entities,
                bypass_status="Blocked (DLP Alert)"
            )
            
        processed_text = final_processed_text
    else:
        # Regex motoru kapalı ise, sadece dummy result oluştur (Loglama için Pii=False varsayarız)
        regex_result = Layer1Result(is_blocked=False, has_pii=False, processed_text=processed_text)

    # ══════════════════════════════════════════════════════════
    # KATMAN 2: ZEKA (DeBERTa AI Modeli)
    # ══════════════════════════════════════════════════════════
    THRESHOLD_HIGH = config.ai_threshold
    THRESHOLD_LOW  = 0.60   # Bu skoru aşan → LLM Judge'a gönder (0.55 çok düşüktü, Türkçe günlük sorular tetikleniyordu)

    deberta_blocked = False
    if config.layer_deberta:
        ai_score = Layer2DeBERTa.predict_score(processed_text)
        logger.info(f"🤖 DeBERTa skoru: {ai_score} | user={request.user_id}")

        if ai_score > THRESHOLD_HIGH:
            deberta_blocked = True
    else:
        ai_score = 0.0

    # ══════════════════════════════════════════════════════════
    # KATMAN 3: BİLGELİK (LLM Yargıç)
    # Hibrit doğrulama: Eğer DeBERTa engelleme kararı verdiyse veya skor gri bölgedeyse
    # ve LLM Judge aktifse, Gemini Yargı ile teyit et.
    # ══════════════════════════════════════════════════════════
    
    # LLM Judge ne zaman çalışacak?
    # 1. LLM Judge aktif ve test modunda değilsek
    # VE EĞER:
    #   a) DeBERTa engelleme kararı verdiyse (deberta_blocked == True) -> Teyit için
    #   b) VEYA DeBERTa skoru gri bölgedeyse (ai_score >= THRESHOLD_LOW) -> İnceleme için
    #   c) VEYA DeBERTa katmanı kapalıysa -> Tüm mesajları incelemesi için (fail-secure)
    # ✅ OPTİMİZASYON: Blacklist bağlam analizi zaten SAFE dönmüşse ve DeBERTa
    # bloklamıyorsa, Layer 3'ü tekrar çağırmaya gerek yok (API çağrısı tasarrufu)
    blacklist_already_cleared = bool(regex_result.blacklist_hits) and config.layer_llm
    
    need_llm_judge = config.layer_llm and not request.is_test and (
        deberta_blocked or 
        (config.layer_deberta and ai_score >= THRESHOLD_LOW and not blacklist_already_cleared) or 
        (not config.layer_deberta and not blacklist_already_cleared)
    )

    if need_llm_judge:
        llm_verdict = await Layer3LLMJudge.evaluate(processed_text, request.conversation_history)
        logger.info(f"⚖️ LLM Yargıç kararı: {llm_verdict} (DeBERTa Skoru: {ai_score:.2f}, Blok Kararı: {deberta_blocked}) | user={request.user_id}")

        if llm_verdict == "UNSAFE":
            stopped_at_layer = "Layer3" if not deberta_blocked else "Layer2+Layer3"
            category = "Injection" if deberta_blocked else "Policy Violation"
            reason = "Yapay Zeka Yargıç anlamsal bir saldırı veya manipülasyon tespit etti."
            
            latency = int((time.time() - start_time) * 1000)
            await DatabaseManager.log_security_event(
                log_id=log_id, user_id=request.user_id,
                masked_prompt=processed_text, action="BLOCK",
                category=category, stopped_at_layer=stopped_at_layer,
                ai_score=ai_score, latency_ms=latency,
                company_id=request.company_id
            )
            logger.warning(f"🚫 BLOCK [{stopped_at_layer}/{category}] | {latency}ms")
            
            block_explanation = await LLMProxy.generate_block_explanation(
                prompt=request.text,
                category=category,
                reason=reason
            )
            
            if not request.is_test:
                _PROMPT_CACHE[request.text] = {
                    "status": "BLOCK", "category": category, 
                    "reason": reason, "llm_response": block_explanation, 
                    "ai_score": ai_score
                }
                
            return PromptResponse(
                log_id=log_id, status="BLOCK", category=category,
                reason=reason,
                llm_response=block_explanation,
                active_layers={"layer1": config.layer_regex, "layer2": config.layer_deberta, "layer3": config.layer_llm},
                latency_ms=latency
            )
        else:
            if deberta_blocked:
                logger.info(f"🛡️ False Positive Tespiti Önleme: DeBERTa engelleme istedi ({ai_score:.2f}) fakat LLM Yargıç SAFE dedi. İzin veriliyor.")
    
    elif deberta_blocked:
        stopped_at_layer = "Layer2"
        latency = int((time.time() - start_time) * 1000)
        await DatabaseManager.log_security_event(
            log_id=log_id, user_id=request.user_id,
            masked_prompt=processed_text, action="BLOCK",
            category="Injection", stopped_at_layer=stopped_at_layer,
            ai_score=ai_score, latency_ms=latency,
            company_id=request.company_id
        )
        logger.warning(f"🚫 BLOCK [Layer2/Injection] score={ai_score} | {latency}ms")
        
        block_explanation = await LLMProxy.generate_block_explanation(
            prompt=request.text,
            category="Injection",
            reason=f"Saldırı girişimi tespit edildi. (AI Skoru: {ai_score:.2f})"
        )
        
        if not request.is_test:
            _PROMPT_CACHE[request.text] = {
                "status": "BLOCK", "category": "Injection", 
                "reason": f"Saldırı girişimi tespit edildi. (AI Skoru: {ai_score:.2f})", 
                "llm_response": block_explanation, 
                "ai_score": ai_score
            }
            
        return PromptResponse(
            log_id=log_id, status="BLOCK", category="Injection",
            reason=f"Saldırı girişimi tespit edildi. (AI Skoru: {ai_score:.2f})",
            llm_response=block_explanation,
            active_layers={"layer1": config.layer_regex, "layer2": config.layer_deberta, "layer3": config.layer_llm},
            latency_ms=latency
        )

    # ══════════════════════════════════════════════════════════
    # GÜVENLİ İSTEK — Tüm katmanlardan geçti
    # ══════════════════════════════════════════════════════════
    stopped_at_layer = "None"
    category = "DLP" if regex_result.has_pii else "Safe"
    latency = int((time.time() - start_time) * 1000)

    await DatabaseManager.log_security_event(
        log_id=log_id, user_id=request.user_id,
        masked_prompt=processed_text, action="ALLOW",
        category=category, stopped_at_layer=stopped_at_layer,
        ai_score=ai_score, latency_ms=latency,
        company_id=request.company_id
    )
    logger.info(f"✅ ALLOW [{category}] | Security Latency: {latency}ms")

    # Yapay zeka'dan cevabı al (sohbet geçmişiyle birlikte)
    if request.is_test:
        llm_response_text = "TEST_MODE_ACTIVE: API limiti korunması için yapay zeka cevabı atlandı."
    else:
        llm_response_text = await LLMProxy.generate_response(processed_text, request.conversation_history)

    if not request.is_test:
        _PROMPT_CACHE[request.text] = {
            "status": "ALLOW", "category": category, 
            "reason": None, "llm_response": llm_response_text, 
            "ai_score": ai_score
        }

    return PromptResponse(
        log_id=log_id, status="ALLOW", category=category,
        processed_text=processed_text,
        llm_response=llm_response_text,
        active_layers={"layer1": config.layer_regex, "layer2": config.layer_deberta, "layer3": config.layer_llm},
        latency_ms=latency
    )


# ══════════════════════════════════════════════════════════════════════════════
# 🔐 ADMIN CONFIGURATION ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/config", tags=["Admin Config"])
async def get_config():
    """
    Tüm sistemin konfigürasyonunu döndür.
    
    Returns:
    - layer_regex: Layer 1 (DLP) aktif mi?
    - layer_deberta: Layer 2 (AI Injection Detection) aktif mi?
    - layer_llm: Layer 3 (LLM Judge) aktif mi?
    - ai_threshold: AI threshold değeri (0.30 - 0.95)
    - blacklist: Yasaklı kelimeler listesi
    """
    config = ConfigManager.load_config()
    logger.info(f"📖 Config getirilerek görüntülendi")
    return config.model_dump()


@router.put("/config/blacklist", tags=["Admin Config"])
async def update_blacklist(
    operation: str = Query(..., description="'add' veya 'remove'"),
    word: str = Query(...)
):
    """
    Blacklist'e kelime ekle/sil.
    
    Query Parameters:
    - operation: 'add' (ekle) veya 'remove' (sil)
    - word: Eklenecek/silinecek kelime
    
    Örnek:
    - PUT /api/v1/config/blacklist?operation=add&word=bomba
    - PUT /api/v1/config/blacklist?operation=remove&word=bomba
    """
    if operation not in ["add", "remove"]:
        raise HTTPException(
            status_code=400,
            detail="operation 'add' veya 'remove' olmalı"
        )

    config = ConfigManager.load_config()

    if operation == "add":
        if word.lower() in [w.lower() for w in config.blacklist]:
            raise HTTPException(
                status_code=400,
                detail=f"'{word}' zaten blacklist'te var"
            )
        config.blacklist.append(word)
        logger.warning(f"➕ Blacklist'e kelime eklendi: {word}")
    else:  # remove
        if word not in config.blacklist:
            raise HTTPException(
                status_code=404,
                detail=f"'{word}' blacklist'te bulunamadı"
            )
        config.blacklist.remove(word)
        logger.warning(f"➖ Blacklist'ten kelime silindi: {word}")

    success = ConfigManager.save_config(config)
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Config kaydedilemedi"
        )

    return {
        "message": f"Blacklist başarıyla güncellendi",
        "operation": operation,
        "word": word,
        "blacklist": config.blacklist
    }


@router.put("/config/threshold", tags=["Admin Config"])
async def update_threshold(
    threshold: float = Query(...)
):
    """
    DeBERTa AI threshold değerini güncelle.
    
    Query Parameters:
    - threshold: Yeni threshold değeri (0.30 - 0.95 arası olmalı)
    
    Örnek:
    - PUT /api/v1/config/threshold?threshold=0.70

    ℹ️ Threshold değeri ne kadar yüksek olursa, sistem o kadar katı olur.
    - 0.30: Çok hassas (yanlış pozitif çok olur)
    - 0.75: Dengeli (default)
    - 0.95: Çok katı (saldırı kaçabilir)
    """
    if not (0.30 <= threshold <= 0.95):
        raise HTTPException(
            status_code=400,
            detail="Threshold değeri 0.30 ile 0.95 arasında olmalı"
        )

    config = ConfigManager.load_config()
    old_threshold = config.ai_threshold
    config.ai_threshold = threshold

    success = ConfigManager.save_config(config)
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Config kaydedilemedi"
        )

    logger.warning(f"📊 AI Threshold güncellendi: {old_threshold:.2f} → {threshold:.2f}")

    return {
        "message": "Threshold başarıyla güncellendi",
        "old_threshold": old_threshold,
        "new_threshold": threshold
    }


@router.put("/config/layers", tags=["Admin Config"])
async def update_layers(
    layer1: bool = Query(None, description="Layer 1 (DLP) aktif mi?"),
    layer2: bool = Query(None, description="Layer 2 (DeBERTa) aktif mi?"),
    layer3: bool = Query(None, description="Layer 3 (LLM Judge) aktif mi?")
):
    """
    Güvenlik katmanlarını açıp kapatma.
    
    Query Parameters (opsiyonel, null ise değişmez):
    - layer1: Layer 1 (DLP/Regex) açık mı? (true/false)
    - layer2: Layer 2 (DeBERTa AI) açık mı? (true/false)
    - layer3: Layer 3 (LLM Judge) açık mı? (true/false)
    
    Örnek:
    - PUT /api/v1/config/layers?layer1=true&layer2=true&layer3=false
    
    ⚠️ Tüm layer'ları kapatmak güvenlik açığı yaratır!
    """
    if layer1 is None and layer2 is None and layer3 is None:
        raise HTTPException(
            status_code=400,
            detail="En az bir layer parametresi gerekli"
        )

    config = ConfigManager.load_config()

    # Eski değerleri kaydet (log için)
    old_state = {
        "layer_regex": config.layer_regex,
        "layer_deberta": config.layer_deberta,
        "layer_llm": config.layer_llm
    }

    # Yeni değerleri ata
    if layer1 is not None:
        config.layer_regex = layer1
    if layer2 is not None:
        config.layer_deberta = layer2
    if layer3 is not None:
        config.layer_llm = layer3

    success = ConfigManager.save_config(config)
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Config kaydedilemedi"
        )

    logger.warning(
        f"🔄 Layer'lar güncellendi | "
        f"L1: {old_state['layer_regex']}→{config.layer_regex}, "
        f"L2: {old_state['layer_deberta']}→{config.layer_deberta}, "
        f"L3: {old_state['layer_llm']}→{config.layer_llm}"
    )

    return {
        "message": "Layer konfigürasyonu başarıyla güncellendi",
        "previous_state": old_state,
        "new_state": {
            "layer_regex": config.layer_regex,
            "layer_deberta": config.layer_deberta,
            "layer_llm": config.layer_llm
        }
    }


@router.post("/feedback", tags=["Feedback"])
async def submit_feedback(
    log_id: str = Query(...),
    feedback_type: str = Query(..., description="'false_positive' veya 'false_negative'")
):
    """
    Yanlış pozitif / yanlış negatif bildirimi.
    
    Query Parameters:
    - log_id: Geri bildirim verilen log kaydının ID'si
    - feedback_type: 'false_positive' (yanlış engelleme) veya 'false_negative' (yanlış izin)
    
    Örnek:
    - POST /api/v1/feedback?log_id=abc-123&feedback_type=false_positive
    
    💾 Geri bildirimler kalıcı olarak kaydedilir ve analiz için kullanılabilir.
    """
    if feedback_type not in ["false_positive", "false_negative"]:
        raise HTTPException(
            status_code=400,
            detail="feedback_type 'false_positive' veya 'false_negative' olmalı"
        )

    # Geri bildirimi veritabanına kaydet
    try:
        await DatabaseManager.log_feedback(
            log_id=log_id,
            feedback_type=feedback_type
        )
        logger.info(f"📢 Feedback kaydedildi | log_id={log_id}, type={feedback_type}")
        return {
            "message": "Geri bildiriminiz başarıyla kaydedildi. Teşekkürler!",
            "log_id": log_id,
            "feedback_type": feedback_type
        }
    except Exception as e:
        logger.error(f"❌ Feedback kaydetme hatası: {e}")
        raise HTTPException(
            status_code=500,
            detail="Geri bildirim kaydedilemedi"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 📊 LOG VE İSTATİSTİK ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/logs", tags=["Logs"])
async def get_logs(
    limit: int = Query(50, ge=1, le=500),
    action: str = Query(None, description="'BLOCK' veya 'ALLOW'"),
    category: str = Query(None, description="'Safe', 'Injection', 'PII', 'Blacklist', 'Policy Violation'")
):
    """
    Filtrelenmiş log kayıtlarını döndür.
    
    Query Parameters:
    - limit: Kaç kayıt döndürülecek (1-500, default: 50)
    - action: 'BLOCK' (engellenenler) veya 'ALLOW' (izin verilenler)
    - category: Güvenlik kategorisi filtrelemesi
    
    Örnek:
    - GET /api/v1/logs?limit=100&action=BLOCK&category=Injection
    """
    logs = await DatabaseManager.get_logs(
        limit=limit,
        action_filter=action,
        category_filter=category
    )
    logger.info(f"📖 Log listesi getirildi | action={action}, category={category}, count={len(logs)}")
    return {"logs": logs, "count": len(logs)}


@router.get("/stats", tags=["Statistics"])
async def get_stats():
    """
    Dashboard için özet istatistikler.
    
    Returns:
    - total_requests: Toplam istek sayısı
    - blocked: Engellenen istek sayısı
    - allowed: İzin verilen istek sayısı
    - avg_latency_ms: Ortalama yanıt süresi (ms)
    """
    stats = await DatabaseManager.get_stats()
    logger.info(f"📊 İstatistikler getirildi | {stats}")
    return stats


@router.get("/health", tags=["Health"])
async def health_check():
    """
    Sistem sağlık kontrolü.
    
    Returns:
    - status: 'ok' veya 'error'
    - model_loaded: DeBERTa modeli yüklü mü?
    - db_connected: Veritabanı bağlı mı?
    """
    try:
        # DeBERTa modeli yüklü mü
        model_ready = Layer2DeBERTa._classifier is not None
        
        # DB kontrol et
        db_ok = await DatabaseManager.get_stats() is not None
        
        return {
            "status": "ok" if db_ok else "degraded",
            "model_loaded": model_ready,
            "db_connected": db_ok,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"❌ Health check hatası: {e}")
        return {
            "status": "error",
            "detail": str(e)
        }