# GenAI Security Gateway - Geliştirme Süreci ve Notlar Özeti

Bu belge, projenin geliştirme süreci boyunca oluşturulan tüm durum raporları, planlama notları, tamamlama listeleri ve hata kontrol yönergelerinin tek bir çatı altında sentezlenmiş halidir. Eski ve dağınık raporların yerine sunumlarda veya gelecekteki incelemelerde tek bir referans noktası olması için oluşturulmuştur.

## 🎯 Projenin Genel Özeti
**GenAI Security Gateway**, yapay zeka sistemlerine (LLM'lere) gönderilen istemleri (prompt'ları) zararlı içeriklere, prompt injection saldırılarına ve veri sızıntılarına (DLP) karşı koruyan **3 katmanlı (Layer)** gelişmiş bir güvenlik duvarıdır. 

Sistem iki ana bacaktan oluşur:
1. **Backend (FastAPI & Python)**: Güvenlik analizi yapan asıl motor.
2. **Frontend (HTML/JS/CSS)**: Logların, grafiklerin ve admin ayarlarının yönetildiği kontrol paneli.

---

## 🛡️ Güvenlik Katmanları (Mimarimiz)

Projemizin kalbi olan 3 aşamalı tarama sistemi başarıyla inşa edilmiştir:

1. **Layer 1 (DLP & Regex Kontrolü):**
   - Kara liste (blacklist) kelimelerin ve PII (Kişisel Tanımlanabilir Bilgiler - TC Kimlik No, Kredi Kartı vb.) verilerinin tespit edildiği ilk katmandır.
   - Son derece hızlıdır (genellikle 5ms altında yanıt verir) ve statik kurallara dayanır.

2. **Layer 2 (DeBERTa AI Modeli):**
   - Regex'in yakalayamayacağı karmaşık "Prompt Injection" saldırılarını anlamak için doğal dil işleme (NLP) yeteneği olan Transformer tabanlı bir yapay zeka (DeBERTa) kullanır.
   - Belirli bir skor eşiği (Threshold, örn: 0.70) üzerinden gelen metinlerin zararlı olup olmadığına karar verir.
   - Performansı artırmak için bellek içi önbellekleme (In-memory caching) yapısı kurulmuştur.

3. **Layer 3 (LLM Judge - Üst Düzey Karar Verici):**
   - Eğer Layer 2'den gelen sonuç bir "Gri Bölge" içerisindeyse (yani skor 0.35 ile 0.75 arasındaysa ve emin olunamadıysa), sistem bu prompt'u çok daha zeki olan GPT-4o-mini gibi devasa bir LLM'e (Judge) gönderir.
   - Bu LLM, cümlenin niyetini derinlemesine analiz eder ve nihai kararı (Fail-closed prensibiyle) verir.

---

## 💾 Veritabanı ve Performans Geliştirmeleri

- **Çift Veritabanı Desteği (Dual DB):** Geliştirme aşamasında hafif olması için `SQLite`, gerçek üretim ortamında yüksek yükü kaldırması için `PostgreSQL` (Asenkron connection pooling ile) destekleyecek şekilde altyapı kuruldu.
- **Güvenlik Logları:** Tüm engellenen veya izin verilen promptlar `security_logs` tablosuna (log_id, user_id, action, category, latency_ms gibi kritik detaylarla) kaydedilmekte, arayüzden saniye saniye takip edilebilmektedir.
- **Test ve Sentetik Veri Süreci:** Sistemin performansını ve AI modellerinin başarısını ölçmek için `generate_synthetic_massive_dataset.py` kullanılarak on binlerce satırlık "Safe" ve "Injection" verisi üretildi ve sisteme test olarak gönderildi.

---

## 🖥️ Admin Paneli (Frontend) Özellikleri

Geliştirme sürecinde Backend tarafı kusursuzlaştırıldıktan sonra Frontend arayüzü inşa edilmiştir. Panel aşağıdaki işlevleri barındırır:
- **Dashboard:** Anlık bloklanan/geçen trafik istatistikleri ve performans (gecikme süresi) metrikleri.
- **Log Yönetimi:** Logları detaylı inceleme, kategoriye göre filtreleme (PII, Injection vb.) ve her bir log detayını popup olarak görüntüleme.
- **Sistem Ayarları (Settings):** 
  - Layer'ları (1, 2, 3) anlık olarak açıp kapatabilme.
  - Yapay zeka duyarlılığını (Threshold slider) canlı olarak değiştirebilme.
  - Blacklist kelimelerine arayüz üzerinden dinamik olarak yeni kelimeler ekleme ve çıkarma.

---

## 🛠️ Sunum ve Profesyonel İş Akışı İçin Notlar

Bu belgenin oluşturulması sırasında, projenin kök dizininde yer alan tüm kalabalık geçici scriptler şu klasörlere taşınmıştır (Hocalara sunum yaparken bu klasörlerdeki scriptlerin nasıl çalıştığı anlatılarak profesyonellik gösterilebilir):

1. **`database_scripts/`**: Veritabanının sıfırdan oluşturulması, güncellenmesi ve admin yetkililerinin ayarlanması için yazılmış otomasyon betikleri. *(Hocaya: "Tabloları elle girmedik, bu betiklerle otomatize ettik")*
2. **`test_scripts/`**: API endpoint'lerini, modelleri ve yoğun yük trafiğini test etmek için yazılmış betikler. *(Hocaya: "Sistemin yük altında çökmemesi için bu kodlarla trafik simülasyonları yaptık")*
3. **`tools_and_fixes/`**: Log analizini kolaylaştırmak veya hatalı kayıtları tespit etmek için yazılan mini araçlar.
4. **`data_generation_scripts/`**: Modelin tespiti için gerekli olan sentetik veri üretme ve devasa veri setlerini internetten otomatik çekme betikleri.

Proje, hem güvenlik hem de mimari açıdan %100 oranında tamamlanmış olup, sunuma hazırdır.
