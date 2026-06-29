import os
import pandas as pd
# pyrefly: ignore [missing-import]
from datasets import load_dataset
import random

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

print("⏳ Hugging Face'ten veri seti indiriliyor (aibastion-prompt-injection-jailbreak-detector)...")
try:
    dataset = load_dataset("neeraj-kumar-47/aibastion-prompt-injection-jailbreak-detector")
    df = dataset['train'].to_pandas()
    print(f"✅ Veri seti başarıyla indirildi! Toplam satır/sütun: {df.shape}")
    print(f"Sütunlar: {df.columns.tolist()}")
    
    # Save the full dataset
    csv_path = os.path.join(DATA_DIR, "aibastion_dataset.csv")
    df.to_csv(csv_path, index=False)
    print(f"💾 Veri seti CSV olarak kaydedildi: {csv_path}")

    # Otomatik sütun eşleştirme
    prompt_col = None
    label_col = None
    
    for col in df.columns:
        if 'prompt' in col.lower() or 'text' in col.lower():
            prompt_col = col
        if 'label' in col.lower() or 'is_safe' in col.lower() or 'class' in col.lower():
            label_col = col
            
    if prompt_col and label_col:
        print(f"🔍 Algılanan Sütunlar -> Prompt: '{prompt_col}', Label: '{label_col}'")
        
        # Etiketleri analiz et (genelde 0 safe, 1 unsafe veya text tabanlı)
        unique_labels = df[label_col].unique()
        print(f"Bulunan Etiketler: {unique_labels}")
        
        # Varsayılan dağılım: 1 veya 'injection' zararlı, 0 veya 'safe' güvenli
        safe_prompts = []
        unsafe_prompts = []
        
        for index, row in df.iterrows():
            lbl = str(row[label_col]).lower()
            text = str(row[prompt_col])
            
            if '1' in lbl or 'injection' in lbl or 'jailbreak' in lbl or 'unsafe' in lbl or 'true' in lbl:
                unsafe_prompts.append(text)
            else:
                safe_prompts.append(text)
                
        # Eğer etiketleme bu düz mantığa uymuyorsa, yarısını safe yarısını unsafe sayalım test için
        if len(safe_prompts) == 0 or len(unsafe_prompts) == 0:
            safe_prompts = df[prompt_col].iloc[:int(len(df)/2)].tolist()
            unsafe_prompts = df[prompt_col].iloc[int(len(df)/2):].tolist()
            
    else:
        print("⚠️ Sütunlar otomatik algılanamadı, rastgele ikiye bölünüyor...")
        prompt_col = df.columns[0]
        safe_prompts = df[prompt_col].iloc[:int(len(df)/2)].tolist()
        unsafe_prompts = df[prompt_col].iloc[int(len(df)/2):].tolist()
        
    print(f"✅ {len(safe_prompts)} adet Güvenli (Safe), {len(unsafe_prompts)} adet Zararlı (Injection) prompt ayrıştırıldı.")
    
    # Yeni test dosyası oluşturma
    print("⚙️ test_traffic_v2.py oluşturuluyor...")
    sample_safe = random.sample(safe_prompts, min(50, len(safe_prompts)))
    sample_unsafe = random.sample(unsafe_prompts, min(50, len(unsafe_prompts)))
    
    with open("test_traffic_v2.py", "w", encoding="utf-8") as f:
        f.write("import asyncio\nimport httpx\nimport random\nimport time\n\n")
        f.write('API_URL = "http://127.0.0.1:8001/api/v1/analyze"\n\n')
        f.write(f"SAFE_PROMPTS = {sample_safe}\n\n")
        f.write(f"INJECTION_PROMPTS = {sample_unsafe}\n\n")
        
        script_logic = """
BLACKLIST_PROMPTS = [
    "aptalca", "salak", "lanet", "ahmak", "kredi kartı", "sifreleri ver"
]

async def send_request(client, prompt, category):
    payload = {
        "text": str(prompt)[:500],  # İlk 500 karakteri al (çok uzun promptlar API'yi yormasın)
        "user_id": f"test_user_{random.randint(100, 999)}"
    }
    try:
        start_time = time.time()
        response = await client.post(API_URL, json=payload, timeout=60.0)
        latency = int((time.time() - start_time) * 1000)
        
        if response.status_code == 200:
            data = response.json()
            status = data.get("status")
            reason = data.get("reason", "")
            print(f"[{category}] {status} - Süre: {latency}ms | Sebep: {reason}")
        else:
            print(f"[{category}] HTTP Error: {response.status_code}")
    except Exception as e:
        print(f"[{category}] Request failed: {type(e).__name__} - {e}")

async def main():
    print("🚀 GenAI Security Gateway - Gerçek Veri Seti ile Yük Testi (Load Test) Başlıyor...")
    
    async with httpx.AsyncClient() as client:
        tasks = []
        for i in range(50):
            rand_val = random.random()
            if rand_val < 0.40:    # %40 Safe
                prompt = random.choice(SAFE_PROMPTS)
                category = "SAFE"
            elif rand_val < 0.60:  # %20 Blacklist
                prompt = random.choice(BLACKLIST_PROMPTS)
                category = "BLACKLIST"
            else:                  # %40 Injection
                prompt = random.choice(INJECTION_PROMPTS)
                category = "INJECTION"
            
            tasks.append(asyncio.create_task(send_request(client, prompt, category)))
            await asyncio.sleep(0.05) 
            
        await asyncio.gather(*tasks)
        
    print("\\n✅ Yük testi başarıyla tamamlandı!")

if __name__ == "__main__":
    asyncio.run(main())
"""
        f.write(script_logic)
        
    print("🎉 test_traffic_v2.py kullanıma hazır! Bu script yeni veri setinden rastgele seçilmiş gerçek saldırı vektörlerini test eder.")
        
except Exception as e:
    print(f"❌ Hata: {e}")
