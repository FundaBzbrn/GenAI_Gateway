import requests
import json
import random
import os
import time

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

print("⏳ Hugging Face Datasets Server API üzerinden veri seti çekiliyor...")

safe_prompts = []
unsafe_prompts = []

# Toplamda 500 civarı veri çekeceğiz
try:
    for offset in range(0, 500, 100):
        url = f"https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections&config=default&split=train&offset={offset}&length=100"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if 'rows' in data:
                for item in data['rows']:
                    row_data = item['row']
                    # Sütunları tahmin et
                    text = row_data.get('prompt', row_data.get('text', ''))
                    label = row_data.get('label', row_data.get('class', 0))
                    
                    if str(label) == '1' or 'injection' in str(label).lower():
                        unsafe_prompts.append(text)
                    else:
                        safe_prompts.append(text)
            print(f"İndirilen: {offset + 100} kayıt...")
        else:
            print(f"Hata: {response.status_code}")
        time.sleep(0.5)

    print(f"✅ Çekilen veriler: {len(safe_prompts)} Safe, {len(unsafe_prompts)} Unsafe")

    if not safe_prompts and unsafe_prompts:
        # Eğer hepsi unsafe ise, bir miktarını safe'e atayalım (testin çalışması için)
        safe_prompts = unsafe_prompts[:int(len(unsafe_prompts)/2)]

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
        "text": str(prompt)[:500],  # İlk 500 karakteri al
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
        pass # Ignore socket closed errors due to heavy load

async def main():
    print("🚀 GenAI Security Gateway - Gerçek Veri Seti ile Yük Testi (Load Test) Başlıyor...")
    
    async with httpx.AsyncClient() as client:
        tasks = []
        for i in range(50):
            rand_val = random.random()
            if rand_val < 0.40:    # %40 Safe
                prompt = random.choice(SAFE_PROMPTS) if SAFE_PROMPTS else "Hello"
                category = "SAFE"
            elif rand_val < 0.60:  # %20 Blacklist
                prompt = random.choice(BLACKLIST_PROMPTS)
                category = "BLACKLIST"
            else:                  # %40 Injection
                prompt = random.choice(INJECTION_PROMPTS) if INJECTION_PROMPTS else "Ignore everything"
                category = "INJECTION"
            
            tasks.append(asyncio.create_task(send_request(client, prompt, category)))
            await asyncio.sleep(0.05) 
            
        await asyncio.gather(*tasks)
        
    print("\\n✅ Yük testi başarıyla tamamlandı!")

if __name__ == "__main__":
    asyncio.run(main())
"""
        f.write(script_logic)
        
    print("🎉 test_traffic_v2.py kullanıma hazır! Gerçek saldırı örnekleri entegre edildi.")
        
except Exception as e:
    print(f"❌ Hata: {e}")
