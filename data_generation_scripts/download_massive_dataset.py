import asyncio
import httpx
import csv
import os

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)
FILE_PATH = os.path.join(DATA_DIR, "massive_security_dataset.csv")

DATASET_NAME = "markush1/LLM-Jailbreak-Classifier-Dataset"
TOTAL_ROWS = 55000  # API'den olabildiğince çok veri çekeceğiz
BATCH_SIZE = 100

async def fetch_batch(client, offset):
    url = f"https://datasets-server.huggingface.co/rows?dataset={DATASET_NAME}&config=default&split=train&offset={offset}&length={BATCH_SIZE}"
    try:
        response = await client.get(url, timeout=30.0)
        if response.status_code == 200:
            return response.json().get('rows', [])
    except Exception as e:
        print(f"Hata (Offset {offset}): {e}")
    return []

async def main():
    print(f"⏳ Hugging Face API'den {TOTAL_ROWS} satıra kadar veri asenkron olarak çekiliyor...")
    print(f"Hedef Veri Seti: {DATASET_NAME}")
    
    safe_count = 0
    unsafe_count = 0
    all_data = []

    async with httpx.AsyncClient() as client:
        tasks = []
        # Tüm offset isteklerini hazırla
        for offset in range(0, TOTAL_ROWS, BATCH_SIZE):
            tasks.append(fetch_batch(client, offset))
        
        # API'yi boğmamak (Rate Limit yememek) için 20'şerli bloklar halinde indirelim
        chunk_size = 20
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            results = await asyncio.gather(*chunk)
            
            for batch_rows in results:
                for item in batch_rows:
                    row_data = item['row']
                    text = row_data.get('text', row_data.get('prompt', ''))
                    label = row_data.get('label', row_data.get('class', 0))
                    
                    # Güvenli mi Saldırı mı ayrımını yap
                    is_injection = 1 if (str(label) == '1' or 'injection' in str(label).lower()) else 0
                    
                    if is_injection:
                        unsafe_count += 1
                    else:
                        safe_count += 1
                        
                    # Metni CSV için temizle
                    text = str(text).replace('\n', ' ').replace('\r', '').strip()
                    all_data.append([text, is_injection])
                    
            indirilen = min((i + chunk_size) * BATCH_SIZE, TOTAL_ROWS)
            print(f"İndirilen ve İşlenen: {indirilen} / {TOTAL_ROWS}...")

    print(f"\n💾 Tüm veriler başarıyla çekildi. CSV formatına dönüştürülüyor: {FILE_PATH}")
    with open(FILE_PATH, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["prompt", "is_injection"])
        writer.writerows(all_data)

    print(f"\n✅ BAŞARIYLA TAMAMLANDI!")
    print(f"Toplam Çekilen Satır: {safe_count + unsafe_count}")
    print(f"Güvenli (Safe): {safe_count}")
    print(f"Zararlı (Injection): {unsafe_count}")
    print(f"Kayıt Yeri: {FILE_PATH}")

if __name__ == "__main__":
    asyncio.run(main())
