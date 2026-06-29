import pandas as pd
from datasets import load_dataset
import os

# 1. Klasör Kontrolü
if not os.path.exists("data"):
    os.makedirs("data")

print("⏳ JailbreakBench veri seti indiriliyor...")

try:
    # DÜZELTME BURADA YAPILDI: split="harmful" seçildi
    # Bu sayede saldırı senaryolarını (Jailbreak) indireceğiz.
    dataset = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
    
    # Pandas formatına çevir
    df = pd.DataFrame(dataset)
    
    # 2. İçeriği Görelim (Terminalde ilk 5 satır)
    print("\n✅ Veri Başarıyla İndirildi! İşte ilk 5 SALDIRI örneği:")
    print(df[['Goal', 'Category']].head())
    
    # 3. Dosyayı Kaydet
    kayit_yolu = "data/jailbreak_bench.csv"
    df.to_csv(kayit_yolu, index=False)
    print(f"\n💾 Dosya şuraya kaydedildi: {kayit_yolu}")

except Exception as e:
    print(f"❌ Hata oluştu: {e}")