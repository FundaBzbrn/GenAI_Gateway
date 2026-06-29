import os
import pandas as pd
import re
from collections import Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Yollar
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "custom_dataset_full.csv")
BLACKLIST_PATH = os.path.join(BASE_DIR, "app", "services", "core_blacklist.py")

# Yaygın ve zararsız kelimeler (Stopwords)
STOPWORDS = set([
    "bir", "ve", "için", "nasıl", "bana", "ne", "ile", "nedir", "nelerdir", 
    "yaz", "yapılır", "bütün", "unut", "kendi", "olarak", "da", "de", "mi", 
    "mu", "mı", "mü", "bu", "şu", "o", "gibi", "ben", "sen", "biz", "siz", 
    "onlar", "adım", "anlat", "örnek", "ver", "write", "how", "to", "a", "an",
    "the", "can", "you", "is", "are", "what", "of", "in", "on", "it", "my",
    "me", "for", "and", "that", "this"
])

def main():
    logger.info("🕵️‍♂️ Katman 1 (Regex) için Dinamik Blacklist Çıkarımı Başlıyor...")

    if not os.path.exists(DATA_PATH):
        logger.error(f"❌ Veri seti bulunamadı: {DATA_PATH}")
        return

    df = pd.read_csv(DATA_PATH)
    
    # Sadece Negatif (UNSAFE - 1) olan verileri al
    negatives = df[df['label_id'] == 1]['text'].tolist()
    
    all_words = []
    for text in negatives:
        # Noktalama işaretlerini temizle ve küçük harfe çevir
        clean_text = re.sub(r'[^\w\s]', '', str(text).lower())
        words = clean_text.split()
        
        for word in words:
            # 3 harften kısa kelimeleri ve stopwords'leri atla
            if len(word) > 2 and word not in STOPWORDS:
                all_words.append(word)

    # En çok geçen 50 kelimeyi bul
    word_counts = Counter(all_words)
    top_words = [word for word, count in word_counts.most_common(50)]

    logger.info(f"🚨 En tehlikeli {len(top_words)} kelime tespit edildi!")
    
    # Mevcut core_blacklist.py dosyasının var olup olmadığını kontrol et
    # Varsa üzerine yazacağız
    
    python_code = f'# Bu dosya otomatik olarak oluşturulmuştur (Dinamik Blacklist)\n'
    python_code += f'# Veri setindeki (custom_dataset_300.csv) negatif örneklerden en çok geçen tehlikeli kelimeler çıkarılmıştır.\n\n'
    python_code += f'CORE_BLACKLIST = [\n'
    for word in top_words:
        python_code += f'    "{word}",\n'
    python_code += f']\n'

    os.makedirs(os.path.dirname(BLACKLIST_PATH), exist_ok=True)
    with open(BLACKLIST_PATH, 'w', encoding='utf-8') as f:
        f.write(python_code)
        
    logger.info(f"✅ Blacklist güncellendi ve kaydedildi: {BLACKLIST_PATH}")
    logger.info("Katman 1 (Regex) artık bu yeni kelimeleri anında yakalayacak!")

if __name__ == "__main__":
    main()
