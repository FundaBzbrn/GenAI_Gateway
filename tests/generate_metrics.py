import sys, os, time, json, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from app.services.layer1_regex import Layer1Regex
from app.services.layer2_deberta import Layer2DeBERTa
from app.services.layer3_llm_judge import Layer3LLMJudge
import pandas as pd

# Matplotlib ve Seaborn görselleştirme için (eğer kuruluysa çalışır, değilse metin bazlı çıktı verir)
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
    HAS_PLOT_LIBS = True
except ImportError:
    HAS_PLOT_LIBS = False
    print("Uyarı: 'matplotlib', 'seaborn' veya 'scikit-learn' kurulu değil. Grafik çizilmeyecek, sadece metin tablosu üretilecek.")
    print("Grafik çizdirmek için: pip install matplotlib seaborn scikit-learn")

THRESHOLD_HIGH = 0.75
THRESHOLD_LOW  = 0.35


def calculate_metrics(y_true, y_pred):
    """
    Manuel metrik hesaplaması (scikit-learn'e bağımlı olmamak için)
    y_true: 1 (Saldırı/BLOCK), 0 (Masum/ALLOW)
    y_pred: 1 (BLOCK kararı), 0 (ALLOW kararı)
    """
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    
    total = len(y_true)
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    return {
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1-Score": f1,
        "FPR": fpr,
        "TP": tp, "TN": tn, "FP": fp, "FN": fn
    }

def print_confusion_matrix_text(metrics, title):
    print(f"\n--- {title} Confusion Matrix ---")
    print("                 Tahmin: GÜVENLİ (0) | Tahmin: ZARARLI (1)")
    print(f"Gerçek: GÜVENLİ (0) | TN: {metrics['TN']:<13} | FP: {metrics['FP']:<13} (Hatalı Alarm)")
    print(f"Gerçek: ZARARLI (1) | FN: {metrics['FN']:<13} (Sızıntı)| TP: {metrics['TP']:<13} (Başarı)")
    print("-" * 65)

def plot_confusion_matrix(y_true, y_pred, title, filename):
    if not HAS_PLOT_LIBS:
        return
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['GÜVENLİ (0)', 'ZARARLI (1)'], 
                yticklabels=['GÜVENLİ (0)', 'ZARARLI (1)'])
    plt.title(f"{title}\nConfusion Matrix")
    plt.ylabel('Gerçek Sınıf')
    plt.xlabel('Tahmin Edilen Sınıf')
    plt.tight_layout()
    plt.savefig(f"tests/{filename}")
    plt.close()
    print(f"Grafik kaydedildi: tests/{filename}")

def plot_bar_chart(m_l1, m_l2, m_l3, m_cas, filename):
    if not HAS_PLOT_LIBS:
        return
    labels = ['Katman 1 (Regex)', 'Katman 2 (DeBERTa)', 'Katman 3 (LLM)', 'Genel Sistem']
    accuracies = [m_l1['Accuracy']*100, m_l2['Accuracy']*100, m_l3['Accuracy']*100, m_cas['Accuracy']*100]
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(labels, accuracies, color=['#FF9999', '#66B2FF', '#99FF99', '#FFCC99'])
    plt.ylim(0, 100)
    plt.title('Katmanlara Göre Doğruluk (Accuracy) Oranları')
    plt.ylabel('Accuracy (%)')
    
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 1, f"%{yval:.1f}", ha='center', va='bottom', fontweight='bold')
        
    plt.tight_layout()
    plt.savefig(f"tests/{filename}")
    plt.close()
    print(f"Bar grafiği kaydedildi: tests/{filename}")

async def main():
    print("=" * 80)
    print("  GenAI Security Gateway - Katmanlı Metrik & Doğruluk (Accuracy) Analizi")
    print("=" * 80)

    print("\nModeller yükleniyor...")
    Layer2DeBERTa.load_model()

    # Verileri hazırla (Yeni 1000'lik dev veri setinden)
    try:
        df = pd.read_csv("data/custom_dataset_full.csv")
        
        from sklearn.model_selection import train_test_split
        # train_deberta.py icindeki 80/20 test ayrımının aynısı
        _, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df["label_id"])
        
        # Hocaya sunum için, Google API kotasını doldurmayacak 30 adet (15 saldırı, 15 masum) seçiyoruz.
        # Bu veriler hala modelin hiç görmediği (%20) kısımdan seçilmektedir (Hile yoktur).
        attacks_df = test_df[test_df['label_id'] == 1].sample(n=15, random_state=42)
        benign_df = test_df[test_df['label_id'].isin([0, 2])].sample(n=15, random_state=42)
        
        attacks = attacks_df['text'].tolist()
        benign = benign_df['text'].tolist()
    except Exception as e:
        print(f"Hata: {e}")
        return
    
    # 1: Zararlı (BLOCK bekleniyor), 0: Masum/Nötr (ALLOW bekleniyor)
    y_true_all = [1] * len(attacks) + [0] * len(benign)
    all_texts = attacks + benign

    results_layer1 = []
    results_layer2 = []
    results_layer3 = []
    results_cascade = []

    print(f"\nToplam test edilecek veri: {len(all_texts)} ({len(attacks)} Saldırı, {len(benign)} Masum)")
    print("Testler çalıştırılıyor, lütfen bekleyin...\n")

    for idx, text in enumerate(all_texts):
        # Gerçek Sınıf
        is_attack = (idx < len(attacks))
        
        # --- Katman 1 (Sadece Regex) Testi ---
        r1 = Layer1Regex.scan(text)
        pred_l1 = 1 if r1.is_blocked else 0
        results_layer1.append(pred_l1)
        
        # --- Katman 2 (Sadece DeBERTa) Testi ---
        score = Layer2DeBERTa.predict_score(r1.processed_text)
        pred_l2 = 1 if score > THRESHOLD_HIGH else 0
        results_layer2.append(pred_l2)
        
        # --- Katman 3 (Sadece LLM Judge) Testi ---
        # Sadece saldırılar ve masumlar için LLM test ediliyor (Maliyetli olduğu için)
        # Normalde LLM sadece gri alanda çalışır, ama burada kapasitesini ölçüyoruz.
        pred_l3 = 0
        try:
            await asyncio.sleep(4.0) # Google API Rate Limit'i önlemek için bekleme (Güvenli: 4 saniye)
            verdict = await Layer3LLMJudge.evaluate(r1.processed_text)
            pred_l3 = 1 if verdict == "UNSAFE" else 0
        except Exception as e:
            pred_l3 = 0 # Hata durumunda fail-open
        results_layer3.append(pred_l3)

        # --- Cascade (Mevcut Sistem) Testi ---
        pred_cascade = 0
        if r1.is_blocked:
            pred_cascade = 1
        elif score > THRESHOLD_HIGH:
            pred_cascade = 1
            if is_attack:
                await Layer1Regex.learn_from_attack(text) # Canlı Öğrenme (Artık Async ve Akıllı)
        elif THRESHOLD_LOW < score <= THRESHOLD_HIGH:
            if pred_l3 == 1:
                pred_cascade = 1
                if is_attack:
                    await Layer1Regex.learn_from_attack(text) # Canlı Öğrenme (Artık Async ve Akıllı)
        
        results_cascade.append(pred_cascade)
        
        sys.stdout.write(f"\rİşlenen: {idx+1}/{len(all_texts)}")
        sys.stdout.flush()

    print("\n\nTest tamamlandı. Metrikler hesaplanıyor...")

    m_l1 = calculate_metrics(y_true_all, results_layer1)
    m_l2 = calculate_metrics(y_true_all, results_layer2)
    m_l3 = calculate_metrics(y_true_all, results_layer3)
    m_cas = calculate_metrics(y_true_all, results_cascade)

    print("\n" + "=" * 80)
    print(f"{'Katman / Model':<25} | {'Accuracy':<10} | {'Precision':<10} | {'Recall (TPR)':<13} | {'F1-Score':<10} | {'FPR':<10}")
    print("-" * 80)
    print(f"{'Katman 1 (Regex)':<25} | %{m_l1['Accuracy']*100:<9.1f} | %{m_l1['Precision']*100:<9.1f} | %{m_l1['Recall']*100:<12.1f} | %{m_l1['F1-Score']*100:<9.1f} | %{m_l1['FPR']*100:<9.1f}")
    print(f"{'Katman 2 (DeBERTa)':<25} | %{m_l2['Accuracy']*100:<9.1f} | %{m_l2['Precision']*100:<9.1f} | %{m_l2['Recall']*100:<12.1f} | %{m_l2['F1-Score']*100:<9.1f} | %{m_l2['FPR']*100:<9.1f}")
    print(f"{'Katman 3 (LLM Judge)':<25} | %{m_l3['Accuracy']*100:<9.1f} | %{m_l3['Precision']*100:<9.1f} | %{m_l3['Recall']*100:<12.1f} | %{m_l3['F1-Score']*100:<9.1f} | %{m_l3['FPR']*100:<9.1f}")
    print("-" * 80)
    print(f"{'Genel Sistem (Cascade)':<25} | %{m_cas['Accuracy']*100:<9.1f} | %{m_cas['Precision']*100:<9.1f} | %{m_cas['Recall']*100:<12.1f} | %{m_cas['F1-Score']*100:<9.1f} | %{m_cas['FPR']*100:<9.1f}")
    print("=" * 80)

    # Text tabanlı confusion matrix yazdır
    print_confusion_matrix_text(m_cas, "GENEL SİSTEM (CASCADE)")

    # Görselleri oluştur (Sunum için ayrı isimlerle kaydediyoruz)
    plot_confusion_matrix(y_true_all, results_layer1, "Katman 1 (Regex)", "cm_layer1_presentation.png")
    plot_confusion_matrix(y_true_all, results_layer2, "Katman 2 (DeBERTa)", "cm_layer2_presentation.png")
    plot_confusion_matrix(y_true_all, results_layer3, "Katman 3 (LLM Judge)", "cm_layer3_presentation.png")
    plot_confusion_matrix(y_true_all, results_cascade, "Genel Sistem (Cascade Mimarisi)", "cm_cascade_presentation.png")
    
    # Sütun grafiği çizdir
    plot_bar_chart(m_l1, m_l2, m_l3, m_cas, "accuracy_comparison_presentation.png")

    report = {
        "Layer1_Regex": m_l1,
        "Layer2_DeBERTa": m_l2,
        "Layer3_LLMJudge": m_l3,
        "System_Cascade": m_cas
    }
    with open("tests/metrics_report_presentation.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print("\nDetaylı JSON raporu kaydedildi: tests/metrics_report_presentation.json")

if __name__ == "__main__":
    asyncio.run(main())
    asyncio.run(main())
