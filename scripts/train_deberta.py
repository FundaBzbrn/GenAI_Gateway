import os

# TensorFlow / TensorBoard kaynaklı Protobuf çökmesini engellemek için
# Bu satırlar HER ZAMAN tüm import'lardan ÖNCE gelmeli!
os.environ["USE_TF"] = "0"
os.environ["USE_TORCH"] = "1"
os.environ["DISABLE_MLFLOW_INTEGRATION"] = "TRUE"

import pandas as pd
import logging
import torch
from sklearn.model_selection import train_test_split

try:
    from datasets import Dataset
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
    import evaluate
    import numpy as np
    import matplotlib.pyplot as plt
except ImportError:
    print("Gerekli kutuphaneler eksik! Lutfen calistirin:")
    print("pip install transformers datasets evaluate accelerate scikit-learn matplotlib")
    exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Yollar
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "custom_dataset_full.csv")
MODEL_OUTPUT_DIR = os.path.join(BASE_DIR, "models", "fine_tuned_deberta")
BASE_MODEL_NAME = "protectai/deberta-v3-base-prompt-injection-v2"

def compute_metrics(eval_pred):
    metric = evaluate.load("accuracy")
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    return metric.compute(predictions=predictions, references=labels)

def main():
    logger.info("🚀 DeBERTa Fine-Tuning Süreci Başlıyor...")

    if not os.path.exists(DATA_PATH):
        logger.error(f"❌ Veri seti bulunamadı: {DATA_PATH}")
        return

    # 1. Veri Setini Yükle ve Hazırla
    logger.info("Veri seti yükleniyor...")
    df = pd.read_csv(DATA_PATH)
    
    # Katman 2 (DeBERTa) sadece SAFE(0) ve UNSAFE(1) anlar.
    # Nötr(2) olan verileri DeBERTa'nın kafasını karıştırmaması için SAFE(0) olarak eğitebiliriz 
    # veya onları doğrudan LLM'e bırakabiliriz. Bu modelde Nötr(2) olanları SAFE(0) kabul ediyoruz ki
    # DeBERTa engellemesin, LLM'e (Katman 3'e) geçsin.
    df['label_id'] = df['label_id'].apply(lambda x: 0 if x == 2 else x)

    # Eğitim ve test setlerine ayırma (%80 Eğitim, %20 Test)
    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['label_id'])
    
    train_dataset = Dataset.from_pandas(train_df)
    test_dataset = Dataset.from_pandas(test_df)

    # 2. Tokenizer Yükle
    logger.info(f"Tokenizer yükleniyor: {BASE_MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)

    def tokenize_function(examples):
        return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=512)

    logger.info("Veriler tokenize ediliyor...")
    tokenized_train = train_dataset.map(tokenize_function, batched=True)
    tokenized_test = test_dataset.map(tokenize_function, batched=True)
    
    # Modelin beklediği etiket ismi 'labels' olmalı
    tokenized_train = tokenized_train.rename_column("label_id", "labels")
    tokenized_test = tokenized_test.rename_column("label_id", "labels")
    
    # Gereksiz sütunları kaldır
    tokenized_train = tokenized_train.remove_columns(["text", "label", "__index_level_0__"])
    tokenized_test = tokenized_test.remove_columns(["text", "label", "__index_level_0__"])
    tokenized_train.set_format("torch")
    tokenized_test.set_format("torch")

    # 3. Modeli Yükle
    logger.info("Ana model (pre-trained) yükleniyor...")
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL_NAME, 
        num_labels=2,
        ignore_mismatched_sizes=True
    )

    # 4. Eğitim (Training) Ayarları
    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)
    training_args = TrainingArguments(
        output_dir=MODEL_OUTPUT_DIR,
        eval_strategy="epoch",
        learning_rate=2e-5,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        num_train_epochs=3,
        weight_decay=0.01,
        save_strategy="epoch",
        load_best_model_at_end=True,
        report_to="none",  # TensorBoard/TensorFlow callback'ini tamamen kapat
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_train,
        eval_dataset=tokenized_test,
        compute_metrics=compute_metrics
    )

    # 5. Eğitimi Başlat
    logger.info("Eğitim (Fine-Tuning) başlatılıyor. Bu işlem cihazınızın gücüne göre biraz sürebilir...")
    trainer.train()

    # 6. Kaydet
    logger.info(f"🎉 Eğitim tamamlandı! Yeni model '{MODEL_OUTPUT_DIR}' klasörüne kaydediliyor.")
    trainer.save_model(MODEL_OUTPUT_DIR)
    tokenizer.save_pretrained(MODEL_OUTPUT_DIR)
    
    # 7. Grafikleri Çizdir (Visualization)
    logger.info("📊 Eğitim grafikleri hazırlanıyor...")
    try:
        history = trainer.state.log_history
        
        # Extract losses and accuracies
        train_loss = [x['loss'] for x in history if 'loss' in x]
        train_epochs = [x['epoch'] for x in history if 'loss' in x]
        
        eval_loss = [x['eval_loss'] for x in history if 'eval_loss' in x]
        eval_acc = [x['eval_accuracy'] for x in history if 'eval_accuracy' in x]
        eval_epochs = [x['epoch'] for x in history if 'eval_loss' in x]

        plt.figure(figsize=(14, 5))

        # Loss Graph
        plt.subplot(1, 2, 1)
        if train_loss:
            plt.plot(train_epochs, train_loss, label='Train Loss', marker='o')
        if eval_loss:
            plt.plot(eval_epochs, eval_loss, label='Eval Loss', marker='s')
        plt.title('Model Loss Over Epochs')
        plt.xlabel('Epochs')
        plt.ylabel('Loss')
        plt.legend()
        plt.grid(True)

        # Accuracy Graph
        plt.subplot(1, 2, 2)
        if eval_acc:
            plt.plot(eval_epochs, eval_acc, label='Eval Accuracy', color='green', marker='s')
        plt.title('Model Accuracy Over Epochs')
        plt.xlabel('Epochs')
        plt.ylabel('Accuracy')
        plt.legend()
        plt.grid(True)

        plt.tight_layout()
        plot_path = os.path.join(MODEL_OUTPUT_DIR, "training_history.png")
        plt.savefig(plot_path)
        plt.close()
        logger.info(f"✅ Grafikler başarıyla kaydedildi: {plot_path}")
    except Exception as e:
        logger.error(f"❌ Grafikler çizilirken bir hata oluştu: {e}")

    logger.info("✅ GenAI Gateway artık Katman 2'de bu özel modeli kullanacak!")

if __name__ == "__main__":
    main()
