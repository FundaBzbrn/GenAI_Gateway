# Dockerfile for GenAI Gateway
FROM python:3.12-slim

# Sistemin çalışma dizini
WORKDIR /app

# Ortam değişkenleri
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Sistem araçları ve bağımlılıkları yükle
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Kaynak kodu kopyala ve entrypoint'i ekle
COPY . .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8001

CMD ["/entrypoint.sh"]
