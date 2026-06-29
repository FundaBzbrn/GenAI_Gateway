# GenAI Gateway Docker + CloudPanel Deployment

## Amaç
Bu rehber, GenAI Gateway projesini Ubuntu sunucunuzda `/opt/GenAI_Gateway` dizinine kurmak, PostgreSQL ile Docker konteynerinde çalıştırmak ve `genai.fjcreativehub.com` üzerinden CloudPanel reverse proxy ile yayınlamak için hazırlanmıştır.

---

## 🚀 Projeyi Hızlıca Başlatma (Yerel Ortam)

Eğer projeyi sunucuya kurmadan, **kendi bilgisayarınızda (Windows)** hızlıca denemek ve açmak istiyorsanız, proje dizininde aşağıdaki betiklerden birini çalıştırabilirsiniz:

**Windows (Komut Satırı / CMD):**
```cmd
start_all.bat
```

**Windows (PowerShell):**
```powershell
.\start.ps1
```

**Python ile (Tüm İşletim Sistemleri):**
```bash
python start_system.py
```
*(Not: Bu komutlar hem FastAPI arka yüzünü hem de Streamlit kullanıcı arayüzünü aynı anda otomatik olarak başlatır ve tarayıcınızı açar.)*

---

## 1) Sunucuya proje indirme

Sunucunuza SSH ile bağlanın ve proje dizinini oluşturun:

```bash
sudo mkdir -p /opt/GenAI_Gateway
sudo chown $USER:$USER /opt/GenAI_Gateway
cd /opt/GenAI_Gateway
```

Projeyi GitHub veya başka bir kaynaktan indiriyorsanız:

```bash
git clone <repo-url> /opt/GenAI_Gateway
```

Eğer proje dosyalarını doğrudan sunucuya yüküyorsanız, `/opt/GenAI_Gateway` içine kopyalayın.

---

## 2) Docker ve Docker Compose kurma

Ubuntu için aşağıdaki komutları çalıştırın:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

Kurulum tamamlandıktan sonra Docker servisinin çalıştığını doğrulayın:

```bash
sudo systemctl enable docker --now
sudo docker version
sudo docker compose version
```

---

## 3) Proje yapılandırması

Proje kök dizininde `.env.example` dosyası oluşturuldu. Yeni bir `.env` dosyası oluşturun:

```bash
cd /opt/GenAI_Gateway
cp .env.example .env
```

`.env` içinde aşağıdaki değerleri ayarlayın:

- `DB_HOST=db`
- `DB_PORT=5432`
- `DB_NAME=genai_gateway`
- `DB_USER=postgres`
- `DB_PASSWORD=<güçlü-parola>`
- `JWT_SECRET=<rastgele-gizli-anahtar>`
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` (OAuth kullanmayacaksanız boş bırakabilirsiniz)
- `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` (OAuth kullanmayacaksanız boş bırakabilirsiniz)
- `GEMINI_API_KEY` (OpenAI/Gemini erişimi gerekiyorsa burada girin)

> Not: `.env` dosyası `.dockerignore` içinde listelendiği için Docker imajına dahil edilmez.

---

## 4) Docker Compose ile başlatma

```bash
cd /opt/GenAI_Gateway
sudo docker compose up -d --build
```

Bu komut şu servisleri başlatır:

- `web`: FastAPI uygulaması
- `db`: PostgreSQL veritabanı

Durumu kontrol etmek için:

```bash
sudo docker compose ps
sudo docker compose logs -f web
```

---

## 5) İlk kontroller

Uygulama ayağa kalktıktan sonra doğrudan sunucuda çalışıp çalışmadığını test edin:

```bash
curl http://127.0.0.1:8001/api/v1/health
```

Yanıt `{"status":"healthy",...}` benzeri olmalıdır.

---

## 6) CloudPanel Reverse Proxy ayarı

CloudPanel yönetim paneline gidin ve alan adının (`genai.fjcreativehub.com`) reverse proxy ayarını yapın.

CloudPanel üzerinde:

1. `Websites` alanına gidin.
2. `genai.fjcreativehub.com` alan adını ekleyin veya mevcut siteyi seçin.
3. `Reverse Proxy` bölümünde aşağıdaki ayarları yapın:
   - `Proxy HTTP` için hedef: `http://127.0.0.1:8001`
   - `Proxy HTTPS` için hedef: `http://127.0.0.1:8001`
4. Gerekirse `SSL/TLS` ayarlarını etkinleştirin.
5. `Restart` veya `Apply` ile servisi yeniden başlatın.

> Not: Uygulama zaten Docker üzerinde 8001 portunda çalıştığı için CloudPanel sadece bu portu yönlendirir.

---

## 7) PostgreSQL veri kalıcılığı

`docker-compose.yml` içerisinde aşağıdaki kalıcı veri hacmi tanımlandı:

```yaml
volumes:
  genai_gateway_pgdata:
```

Bu sayede PostgreSQL verileri konteyner yeniden başlasa bile korunur.

---

## 8) Yönetim hesabı

Sunucu ilk başlatıldığında uygulama otomatik olarak `superadmin` kullanıcısını oluşturur ve varsayılan şifre:

- `superadmin` / `superadmin123`

Bu şifreyi hemen değiştirin.

---

## 9) Sunucu üzerinde /opt dizinine kurulum

Proje kök dizini önerisi:

```bash
/opt/GenAI_Gateway
```

Bu dizin altında `Dockerfile`, `docker-compose.yml`, `.env`, `app/`, `database_scripts/` vb. dosyalar yer alır.

---

## 10) Kalıcı çalışma ve yeniden başlatma

Sunucu yeniden başlatıldığında hizmetin otomatik başlaması için Docker Compose ile cron veya systemd kullanabilirsiniz.

Basitçe `docker compose` ile yeniden başlatma:

```bash
cd /opt/GenAI_Gateway
sudo docker compose up -d
```

---

## 11) Önerilen ek iyileştirmeler

- Production için `CORS` izinlerini sadece gerekli domainlerle sınırlandırın.
- `JWT_SECRET` değerini güçlü bir rastgele anahtar yapın.
- `GOOGLE_CLIENT_*` ve `GITHUB_CLIENT_*` değerlerini doğru OAuth redirect URI ile güncelleyin.
- CloudPanel üzerinde HTTPS zorunlu hale getirin.
- Uygulamayı `systemd` veya CloudPanel `Docker` desteği ile daha otomatik başlatabilirsiniz.

## OAuth Redirect URI Ayarları

CloudPanel veya OAuth sağlayıcılarında (Google/Github) uygulamanızı kaydederken aşağıdaki `redirect_uri` değerlerini kullanın (veya kendi domaininizin doğru yolunu gösterin):

```
https://genai.fjcreativehub.com/api/v1/auth/google/callback
https://genai.fjcreativehub.com/api/v1/auth/github/callback
```

Eğer farklı bir path kullanıyorsanız `.env` içindeki `OAUTH_REDIRECT_GOOGLE` ve `OAUTH_REDIRECT_GITHUB` değerlerini güncelleyin.

## `.env` doğrulama

Sunucuya aktarmadan önce aşağıdaki komutla temel doğrulamayı çalıştırın:

```bash
python3 scripts/check_env.py
```

Bu betik; eksik `DB_*` değerlerini, `JWT_SECRET` uzunluğunu ve OAuth redirect ayarlarını kontrol eder ve uyarılar verir.
