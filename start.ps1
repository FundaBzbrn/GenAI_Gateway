# GenAI Security Gateway - Akıllı Başlatma Scripti
# Bu script çalıştırıldığında:
# 1. 8001 portunu kullanan her işlemi otomatik kapatır
# 2. Varsa eski Python sunucu süreçlerini temizler
# 3. Sunucuyu temiz başlatır

Write-Host "🚀 GenAI Security Gateway başlatılıyor..." -ForegroundColor Cyan

# 8001 portunu kullanan süreci bul ve öldür
$portPid = netstat -ano 2>$null | Select-String ":8001 " | ForEach-Object {
    ($_ -split '\s+')[-1]
} | Select-Object -First 1

if ($portPid -and $portPid -match '^\d+$') {
    Write-Host "⚠️  Port 8001 PID $portPid tarafından kullanılıyor, kapatılıyor..." -ForegroundColor Yellow
    try {
        Stop-Process -Id $portPid -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Host "✅ Port 8001 serbest bırakıldı." -ForegroundColor Green
    } catch {
        Write-Host "Port kapatma başarısız, devam ediliyor..." -ForegroundColor Yellow
    }
}

# Ek güvenlik: uvicorn çalıştıran eski python süreçlerini temizle
$uvicornProcs = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
    try { (Get-WmiObject Win32_Process -Filter "ProcessId='$($_.Id)'" -ErrorAction SilentlyContinue).CommandLine -like "*uvicorn*" } catch { $false }
}
if ($uvicornProcs) {
    $uvicornProcs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "✅ Eski uvicorn süreçleri temizlendi." -ForegroundColor Green
}

Write-Host "▶️  Sunucu başlatılıyor (http://127.0.0.1:8001)..." -ForegroundColor Cyan
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8001 --host 127.0.0.1
