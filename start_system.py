#!/usr/bin/env python
"""
GenAI Security Gateway - Complete Startup Manager
Starts Backend and Streamlit in managed processes with graceful shutdown
"""

import subprocess
import time
import os
import sys
import signal
import atexit
import platform

# Global process references for cleanup
backend_process = None
streamlit_process = None

def cleanup_processes():
    """Gracefully terminate all child processes."""
    global backend_process, streamlit_process
    
    print("\n🛑 Sistem kapatılıyor...")
    
    # Terminate gracefully (SIGTERM on Unix, CTRL_BREAK_EVENT on Windows)
    if backend_process and backend_process.poll() is None:
        print("   • Backend process kapatılıyor...")
        try:
            if platform.system() == "Windows":
                backend_process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                backend_process.terminate()
            backend_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            backend_process.kill()
    
    if streamlit_process and streamlit_process.poll() is None:
        print("   • Streamlit process kapatılıyor...")
        try:
            if platform.system() == "Windows":
                streamlit_process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                streamlit_process.terminate()
            streamlit_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            streamlit_process.kill()
    
    print("✓ Sistem tamamen kapatıldı")

def main():
    global backend_process, streamlit_process
    
    if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    
    print("="*60)
    print("GenAI Security Gateway - Başlangıç")
    print("="*60)
    print()
    
    # Register cleanup handler
    atexit.register(cleanup_processes)
    signal.signal(signal.SIGINT, lambda *args: sys.exit(0))
    
    # Check .env
    if not os.path.exists('.env'):
        print("❌ HATA: .env dosyası bulunamadı!")
        print("   Lütfen .env.template kopyalayarak .env oluşturun")
        sys.exit(1)
    
    print("✓ .env dosyası kontrol edildi")
    print()
    
    # Start Backend
    print("[1/2] Backend başlatılıyor (Port 8001)...")
    try:
        # Use creationflags for Windows to allow proper signal handling
        kwargs = {}
        if platform.system() == "Windows":
            kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
        
        backend_process = subprocess.Popen(
            [
                sys.executable, "-m", "uvicorn",
                "app.main:app",
                "--port", "8001",
                "--reload"
            ],
            **kwargs
        )
        print("✓ Backend process başlatıldı (PID: {})".format(backend_process.pid))
    except Exception as e:
        print(f"❌ Backend başlatılamadı: {e}")
        sys.exit(1)
    
    # Wait for backend startup
    time.sleep(3)
    
    print()
    
    # Start Streamlit
    print("[2/2] Streamlit UI başlatılıyor (Port 8501)...")
    try:
        kwargs = {}
        if platform.system() == "Windows":
            kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
        
        streamlit_process = subprocess.Popen(
            [
                sys.executable, "-m", "streamlit",
                "run", "streamlit_app.py",
                "--server.port=8501",
                "--server.address=localhost"
            ],
            **kwargs
        )
        print("✓ Streamlit process başlatıldı (PID: {})".format(streamlit_process.pid))
    except Exception as e:
        print(f"❌ Streamlit başlatılamadı: {e}")
        cleanup_processes()
        sys.exit(1)
    
    print()
    print("="*60)
    print("✓ Sistem Başarıyla Başlatıldı!")
    print("="*60)
    print()
    print("📌 Erişim Adresleri:")
    print("   • Backend  : http://127.0.0.1:8001")
    print("   • API Docs : http://127.0.0.1:8001/docs")
    print("   • Streamlit: http://localhost:8501")
    print()
    print("💡 Çıkış: CTRL+C tuşlarına basın")
    print()
    
    # Monitor both processes
    try:
        while True:
            # Check if either process has died
            backend_alive = backend_process.poll() is None
            streamlit_alive = streamlit_process.poll() is None
            
            if not backend_alive:
                print("❌ Backend process sonlandırıldı (exit code: {})".format(backend_process.returncode))
                break
            if not streamlit_alive:
                print("❌ Streamlit process sonlandırıldı (exit code: {})".format(streamlit_process.returncode))
                break
            
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup_processes()
        sys.exit(0)

if __name__ == "__main__":
    main()

