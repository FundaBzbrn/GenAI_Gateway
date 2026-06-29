#!/usr/bin/env python3
import os
import socket
import time
import subprocess

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
TIMEOUT = 60

print(f"Waiting for database at {DB_HOST}:{DB_PORT}...")
start = time.time()
while True:
    try:
        with socket.create_connection((DB_HOST, DB_PORT), timeout=5):
            print("Database reachable.")
            break
    except OSError:
        if time.time() - start > TIMEOUT:
            raise SystemExit(f"Database did not become available within {TIMEOUT} seconds")
        print("Waiting for DB...")
        time.sleep(1)

print("Starting application")
subprocess.run([
    "uvicorn",
    "app.main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8001",
    "--proxy-headers",
    "--log-level",
    "info"
], check=True)
