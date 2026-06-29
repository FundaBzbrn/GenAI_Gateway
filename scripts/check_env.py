#!/usr/bin/env python3
"""
Simple .env validator for deployment checks.
Usage: python scripts/check_env.py
"""
import os
from dotenv import load_dotenv

load_dotenv()

REQUIRED = ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD", "JWT_SECRET"]
missing = [k for k in REQUIRED if not os.getenv(k)]

if missing:
    print("ERROR: Missing required env vars:", ", ".join(missing))
    raise SystemExit(1)

jwt = os.getenv("JWT_SECRET", "")
if len(jwt) < 32:
    print("WARNING: JWT_SECRET is shorter than 32 characters; consider using a stronger secret.")
else:
    print("OK: JWT_SECRET length is sufficient.")

use_sqlite = os.getenv("USE_SQLITE", "true").lower() == "true"
if use_sqlite:
    print("WARNING: USE_SQLITE=true — production should use PostgreSQL (USE_SQLITE=false).")
else:
    print("OK: Using PostgreSQL settings.")

# OAuth redirects
g_redirect = os.getenv("OAUTH_REDIRECT_GOOGLE")
gh_redirect = os.getenv("OAUTH_REDIRECT_GITHUB")
if not g_redirect:
    print("WARNING: OAUTH_REDIRECT_GOOGLE not set. Add your Google OAuth redirect URI.")
else:
    print("OK: Google redirect URI set to:", g_redirect)

if not gh_redirect:
    print("WARNING: OAUTH_REDIRECT_GITHUB not set. Add your Github OAuth redirect URI.")
else:
    print("OK: Github redirect URI set to:", gh_redirect)

print("All checks done.")
