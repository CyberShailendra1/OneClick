#!/usr/bin/env python3
"""
OneClick "doctor" - run this BEFORE `uvicorn api:app` whenever the server
fails to start or after pulling new code / installing on a new machine.
It checks every dependency (Python package, system binary, model file)
individually and reports exactly which one is missing.

Usage:
    python3 doctor.py
"""

import importlib
import os
import shutil
import socket
import sys

GREEN, RED, YELLOW, RESET, BOLD = "\033[92m", "\033[91m", "\033[93m", "\033[0m", "\033[1m"


def ok(msg):
    print(f"{GREEN}[OK]{RESET} {msg}")


def fail(msg):
    print(f"{RED}[FAIL]{RESET} {msg}")


def warn(msg):
    print(f"{YELLOW}[WARN]{RESET} {msg}")


# (import_name, pip_name, required_for)
CORE_PACKAGES = [
    ("fastapi", "fastapi", "FastAPI backend REST framework"),
    ("uvicorn", "uvicorn", "ASGI web server for API and React Web UI"),
    ("requests", "requests", "VirusTotal / URL scanning"),
    ("androguard", "androguard", "APK static analysis (Layer 2)"),
    ("sklearn", "scikit-learn", "AI risk scoring (Layer 3)"),
    ("pandas", "pandas", "data tables and feature processing"),
    ("joblib", "joblib", "loading the trained ML model"),
    ("numpy", "numpy", "ML feature vectors"),
    ("reportlab", "reportlab", "PDF report export"),
    ("shap", "shap", "SHAP explainability"),
    ("xgboost", "xgboost", "optional alternate ML model"),
    ("loguru", "loguru", "used internally by androguard"),
    ("bs4", "beautifulsoup4", "phishing landing-page investigation"),
]

OPTIONAL_PACKAGES = [
    ("pyzbar", "pyzbar", "QR code scanner (needs system lib libzbar0 too)"),
    ("pytesseract", "pytesseract", "screenshot OCR scanner (needs system binary tesseract-ocr too)"),
    ("qrcode", "qrcode", "only used by tests/demos, not the app itself at runtime"),
    ("whois", "python-whois", "domain age check (also needs network access to WHOIS servers, port 43)"),
    ("telegram", "python-telegram-bot", "the Telegram bot (telegram_bot.py)"),
]

SYSTEM_BINARIES = [
    ("tesseract", "sudo apt install tesseract-ocr", "screenshot OCR scanner tab"),
]


def check_python_version():
    print(f"{BOLD}Python version{RESET}")
    v = sys.version_info
    if v < (3, 10):
        fail(f"Python {v.major}.{v.minor} detected - OneClick expects 3.10+. Some packages may not install correctly.")
    else:
        ok(f"Python {v.major}.{v.minor}.{v.micro}")
    print()


def check_packages(packages, label, required):
    print(f"{BOLD}{label}{RESET}")
    missing = []
    for import_name, pip_name, purpose in packages:
        try:
            importlib.import_module(import_name)
            ok(f"{pip_name}")
        except ImportError as e:
            missing.append(pip_name)
            if required:
                fail(f"{pip_name} - MISSING. Needed for: {purpose}\n         Fix: pip install {pip_name}\n         Error was: {e}")
            else:
                warn(f"{pip_name} - not installed. Needed for: {purpose}\n         Fix: pip install {pip_name}")
    print()
    return missing


def check_system_binaries():
    print(f"{BOLD}System binaries{RESET}")
    for binary, install_cmd, purpose in SYSTEM_BINARIES:
        path = shutil.which(binary)
        if path:
            ok(f"{binary} found at {path}")
        else:
            warn(f"{binary} not found on PATH. Needed for: {purpose}\n         Fix: {install_cmd}")
    print()


def check_model():
    print(f"{BOLD}Trained ML model{RESET}")
    model_path = os.path.join(os.path.dirname(__file__), "models", "rf_model.joblib")
    if os.path.exists(model_path):
        size_kb = os.path.getsize(model_path) / 1024
        ok(f"models/rf_model.joblib found ({size_kb:.0f} KB)")
    else:
        fail("models/rf_model.joblib NOT FOUND. The app will load but AI risk scoring will error.\n"
             "         Fix: python models/train_model.py")
    print()


def check_port(port=8000):
    print(f"{BOLD}Port {port} availability{RESET}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = s.connect_ex(("127.0.0.1", port))
    s.close()
    if result == 0:
        warn(f"Something is already listening on port {port}.\n"
             f"         Fix: stop the existing process or use --port <number>")
    else:
        ok(f"Port {port} is free")
    print()


def check_database():
    print(f"{BOLD}SQLite database{RESET}")
    db_path = os.path.join(os.path.dirname(__file__), "oneclick.db")
    if os.path.exists(db_path):
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.execute("SELECT 1")
            conn.close()
            ok("oneclick.db exists and is readable")
        except Exception as e:
            fail(f"oneclick.db exists but seems corrupt: {e}\n         Fix: rm oneclick.db")
    else:
        ok("oneclick.db doesn't exist yet - will be created automatically on first scan")
    print()


def main():
    print(f"{BOLD}=== OneClick Doctor ==={RESET}\n")

    check_python_version()
    missing_required = check_packages(CORE_PACKAGES, "Core packages (required)", required=True)
    check_packages(OPTIONAL_PACKAGES, "Optional packages (feature-specific)", required=False)
    check_system_binaries()
    check_model()
    check_port(8000)
    check_database()

    print(f"{BOLD}=== Summary ==={RESET}")
    if missing_required:
        fail(f"{len(missing_required)} required package(s) missing: {', '.join(missing_required)}")
        print(f"\n  Fix everything at once:\n    {BOLD}pip install -r requirements.txt{RESET}\n")
        sys.exit(1)
    else:
        ok("All required packages present. To launch the server and Web UI:")
        print(f"\n    {BOLD}uvicorn api:app --host 0.0.0.0 --port 8000{RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
