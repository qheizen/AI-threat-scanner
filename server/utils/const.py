import os

UTILS_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(UTILS_DIR, "..", "database")

DB_PATH = os.path.abspath(os.path.join(DB_DIR, "ai_threat_scanner.db"))

HOST = "0.0.0.0"
PORT = 8300