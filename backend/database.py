import os
import sqlite3
from pathlib import Path

# Find the main SafeVault folder
BASE_DIR = Path(__file__).resolve().parent.parent

# Optional: SAFEVAULT_STORAGE_PATH points at one persistent directory that
# holds both the database and the uploaded evidence. When it is NOT set the
# original locations are used (database/safevault.db and backend/uploads).
_storage_env = (os.environ.get("SAFEVAULT_STORAGE_PATH") or "").strip()
STORAGE_ROOT = Path(_storage_env).expanduser().resolve() if _storage_env else None

if STORAGE_ROOT:
    DATABASE_PATH = STORAGE_ROOT / "safevault.db"
else:
    # Put the database inside the database folder
    DATABASE_PATH = BASE_DIR / "database" / "safevault.db"


def get_connection():
    # Make sure the folder exists (a fresh deployment has an empty disk)
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DATABASE_PATH)


def initialize_database():
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            evidence_type TEXT,
            incident_date TEXT,
            category TEXT,
            severity TEXT,
            summary TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


if __name__ == "__main__":
    initialize_database()
    print("SafeVault database initialized successfully!")