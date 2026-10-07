import sqlite3
from pathlib import Path

# Find the main SafeVault folder
BASE_DIR = Path(__file__).resolve().parent.parent

# Put the database inside the database folder
DATABASE_PATH = BASE_DIR / "database" / "safevault.db"


def get_connection():
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