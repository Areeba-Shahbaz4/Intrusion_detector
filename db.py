# ZERO TRUST AI INTRUSION DETECTION SYSTEM
# DATABASE MODULE
import sqlite3
DATABASE_NAME = "ids.db"
# CREATE DATABASE
def create_database():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    # USERS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # SCAN HISTORY TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_records INTEGER NOT NULL,
            normal_records INTEGER NOT NULL,
            attack_records INTEGER NOT NULL,
            attack_percentage REAL NOT NULL,
            security_status TEXT,
            ml_normal INTEGER,
            ml_attack INTEGER,
            ml_attack_percentage REAL,
            ml_confidence REAL,
            dl_normal INTEGER,
            dl_attack INTEGER,
            dl_attack_percentage REAL,
            dl_confidence REAL,
            model_agreement INTEGER,
            model_agreement_percentage REAL,
            scan_time TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    print("=" * 60)
    print("ZERO TRUST AI IDS DATABASE")
    print("=" * 60)
    print("Database Created Successfully!")
    print("=" * 60)
# RUN DATABASE
if __name__ == "__main__":
    create_database()