import sqlite3
import json
import os
import datetime
import logging

logger = logging.getLogger(__name__)

class SessionDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        total_packets INTEGER,
                        total_flows INTEGER,
                        malicious_flows INTEGER,
                        stats_json TEXT
                    )
                """)
                conn.commit()
            logger.info("Session database initialized.")
        except Exception as e:
            logger.error(f"Failed to initialize session DB: {e}")

    def save_session(self, filename: str, stats: dict) -> int:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                malicious_count = len(stats.get("malicious_flows", [])) + len(stats.get("beaconing_flows", []))
                
                cursor.execute("""
                    INSERT INTO sessions (timestamp, filename, total_packets, total_flows, malicious_flows, stats_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    datetime.datetime.now().isoformat(),
                    filename,
                    stats.get("total_packets", 0),
                    stats.get("active_flows", 0),
                    malicious_count,
                    json.dumps(stats)
                ))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            return -1

    def get_history(self) -> list:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, timestamp, filename, total_packets, total_flows, malicious_flows FROM sessions ORDER BY id DESC LIMIT 50")
                rows = cursor.fetchall()
                
                history = []
                for row in rows:
                    history.append({
                        "id": row[0],
                        "timestamp": row[1],
                        "filename": row[2],
                        "total_packets": row[3],
                        "total_flows": row[4],
                        "malicious_flows": row[5]
                    })
                return history
        except Exception as e:
            logger.error(f"Failed to fetch history: {e}")
            return []

# Singleton
_db = None
def get_db():
    global _db
    if _db is None:
        db_path = os.path.join(os.path.dirname(__file__), "sessions.db")
        _db = SessionDatabase(db_path)
    return _db
