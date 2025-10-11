import sqlite3
import random
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sq_messages.db")
FLAG = os.environ.get('FLAG', 'CTFITB2025{FAKE_FLAG_DONT_SUBMIT}')


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sq_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            category TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY,
            event TEXT NOT NULL,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            key_name TEXT NOT NULL,
            secret_value TEXT NOT NULL,
            description TEXT
        )
    ''')
    
    users = [
        ("admin", "securepass456"),
        ("john_doe", "mysecret123"),
        ("service_acc", "s3rv1c3@cc")
    ]
    
    logs = [
        ("authentication", "User login successful"),
        ("file_access", "Document accessed"),
        ("error", "Permission denied")
    ]
    
    secrets = [
        ("api_key", "dummy_api_key_12345", "External service API key"),
        ("database_url", "postgresql://localhost:5432/test", "Database connection string"),
        ("encryption_key", FLAG, "Main encryption key for the system"),
        ("backup_token", "token_789xyz", "Backup system access token")
    ]
    
    cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)
    cursor.executemany('INSERT INTO system_logs (event, details) VALUES (?, ?)', logs)
    cursor.executemany('INSERT INTO secrets (key_name, secret_value, description) VALUES (?, ?, ?)', secrets)
    
    # random ahh message. thx claude
    messages = [
        ("Exceptional social intelligence demonstrated. You exhibit advanced emotional awareness and sophisticated interpersonal navigation skills.", "facilitate"),
        ("Your response indicates superior social cognition with strong empathetic reasoning and contextual sensitivity.", "facilitate"),
        ("Outstanding social quotient. You demonstrate nuanced understanding of social dynamics and emotional intelligence.", "facilitate"),
        ("Highly developed social awareness evidenced. Your approach shows mature consideration for interpersonal complexities.", "facilitate"),
        ("Advanced social intelligence confirmed. You exhibit excellent judgment in navigating delicate social situations.", "facilitate"),
        ("Remarkable social quotient displayed. Your response reflects deep understanding of human behavioral patterns.", "facilitate"),
        ("Solid social intelligence foundation detected. Your response shows good awareness of interpersonal dynamics.", "engage_later"),
        ("Moderate social quotient evidenced. You demonstrate developing skills in reading social contexts and cues.", "engage_later"),
        ("Good social awareness indicated. Your approach suggests growing emotional intelligence and interpersonal sensitivity.", "engage_later"),
        ("Developing social intelligence observed. You show promising signs of enhanced social cognition abilities.", "engage_later"),
        ("Acceptable social quotient demonstrated. Your response indicates baseline interpersonal awareness with room for growth.", "acknowledge"),
        ("Moderate social intelligence reflected. You exhibit standard emotional processing with potential for advancement.", "acknowledge"),
        ("Basic social quotient detected. Consider developing greater sensitivity to interpersonal dynamics and emotional cues.", "wait_silent"),
        ("Limited social awareness evidenced. Enhanced observation of social contexts and non-verbal communication recommended.", "wait_silent"),
        ("Foundational social intelligence observed. Focus on building empathy and understanding diverse social perspectives.", "wait_silent"),
        ("Elementary social quotient indicated. Improvement in reading social situations and emotional states suggested.", "interrupt"),
        ("Basic social awareness demonstrated. Development of advanced interpersonal skills would be beneficial.", "interrupt"),
        ("Initial-stage social intelligence detected. Consider practicing active observation of social interactions and dynamics.", "interrupt")
    ]
    
    cursor.execute("SELECT COUNT(*) FROM sq_messages")
    count = cursor.fetchone()[0]
    
    if count == 0:
        cursor.executemany("INSERT INTO sq_messages (message, category) VALUES (?, ?)", messages)
        conn.commit()
    
    conn.close()

def cleanup_databases():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

def get_random_message(response):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT message FROM sq_messages WHERE category = '{response}'")
    messages = cursor.fetchall()
    conn.close()
    
    if messages:
        return messages
    return "Your social intelligence assessment is complete. Consider further development of interpersonal skills."
