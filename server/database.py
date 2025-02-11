# server/database.py
import sqlite3
import os

DB_FILE = 'database.sqlite'

def init_db():
    """Initialize (or recreate) the database with columns for security scans, privacy scans, and final score."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Drop table if it exists (for development purposes)
    cursor.execute("DROP TABLE IF EXISTS logs")
    
    cursor.execute('''
        CREATE TABLE logs (
            url TEXT NOT NULL,
            -- Security Scans (10 scans: each has name and result)
            sec_scan1_name TEXT NOT NULL,
            sec_scan1_result TEXT NOT NULL,
            sec_scan2_name TEXT NOT NULL,
            sec_scan2_result TEXT NOT NULL,
            sec_scan3_name TEXT NOT NULL,
            sec_scan3_result TEXT NOT NULL,
            sec_scan4_name TEXT NOT NULL,
            sec_scan4_result TEXT NOT NULL,
            sec_scan5_name TEXT NOT NULL,
            sec_scan5_result TEXT NOT NULL,
            sec_scan6_name TEXT NOT NULL,
            sec_scan6_result TEXT NOT NULL,
            sec_scan7_name TEXT NOT NULL,
            sec_scan7_result TEXT NOT NULL,
            sec_scan8_name TEXT NOT NULL,
            sec_scan8_result TEXT NOT NULL,
            sec_scan9_name TEXT NOT NULL,
            sec_scan9_result TEXT NOT NULL,
            sec_scan10_name TEXT NOT NULL,
            sec_scan10_result TEXT NOT NULL,
            -- Privacy Scans (5 scans: each has name and result)
            priv_scan1_name TEXT NOT NULL,
            priv_scan1_result TEXT NOT NULL,
            priv_scan2_name TEXT NOT NULL,
            priv_scan2_result TEXT NOT NULL,
            priv_scan3_name TEXT NOT NULL,
            priv_scan3_result TEXT NOT NULL,
            priv_scan4_name TEXT NOT NULL,
            priv_scan4_result TEXT NOT NULL,
            priv_scan5_name TEXT NOT NULL,
            priv_scan5_result TEXT NOT NULL,
            final_score REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def insert_log(url,
               sec_scan1_name, sec_scan1_result,
               sec_scan2_name, sec_scan2_result,
               sec_scan3_name, sec_scan3_result,
               sec_scan4_name, sec_scan4_result,
               sec_scan5_name, sec_scan5_result,
               sec_scan6_name, sec_scan6_result,
               sec_scan7_name, sec_scan7_result,
               sec_scan8_name, sec_scan8_result,
               sec_scan9_name, sec_scan9_result,
               sec_scan10_name, sec_scan10_result,
               priv_scan1_name, priv_scan1_result,
               priv_scan2_name, priv_scan2_result,
               priv_scan3_name, priv_scan3_result,
               priv_scan4_name, priv_scan4_result,
               priv_scan5_name, priv_scan5_result,
               final_score):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT rowid FROM logs WHERE url = ?", (url,))
    existing = cursor.fetchone()
    if existing:
        # Update branch: update only the result columns and final_score (assuming scan names remain unchanged)
        cursor.execute("""
            UPDATE logs
            SET sec_scan1_result = ?,
                sec_scan2_result = ?,
                sec_scan3_result = ?,
                sec_scan4_result = ?,
                sec_scan5_result = ?,
                sec_scan6_result = ?,
                sec_scan7_result = ?,
                sec_scan8_result = ?,
                sec_scan9_result = ?,
                sec_scan10_result = ?,
                priv_scan1_result = ?,
                priv_scan2_result = ?,
                priv_scan3_result = ?,
                priv_scan4_result = ?,
                priv_scan5_result = ?,
                final_score = ?,
                timestamp = CURRENT_TIMESTAMP
            WHERE rowid = ?
        """, (
            sec_scan1_result, sec_scan2_result, sec_scan3_result, sec_scan4_result, sec_scan5_result,
            sec_scan6_result, sec_scan7_result, sec_scan8_result, sec_scan9_result, sec_scan10_result,
            priv_scan1_result, priv_scan2_result, priv_scan3_result, priv_scan4_result, priv_scan5_result,
            final_score,
            existing[0]
        ))
    else:
        cursor.execute("""
            INSERT INTO logs (
                url,
                sec_scan1_name, sec_scan1_result,
                sec_scan2_name, sec_scan2_result,
                sec_scan3_name, sec_scan3_result,
                sec_scan4_name, sec_scan4_result,
                sec_scan5_name, sec_scan5_result,
                sec_scan6_name, sec_scan6_result,
                sec_scan7_name, sec_scan7_result,
                sec_scan8_name, sec_scan8_result,
                sec_scan9_name, sec_scan9_result,
                sec_scan10_name, sec_scan10_result,
                priv_scan1_name, priv_scan1_result,
                priv_scan2_name, priv_scan2_result,
                priv_scan3_name, priv_scan3_result,
                priv_scan4_name, priv_scan4_result,
                priv_scan5_name, priv_scan5_result,
                final_score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            url,
            sec_scan1_name, sec_scan1_result,
            sec_scan2_name, sec_scan2_result,
            sec_scan3_name, sec_scan3_result,
            sec_scan4_name, sec_scan4_result,
            sec_scan5_name, sec_scan5_result,
            sec_scan6_name, sec_scan6_result,
            sec_scan7_name, sec_scan7_result,
            sec_scan8_name, sec_scan8_result,
            sec_scan9_name, sec_scan9_result,
            sec_scan10_name, sec_scan10_result,
            priv_scan1_name, priv_scan1_result,
            priv_scan2_name, priv_scan2_result,
            priv_scan3_name, priv_scan3_result,
            priv_scan4_name, priv_scan4_result,
            priv_scan5_name, priv_scan5_result,
            final_score
        ))
    conn.commit()
    conn.close()


def get_all_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT url,
               sec_scan1_name, sec_scan1_result,
               sec_scan2_name, sec_scan2_result,
               sec_scan3_name, sec_scan3_result,
               sec_scan4_name, sec_scan4_result,
               sec_scan5_name, sec_scan5_result,
               sec_scan6_name, sec_scan6_result,
               sec_scan7_name, sec_scan7_result,
               sec_scan8_name, sec_scan8_result,
               sec_scan9_name, sec_scan9_result,
               sec_scan10_name, sec_scan10_result,
               priv_scan1_name, priv_scan1_result,
               priv_scan2_name, priv_scan2_result,
               priv_scan3_name, priv_scan3_result,
               priv_scan4_name, priv_scan4_result,
               priv_scan5_name, priv_scan5_result,
               final_score,
               timestamp
        FROM logs
        ORDER BY timestamp DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for row in rows:
        logs.append({
            'url': row[0],
            'sec_scan1_name': row[1],
            'sec_scan1_result': row[2],
            'sec_scan2_name': row[3],
            'sec_scan2_result': row[4],
            'sec_scan3_name': row[5],
            'sec_scan3_result': row[6],
            'sec_scan4_name': row[7],
            'sec_scan4_result': row[8],
            'sec_scan5_name': row[9],
            'sec_scan5_result': row[10],
            'sec_scan6_name': row[11],
            'sec_scan6_result': row[12],
            'sec_scan7_name': row[13],
            'sec_scan7_result': row[14],
            'sec_scan8_name': row[15],
            'sec_scan8_result': row[16],
            'sec_scan9_name': row[17],
            'sec_scan9_result': row[18],
            'sec_scan10_name': row[19],
            'sec_scan10_result': row[20],
            'priv_scan1_name': row[21],
            'priv_scan1_result': row[22],
            'priv_scan2_name': row[23],
            'priv_scan2_result': row[24],
            'priv_scan3_name': row[25],
            'priv_scan3_result': row[26],
            'priv_scan4_name': row[27],
            'priv_scan4_result': row[28],
            'priv_scan5_name': row[29],
            'priv_scan5_result': row[30],
            'final_score': row[31],
            'timestamp': row[32]
        })
    return logs
