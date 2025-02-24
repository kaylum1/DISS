import sqlite3
import os

DB_FILE = 'database.sqlite'

def init_db():
    """Initialize (or recreate) the database with columns for 22 scans and a final score."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("DROP TABLE IF EXISTS logs")
    
    cursor.execute('''
        CREATE TABLE logs (
            url TEXT NOT NULL,
            xss_scan_name TEXT NOT NULL,
            xss_scan_result TEXT NOT NULL,
            vuln_scan_name TEXT NOT NULL,
            vuln_scan_result TEXT NOT NULL,
            privacy_tracker_scan_name TEXT NOT NULL,
            privacy_tracker_scan_result TEXT NOT NULL,
            privacy_third_party_script_scan_name TEXT NOT NULL,
            privacy_third_party_script_scan_result TEXT NOT NULL,
            ssl_scan_name TEXT NOT NULL,
            ssl_scan_result TEXT NOT NULL,
            sql_scan_name TEXT NOT NULL,
            sql_scan_result TEXT NOT NULL,
            headers_scan_name TEXT NOT NULL,
            headers_scan_result TEXT NOT NULL,
            privacy_audit_scan_name TEXT NOT NULL,
            privacy_audit_scan_result TEXT NOT NULL,
            performance_scan_name TEXT NOT NULL,
            performance_scan_result TEXT NOT NULL,
            outdated_scan_name TEXT NOT NULL,
            outdated_scan_result TEXT NOT NULL,
            mixed_scan_name TEXT NOT NULL,
            mixed_scan_result TEXT NOT NULL,
            directory_scan_name TEXT NOT NULL,
            directory_scan_result TEXT NOT NULL,
            csrf_scan_name TEXT NOT NULL,
            csrf_scan_result TEXT NOT NULL,
            csp_scan_name TEXT NOT NULL,
            csp_scan_result TEXT NOT NULL,
            https_scan_name TEXT NOT NULL,
            https_scan_result TEXT NOT NULL,
            third_party_data_collection_scan_name TEXT NOT NULL,
            third_party_data_collection_scan_result TEXT NOT NULL,
            tracker_detection_scan_name TEXT NOT NULL,
            tracker_detection_scan_result TEXT NOT NULL,
            fingerprinting_scan_name TEXT NOT NULL,
            fingerprinting_scan_result TEXT NOT NULL,
            referrer_dnt_scan_name TEXT NOT NULL,
            referrer_dnt_scan_result TEXT NOT NULL,
            dnt_scan_name TEXT NOT NULL,
            dnt_scan_result TEXT NOT NULL,
            data_leakage_scan_name TEXT NOT NULL,
            data_leakage_scan_result TEXT NOT NULL,
            cookie_scan_name TEXT NOT NULL,
            cookie_scan_result TEXT NOT NULL,
            final_score REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def insert_log(url, xss_scan_name, xss_scan_result, vuln_scan_name, vuln_scan_result,
               privacy_tracker_scan_name, privacy_tracker_scan_result, privacy_third_party_script_scan_name, privacy_third_party_script_scan_result,
               ssl_scan_name, ssl_scan_result, sql_scan_name, sql_scan_result,
               headers_scan_name, headers_scan_result, privacy_audit_scan_name, privacy_audit_scan_result,
               performance_scan_name, performance_scan_result, outdated_scan_name, outdated_scan_result,
               mixed_scan_name, mixed_scan_result, directory_scan_name, directory_scan_result,
               csrf_scan_name, csrf_scan_result, csp_scan_name, csp_scan_result,
               https_scan_name, https_scan_result, third_party_data_collection_scan_name, third_party_data_collection_scan_result,
               tracker_detection_scan_name, tracker_detection_scan_result, fingerprinting_scan_name, fingerprinting_scan_result,
               referrer_dnt_scan_name, referrer_dnt_scan_result, dnt_scan_name, dnt_scan_result,
               data_leakage_scan_name, data_leakage_scan_result, cookie_scan_name, cookie_scan_result,
               final_score):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT rowid FROM logs WHERE url = ?", (url,))
    existing = cursor.fetchone()
    if existing:
        cursor.execute("""
            UPDATE logs
            SET xss_scan_result = ?,
                vuln_scan_result = ?,
                privacy_tracker_scan_result = ?,
                privacy_third_party_script_scan_result = ?,
                ssl_scan_result = ?,
                sql_scan_result = ?,
                headers_scan_result = ?,
                privacy_audit_scan_result = ?,
                performance_scan_result = ?,
                outdated_scan_result = ?,
                mixed_scan_result = ?,
                directory_scan_result = ?,
                csrf_scan_result = ?,
                csp_scan_result = ?,
                https_scan_result = ?,
                third_party_data_collection_scan_result = ?,
                tracker_detection_scan_result = ?,
                fingerprinting_scan_result = ?,
                referrer_dnt_scan_result = ?,
                dnt_scan_result = ?,
                data_leakage_scan_result = ?,
                cookie_scan_result = ?,
                final_score = ?,
                timestamp = CURRENT_TIMESTAMP
            WHERE rowid = ?
        """, (
            xss_scan_result,
            vuln_scan_result,
            privacy_tracker_scan_result,
            privacy_third_party_script_scan_result,
            ssl_scan_result,
            sql_scan_result,
            headers_scan_result,
            privacy_audit_scan_result,
            performance_scan_result,
            outdated_scan_result,
            mixed_scan_result,
            directory_scan_result,
            csrf_scan_result,
            csp_scan_result,
            https_scan_result,
            third_party_data_collection_scan_result,
            tracker_detection_scan_result,
            fingerprinting_scan_result,
            referrer_dnt_scan_result,
            dnt_scan_result,
            data_leakage_scan_result,
            cookie_scan_result,
            final_score,
            existing[0]
        ))
    else:
        cursor.execute("""
            INSERT INTO logs (
                url, xss_scan_name, xss_scan_result,
                vuln_scan_name, vuln_scan_result,
                privacy_tracker_scan_name, privacy_tracker_scan_result,
                privacy_third_party_script_scan_name, privacy_third_party_script_scan_result,
                ssl_scan_name, ssl_scan_result,
                sql_scan_name, sql_scan_result,
                headers_scan_name, headers_scan_result,
                privacy_audit_scan_name, privacy_audit_scan_result,
                performance_scan_name, performance_scan_result,
                outdated_scan_name, outdated_scan_result,
                mixed_scan_name, mixed_scan_result,
                directory_scan_name, directory_scan_result,
                csrf_scan_name, csrf_scan_result,
                csp_scan_name, csp_scan_result,
                https_scan_name, https_scan_result,
                third_party_data_collection_scan_name, third_party_data_collection_scan_result,
                tracker_detection_scan_name, tracker_detection_scan_result,
                fingerprinting_scan_name, fingerprinting_scan_result,
                referrer_dnt_scan_name, referrer_dnt_scan_result,
                dnt_scan_name, dnt_scan_result,
                data_leakage_scan_name, data_leakage_scan_result,
                cookie_scan_name, cookie_scan_result,
                final_score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (url, xss_scan_name, xss_scan_result, vuln_scan_name, vuln_scan_result,
              privacy_tracker_scan_name, privacy_tracker_scan_result, privacy_third_party_script_scan_name, privacy_third_party_script_scan_result,
              ssl_scan_name, ssl_scan_result, sql_scan_name, sql_scan_result,
              headers_scan_name, headers_scan_result, privacy_audit_scan_name, privacy_audit_scan_result,
              performance_scan_name, performance_scan_result, outdated_scan_name, outdated_scan_result,
              mixed_scan_name, mixed_scan_result, directory_scan_name, directory_scan_result,
              csrf_scan_name, csrf_scan_result, csp_scan_name, csp_scan_result,
              https_scan_name, https_scan_result, third_party_data_collection_scan_name, third_party_data_collection_scan_result,
              tracker_detection_scan_name, tracker_detection_scan_result, fingerprinting_scan_name, fingerprinting_scan_result,
              referrer_dnt_scan_name, referrer_dnt_scan_result, dnt_scan_name, dnt_scan_result,
              data_leakage_scan_name, data_leakage_scan_result, cookie_scan_name, cookie_scan_result,
              final_score))
    conn.commit()
    conn.close()

def get_all_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT url, xss_scan_name, xss_scan_result,
               vuln_scan_name, vuln_scan_result,
               privacy_tracker_scan_name, privacy_tracker_scan_result,
               privacy_third_party_script_scan_name, privacy_third_party_script_scan_result,
               ssl_scan_name, ssl_scan_result,
               sql_scan_name, sql_scan_result,
               headers_scan_name, headers_scan_result,
               privacy_audit_scan_name, privacy_audit_scan_result,
               performance_scan_name, performance_scan_result,
               outdated_scan_name, outdated_scan_result,
               mixed_scan_name, mixed_scan_result,
               directory_scan_name, directory_scan_result,
               csrf_scan_name, csrf_scan_result,
               csp_scan_name, csp_scan_result,
               https_scan_name, https_scan_result,
               third_party_data_collection_scan_name, third_party_data_collection_scan_result,
               tracker_detection_scan_name, tracker_detection_scan_result,
               fingerprinting_scan_name, fingerprinting_scan_result,
               referrer_dnt_scan_name, referrer_dnt_scan_result,
               dnt_scan_name, dnt_scan_result,
               data_leakage_scan_name, data_leakage_scan_result,
               cookie_scan_name, cookie_scan_result,
               final_score, timestamp
        FROM logs
        ORDER BY timestamp DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for row in rows:
        logs.append({
            'url': row[0],
            'xss_scan_name': row[1],
            'xss_scan_result': row[2],
            'vuln_scan_name': row[3],
            'vuln_scan_result': row[4],
            'privacy_tracker_scan_name': row[5],
            'privacy_tracker_scan_result': row[6],
            'privacy_third_party_script_scan_name': row[7],
            'privacy_third_party_script_scan_result': row[8],
            'ssl_scan_name': row[9],
            'ssl_scan_result': row[10],
            'sql_scan_name': row[11],
            'sql_scan_result': row[12],
            'headers_scan_name': row[13],
            'headers_scan_result': row[14],
            'privacy_audit_scan_name': row[15],
            'privacy_audit_scan_result': row[16],
            'performance_scan_name': row[17],
            'performance_scan_result': row[18],
            'outdated_scan_name': row[19],
            'outdated_scan_result': row[20],
            'mixed_scan_name': row[21],
            'mixed_scan_result': row[22],
            'directory_scan_name': row[23],
            'directory_scan_result': row[24],
            'csrf_scan_name': row[25],
            'csrf_scan_result': row[26],
            'csp_scan_name': row[27],
            'csp_scan_result': row[28],
            'https_scan_name': row[29],
            'https_scan_result': row[30],
            'third_party_data_collection_scan_name': row[31],
            'third_party_data_collection_scan_result': row[32],
            'tracker_detection_scan_name': row[33],
            'tracker_detection_scan_result': row[34],
            'fingerprinting_scan_name': row[35],
            'fingerprinting_scan_result': row[36],
            'referrer_dnt_scan_name': row[37],
            'referrer_dnt_scan_result': row[38],
            'dnt_scan_name': row[39],
            'dnt_scan_result': row[40],
            'data_leakage_scan_name': row[41],
            'data_leakage_scan_result': row[42],
            'cookie_scan_name': row[43],
            'cookie_scan_result': row[44],
            'final_score': row[45],
            'timestamp': row[46]
        })
    return logs

def get_log_by_url(url):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT url, xss_scan_name, xss_scan_result,
               vuln_scan_name, vuln_scan_result,
               privacy_tracker_scan_name, privacy_tracker_scan_result,
               privacy_third_party_script_scan_name, privacy_third_party_script_scan_result,
               ssl_scan_name, ssl_scan_result,
               sql_scan_name, sql_scan_result,
               headers_scan_name, headers_scan_result,
               privacy_audit_scan_name, privacy_audit_scan_result,
               performance_scan_name, performance_scan_result,
               outdated_scan_name, outdated_scan_result,
               mixed_scan_name, mixed_scan_result,
               directory_scan_name, directory_scan_result,
               csrf_scan_name, csrf_scan_result,
               csp_scan_name, csp_scan_result,
               https_scan_name, https_scan_result,
               third_party_data_collection_scan_name, third_party_data_collection_scan_result,
               tracker_detection_scan_name, tracker_detection_scan_result,
               fingerprinting_scan_name, fingerprinting_scan_result,
               referrer_dnt_scan_name, referrer_dnt_scan_result,
               dnt_scan_name, dnt_scan_result,
               data_leakage_scan_name, data_leakage_scan_result,
               cookie_scan_name, cookie_scan_result,
               final_score, timestamp
        FROM logs
        WHERE url = ?
    ''', (url,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            'url': row[0],
            'xss_scan_name': row[1],
            'xss_scan_result': row[2],
            'vuln_scan_name': row[3],
            'vuln_scan_result': row[4],
            'privacy_tracker_scan_name': row[5],
            'privacy_tracker_scan_result': row[6],
            'privacy_third_party_script_scan_name': row[7],
            'privacy_third_party_script_scan_result': row[8],
            'ssl_scan_name': row[9],
            'ssl_scan_result': row[10],
            'sql_scan_name': row[11],
            'sql_scan_result': row[12],
            'headers_scan_name': row[13],
            'headers_scan_result': row[14],
            'privacy_audit_scan_name': row[15],
            'privacy_audit_scan_result': row[16],
            'performance_scan_name': row[17],
            'performance_scan_result': row[18],
            'outdated_scan_name': row[19],
            'outdated_scan_result': row[20],
            'mixed_scan_name': row[21],
            'mixed_scan_result': row[22],
            'directory_scan_name': row[23],
            'directory_scan_result': row[24],
            'csrf_scan_name': row[25],
            'csrf_scan_result': row[26],
            'csp_scan_name': row[27],
            'csp_scan_result': row[28],
            'https_scan_name': row[29],
            'https_scan_result': row[30],
            'third_party_data_collection_scan_name': row[31],
            'third_party_data_collection_scan_result': row[32],
            'tracker_detection_scan_name': row[33],
            'tracker_detection_scan_result': row[34],
            'fingerprinting_scan_name': row[35],
            'fingerprinting_scan_result': row[36],
            'referrer_dnt_scan_name': row[37],
            'referrer_dnt_scan_result': row[38],
            'dnt_scan_name': row[39],
            'dnt_scan_result': row[40],
            'data_leakage_scan_name': row[41],
            'data_leakage_scan_result': row[42],
            'cookie_scan_name': row[43],
            'cookie_scan_result': row[44],
            'final_score': row[45],
            'timestamp': row[46]
        }
    else:
        return None
