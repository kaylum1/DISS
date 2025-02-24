from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from database import init_db, insert_log, get_all_logs, get_log_by_url

from fastapi import HTTPException

# Import the scan functions.
from Security_scans.Passive_XSS_Security_Scanner import analyze_xss_security
from Security_scans.Passive_Vulnerability_Cross_Reference_Scanner import analyze_vulnerabilities
from Privacy_scan.Passive_Tracker_Script_Scanner import analyze_tracker_security
from Privacy_scan.Passive_Third_Party_Script_Evaluation_Scanner import analyze_third_party_script_evaluation
from Privacy_scan.Passive_Privacy_and_Tracker_Audit_Scanner import analyze_privacy

from Security_scans.Passive_SSL_TLS_Certificate_Validation_Scanner import analyze_certificate, get_hostname
from Security_scans.Passive_SQL_Injection_Security_Scanner import analyze_sql_security
from Security_scans.Passive_Security_Headers_Scanner import analyze_security_headers
from Security_scans.Passive_Performance_and_Configuration_Analysis_Scanner import analyze_performance
from Security_scans.Passive_Outdated_Plugin_Security_Scanner import analyze_outdated_plugins
from Security_scans.Passive_Mixed_Content_Detection_Scanner import analyze_mixed_content
from Security_scans.Passive_Directory_Listing_Security_Scanner import analyze_directory_security
from Security_scans.Passive_CSRF_Security_Scanner import analyze_csrf_security

# New scans.
from Security_scans.Passive_CSP_Security_Scanner import analyze_csp_security
from Security_scans.Passive_HTTPS_Scanner import analyze_https_security
from Privacy_scan.Passive_Third_Party_Data_Collection_Scanner import analyze_third_party_data_collection
from Privacy_scan.Passive_Tracker_Detection_Scan import analyze_tracker_detection
from Privacy_scan.Passive_Fingerprinting_Detection_Scan import analyze_fingerprinting_detection
from Privacy_scan.Passive_Referrer_DNT_Analysis_Scan import analyze_referrer_dnt
from Privacy_scan.Passive_Data_Leakage_HTTP_Headers_Scan import analyze_data_leakage_headers
from Privacy_scan.Passive_Do_Not_Track_Support_Scan import analyze_dnt_support
from Privacy_scan.Passive_Cookie_Privacy_Scan import analyze_cookie_privacy  # New scan

from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import asyncio
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse
import os
import logging

# Import the updated score calculator.
from score_calculator import calculate_final_score

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")

class URLRequest(BaseModel):
    url: str

def normalize_url(url: str) -> str:
    """Normalize the URL to its base form."""
    parsed = urlparse(url)
    if parsed.scheme == 'file':
        return os.path.basename(parsed.path)
    else:
        normalized_path = parsed.path.rstrip('/')
        if normalized_path == '':
            normalized_path = '/'
        return urlunparse((parsed.scheme, parsed.netloc, normalized_path, '', '', ''))

@app.on_event("startup")
def startup_event():
    init_db()

@app.post("/log")
async def log_url(data: URLRequest, request: Request):
    original_url = data.url
    normalized_url = normalize_url(original_url)

    # Return cached result if a scan was performed recently.
    existing_entry = get_log_by_url(normalized_url)
    if existing_entry:
        timestamp_str = existing_entry['timestamp']
        try:
            entry_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            entry_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        if datetime.now() - entry_time < timedelta(weeks=1):
            log_access(request, normalized_url)
            return existing_entry

    loop = asyncio.get_event_loop()
    host = get_hostname(original_url)
    results = await asyncio.gather(
        loop.run_in_executor(None, analyze_xss_security, original_url),              # index 0
        loop.run_in_executor(None, analyze_vulnerabilities, original_url),            # index 1
        loop.run_in_executor(None, analyze_tracker_security, original_url),           # index 2
        loop.run_in_executor(None, analyze_third_party_script_evaluation, original_url),# index 3
        loop.run_in_executor(None, analyze_certificate, host),                        # index 4
        loop.run_in_executor(None, analyze_sql_security, original_url),               # index 5
        loop.run_in_executor(None, analyze_security_headers, original_url),           # index 6
        loop.run_in_executor(None, analyze_privacy, original_url),                    # index 7
        loop.run_in_executor(None, analyze_performance, original_url),                # index 8
        loop.run_in_executor(None, analyze_outdated_plugins, original_url),           # index 9
        loop.run_in_executor(None, analyze_mixed_content, original_url),              # index 10
        loop.run_in_executor(None, analyze_directory_security, original_url),         # index 11
        loop.run_in_executor(None, analyze_csrf_security, original_url),              # index 12
        loop.run_in_executor(None, analyze_csp_security, original_url),               # index 13
        loop.run_in_executor(None, analyze_https_security, original_url),             # index 14
        loop.run_in_executor(None, analyze_third_party_data_collection, original_url),# index 15
        loop.run_in_executor(None, analyze_tracker_detection, original_url),          # index 16
        loop.run_in_executor(None, analyze_fingerprinting_detection, original_url),   # index 17
        loop.run_in_executor(None, analyze_referrer_dnt, original_url),               # index 18
        loop.run_in_executor(None, analyze_data_leakage_headers, original_url),         # index 19
        loop.run_in_executor(None, analyze_dnt_support, original_url),                # index 20
        loop.run_in_executor(None, analyze_cookie_privacy, original_url)              # index 21
    )

    # Unpack the 22 results.
    xss_score, xss_details = results[0]
    vuln_score, vuln_details = results[1]
    privacy_tracker_score, privacy_tracker_details = results[2]
    privacy_third_party_script_score, privacy_third_party_script_details = results[3]
    ssl_score, ssl_details = results[4]
    sql_score, sql_details = results[5]
    headers_score, headers_details = results[6]
    privacy_audit_score, privacy_audit_details = results[7]
    performance_score, performance_details = results[8]
    outdated_score, outdated_details = results[9]
    mixed_score, mixed_details = results[10]
    directory_score, directory_details = results[11]
    csrf_score, csrf_details = results[12]
    csp_score, csp_details = results[13]
    https_score, https_details = results[14]
    third_party_data_collection_score, third_party_data_collection_details = results[15]
    tracker_detection_score, tracker_detection_details = results[16]
    fingerprinting_score, fingerprinting_details = results[17]
    referrer_dnt_score, referrer_dnt_details = results[18]
    data_leakage_score, data_leakage_details = results[19]
    dnt_score, dnt_details = results[20]
    cookie_score, cookie_details = results[21]

    # Join details.
    def join_details(detail):
        return detail if isinstance(detail, str) else "; ".join(detail)
    xss_details = join_details(xss_details)
    vuln_details = join_details(vuln_details)
    privacy_tracker_details = join_details(privacy_tracker_details)
    privacy_third_party_script_details = join_details(privacy_third_party_script_details)
    ssl_details = join_details(ssl_details)
    sql_details = join_details(sql_details)
    headers_details = join_details(headers_details)
    privacy_audit_details = join_details(privacy_audit_details)
    performance_details = join_details(performance_details)
    outdated_details = join_details(outdated_details)
    mixed_details = join_details(mixed_details)
    directory_details = join_details(directory_details)
    csrf_details = join_details(csrf_details)
    csp_details = join_details(csp_details)
    https_details = join_details(https_details)
    third_party_data_collection_details = join_details(third_party_data_collection_details)
    tracker_detection_details = join_details(tracker_detection_details)
    fingerprinting_details = join_details(fingerprinting_details)
    referrer_dnt_details = join_details(referrer_dnt_details)
    data_leakage_details = join_details(data_leakage_details)
    dnt_details = join_details(dnt_details)
    cookie_details = join_details(cookie_details)

    # Format result strings (now including "/10" to meet the expected format).
    xss_scan_result = f"Score: {xss_score}/10 - {xss_details}"
    vuln_scan_result = f"Score: {vuln_score}/10 - {vuln_details}"
    privacy_tracker_scan_result = f"Score: {privacy_tracker_score}/10 - {privacy_tracker_details}"
    privacy_third_party_script_scan_result = f"Score: {privacy_third_party_script_score}/10 - {privacy_third_party_script_details}"
    ssl_scan_result = f"Score: {ssl_score}/10 - {ssl_details}"
    sql_scan_result = f"Score: {sql_score}/10 - {sql_details}"
    headers_scan_result = f"Score: {headers_score}/10 - {headers_details}"
    privacy_audit_scan_result = f"Score: {privacy_audit_score}/10 - {privacy_audit_details}"
    performance_scan_result = f"Score: {performance_score}/10 - {performance_details}"
    outdated_scan_result = f"Score: {outdated_score}/10 - {outdated_details}"
    mixed_scan_result = f"Score: {mixed_score}/10 - {mixed_details}"
    directory_scan_result = f"Score: {directory_score}/10 - {directory_details}"
    csrf_scan_result = f"Score: {csrf_score}/10 - {csrf_details}"
    csp_scan_result = f"Score: {csp_score}/10 - {csp_details}"
    https_scan_result = f"Score: {https_score}/10 - {https_details}"
    third_party_data_collection_scan_result = f"Score: {third_party_data_collection_score}/10 - {third_party_data_collection_details}"
    tracker_detection_scan_result = f"Score: {tracker_detection_score}/10 - {tracker_detection_details}"
    fingerprinting_scan_result = f"Score: {fingerprinting_score}/10 - {fingerprinting_details}"
    referrer_dnt_scan_result = f"Score: {referrer_dnt_score}/10 - {referrer_dnt_details}"
    data_leakage_scan_result = f"Score: {data_leakage_score}/10 - {data_leakage_details}"
    dnt_scan_result = f"Score: {dnt_score}/10 - {dnt_details}"
    cookie_scan_result = f"Score: {cookie_score}/10 - {cookie_details}"

    # Compute the final combined score using the updated calculator.
    # Here we pass an example weights list (all ones, meaning equal weighting).
    weights = [3, 3, 2, 2, 2, 3, 3, 2, 1, 1, 2, 1, 30, 2, 0.5, 2, 2, 2, 1, 2, 1, 2] # Adjust individual weights as needed.
    final_score = calculate_final_score(
        xss_scan_result, vuln_scan_result, privacy_tracker_scan_result, privacy_third_party_script_scan_result,
        ssl_scan_result, sql_scan_result, headers_scan_result, privacy_audit_scan_result,
        performance_scan_result, outdated_scan_result, mixed_scan_result, directory_scan_result,
        csrf_scan_result, csp_scan_result, https_scan_result, third_party_data_collection_scan_result,
        tracker_detection_scan_result, fingerprinting_scan_result, referrer_dnt_scan_result,
        data_leakage_scan_result, dnt_scan_result, cookie_scan_result,
        weights=weights
    )
    #

    insert_log(
        normalized_url,
        "Passive XSS Security Scan", xss_scan_result,
        "Passive Vulnerability Cross-Reference Scan", vuln_scan_result,
        "Passive Privacy Tracker Script Scan", privacy_tracker_scan_result,
        "Passive Privacy Third-Party Script Evaluation Scan", privacy_third_party_script_scan_result,
        "Passive SSL/TLS Certificate Validation Scan", ssl_scan_result,
        "Passive SQL Injection Security Scan", sql_scan_result,
        "Passive Security Headers Scan", headers_scan_result,
        "Passive Privacy & Tracker Audit Scan", privacy_audit_scan_result,
        "Passive Performance & Configuration Analysis Scan", performance_scan_result,
        "Passive Outdated Plugin Security Scan", outdated_scan_result,
        "Passive Mixed Content Detection Scan", mixed_scan_result,
        "Passive Directory Listing Security Scan", directory_scan_result,
        "Passive CSRF Security Scan", csrf_scan_result,
        "Passive CSP Security Scan", csp_scan_result,
        "Passive HTTPS Security Scan", https_scan_result,
        "Passive Third-Party Data Collection Scan", third_party_data_collection_scan_result,
        "Passive Tracker Detection Scan", tracker_detection_scan_result,
        "Passive Fingerprinting Detection Scan", fingerprinting_scan_result,
        "Passive Referrer & DNT Analysis Scan", referrer_dnt_scan_result,
        "Passive Data Leakage HTTP Headers Scan", data_leakage_scan_result,
        "Passive Do Not Track Support Scan", dnt_scan_result,
        "Passive Cookie Privacy Scan", cookie_scan_result,
        final_score
    )

    log_access(request, normalized_url)

    return {
        "url": normalized_url,
        "xss_scan_name": "Passive XSS Security Scan",
        "xss_scan_result": xss_scan_result,
        "vuln_scan_name": "Passive Vulnerability Cross-Reference Scan",
        "vuln_scan_result": vuln_scan_result,
        "privacy_tracker_scan_name": "Passive Privacy Tracker Script Scan",
        "privacy_tracker_scan_result": privacy_tracker_scan_result,
        "privacy_third_party_script_scan_name": "Passive Privacy Third-Party Script Evaluation Scan",
        "privacy_third_party_script_scan_result": privacy_third_party_script_scan_result,
        "ssl_scan_name": "Passive SSL/TLS Certificate Validation Scan",
        "ssl_scan_result": ssl_scan_result,
        "sql_scan_name": "Passive SQL Injection Security Scan",
        "sql_scan_result": sql_scan_result,
        "headers_scan_name": "Passive Security Headers Scan",
        "headers_scan_result": headers_scan_result,
        "privacy_audit_scan_name": "Passive Privacy & Tracker Audit Scan",
        "privacy_audit_scan_result": privacy_audit_scan_result,
        "performance_scan_name": "Passive Performance & Configuration Analysis Scan",
        "performance_scan_result": performance_scan_result,
        "outdated_scan_name": "Passive Outdated Plugin Security Scan",
        "outdated_scan_result": outdated_scan_result,
        "mixed_scan_name": "Passive Mixed Content Detection Scan",
        "mixed_scan_result": mixed_scan_result,
        "directory_scan_name": "Passive Directory Listing Security Scan",
        "directory_scan_result": directory_scan_result,
        "csrf_scan_name": "Passive CSRF Security Scan",
        "csrf_scan_result": csrf_scan_result,
        "csp_scan_name": "Passive CSP Security Scan",
        "csp_scan_result": csp_scan_result,
        "https_scan_name": "Passive HTTPS Security Scan",
        "https_scan_result": https_scan_result,
        "third_party_data_collection_scan_name": "Passive Third-Party Data Collection Scan",
        "third_party_data_collection_scan_result": third_party_data_collection_scan_result,
        "tracker_detection_scan_name": "Passive Tracker Detection Scan",
        "tracker_detection_scan_result": tracker_detection_scan_result,
        "fingerprinting_scan_name": "Passive Fingerprinting Detection Scan",
        "fingerprinting_scan_result": fingerprinting_scan_result,
        "referrer_dnt_scan_name": "Passive Referrer & DNT Analysis Scan",
        "referrer_dnt_scan_result": referrer_dnt_scan_result,
        "dnt_scan_name": "Passive Do Not Track Support Scan",
        "dnt_scan_result": dnt_scan_result,
        "data_leakage_scan_name": "Passive Data Leakage HTTP Headers Scan",
        "data_leakage_scan_result": data_leakage_scan_result,
        "cookie_scan_name": "Passive Cookie Privacy Scan",
        "cookie_scan_result": cookie_scan_result,
        "final_score": final_score
    }

def log_access(request: Request, normalized_url: str):
    custom_logger = logging.getLogger("custom_access")
    if not custom_logger.hasHandlers():
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        handler.setFormatter(formatter)
        custom_logger.addHandler(handler)
        custom_logger.setLevel(logging.INFO)
    client = ""
    if request.client:
        client = f"{request.client.host}:{request.client.port}" if request.client.port else request.client.host
    msg = f'{client} - "{request.method} {request.url}" 200 OK - {normalized_url}'
    custom_logger.info(msg)

@app.get("/logs", response_class=HTMLResponse)
async def view_logs(request: Request):
    logs_data = get_all_logs()
    return templates.TemplateResponse("logs.html", {"request": request, "logs": logs_data})

@app.get("/Passive_CSP_Security_Scanner_Fail", response_class=HTMLResponse)
async def show_fail_page(request: Request):
    return templates.TemplateResponse("multiple_fails.html", {"request": request})

@app.get("/XSS_fail", response_class=HTMLResponse)
async def show_xss_fail(request: Request):
    return templates.TemplateResponse(
        "XSS_fail.html",
        {"request": request},
        status_code=404
    )

@app.get("/backup/", response_class=HTMLResponse)
async def backup_directory_listing(request: Request):
    return templates.TemplateResponse("Directory_Listing_Fail.html", {"request": request})

if __name__ == '__main__':
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
