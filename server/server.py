'''
from fastapi import FastAPI
from pydantic import BaseModel
from database import init_db, insert_log, get_all_logs

# Import Security Scan functions
from Security_scans.httpscan import scan_url
from Security_scans.security_headers_checker import check_security_headers
from Security_scans.scanner_cookie_security_check import check_cookie_security
from Security_scans.cross_site_scripting_scan import check_cross_site_scripting
from Security_scans.sql_injection_scan import check_sql_injection
from Security_scans.ssl_tls_configuration_scan import check_ssl_tls_configuration
from Security_scans.crrf_scan import check_crrf
from Security_scans.broken_authentication_scan import check_broken_authentication
from Security_scans.directory_listing_check_scan import check_directory_listing
from Security_scans.open_redirect_check_scan import check_open_redirect

# Import Privacy Scan functions
from Privacy_scan.privacy_policy_scan import check_privacy_policy
from Privacy_scan.tracker_detection_scan import check_tracker_detection
from Privacy_scan.cookie_privacy_scan import check_cookie_privacy
from Privacy_scan.do_not_track_support_scan import check_do_not_track_support
from Privacy_scan.third_party_data_collection_scan import check_third_party_data_collection

# Import the final score calculator
from score_calculator import calculate_final_score

from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import asyncio

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.on_event("startup")
def startup_event():
    init_db()

@app.post("/log")
async def log_url(data: URLRequest):
    url = data.url

    # Use the event loop to run blocking scan functions concurrently.
    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, scan_url, url),                       # sec_scan1: HTTPS Scan
        loop.run_in_executor(None, check_security_headers, url),           # sec_scan2
        loop.run_in_executor(None, check_cookie_security, url),            # sec_scan3
        loop.run_in_executor(None, check_cross_site_scripting, url),         # sec_scan4
        loop.run_in_executor(None, check_sql_injection, url),              # sec_scan5
        loop.run_in_executor(None, check_ssl_tls_configuration, url),      # sec_scan6
        loop.run_in_executor(None, check_crrf, url),                       # sec_scan7
        loop.run_in_executor(None, check_broken_authentication, url),      # sec_scan8
        loop.run_in_executor(None, check_directory_listing, url),          # sec_scan9
        loop.run_in_executor(None, check_open_redirect, url),              # sec_scan10
        loop.run_in_executor(None, check_privacy_policy, url),             # priv_scan1
        loop.run_in_executor(None, check_tracker_detection, url),          # priv_scan2
        loop.run_in_executor(None, check_cookie_privacy, url),             # priv_scan3
        loop.run_in_executor(None, check_do_not_track_support, url),       # priv_scan4
        loop.run_in_executor(None, check_third_party_data_collection, url)   # priv_scan5
    ]

    results = await asyncio.gather(*tasks)

    # Unpack scan results for clarity.
    sec_scan1_result = results[0]
    sec_scan2_result = results[1]
    sec_scan3_result = results[2]
    sec_scan4_result = results[3]
    sec_scan5_result = results[4]
    sec_scan6_result = results[5]
    sec_scan7_result = results[6]
    sec_scan8_result = results[7]
    sec_scan9_result = results[8]
    sec_scan10_result = results[9]
    priv_scan1_result = results[10]
    priv_scan2_result = results[11]
    priv_scan3_result = results[12]
    priv_scan4_result = results[13]
    priv_scan5_result = results[14]

    # Calculate the final score.
    final_score = calculate_final_score(
        sec_scan1_result, sec_scan2_result, sec_scan3_result, sec_scan4_result,
        sec_scan5_result, sec_scan6_result, sec_scan7_result, sec_scan8_result,
        sec_scan9_result, sec_scan10_result,
        priv_scan1_result, priv_scan2_result, priv_scan3_result, priv_scan4_result,
        priv_scan5_result
    )

    # Insert the log into the database.
    insert_log(
        url,
        "HTTPS Scan", sec_scan1_result,
        "Security Headers Checker", sec_scan2_result,
        "Cookie Security Check", sec_scan3_result,
        "Cross-Site Scripting Scan", sec_scan4_result,
        "SQL Injection Scan", sec_scan5_result,
        "SSL-TLS Configuration Scan", sec_scan6_result,
        "CRRF Scan", sec_scan7_result,
        "Broken Authentication and Session Management Check Scan", sec_scan8_result,
        "Directory Listing Check Scan", sec_scan9_result,
        "Open Redirect Check Scan", sec_scan10_result,
        "Privacy Policy Scan", priv_scan1_result,
        "Tracker Detection Scan", priv_scan2_result,
        "Cookie Privacy Scan", priv_scan3_result,
        "Do Not Track Support Scan", priv_scan4_result,
        "Third-Party Data Collection Scan", priv_scan5_result,
        final_score
    )

    # Return the combined results.
    return {
        "url": url,
        "sec_scan1_name": "HTTPS Scan",
        "sec_scan1_result": sec_scan1_result,
        "sec_scan2_name": "Security Headers Checker",
        "sec_scan2_result": sec_scan2_result,
        "sec_scan3_name": "Cookie Security Check",
        "sec_scan3_result": sec_scan3_result,
        "sec_scan4_name": "Cross-Site Scripting Scan",
        "sec_scan4_result": sec_scan4_result,
        "sec_scan5_name": "SQL Injection Scan",
        "sec_scan5_result": sec_scan5_result,
        "sec_scan6_name": "SSL-TLS Configuration Scan",
        "sec_scan6_result": sec_scan6_result,
        "sec_scan7_name": "CRRF Scan",
        "sec_scan7_result": sec_scan7_result,
        "sec_scan8_name": "Broken Authentication and Session Management Check Scan",
        "sec_scan8_result": sec_scan8_result,
        "sec_scan9_name": "Directory Listing Check Scan",
        "sec_scan9_result": sec_scan9_result,
        "sec_scan10_name": "Open Redirect Check Scan",
        "sec_scan10_result": sec_scan10_result,
        "priv_scan1_name": "Privacy Policy Scan",
        "priv_scan1_result": priv_scan1_result,
        "priv_scan2_name": "Tracker Detection Scan",
        "priv_scan2_result": priv_scan2_result,
        "priv_scan3_name": "Cookie Privacy Scan",
        "priv_scan3_result": priv_scan3_result,
        "priv_scan4_name": "Do Not Track Support Scan",
        "priv_scan4_result": priv_scan4_result,
        "priv_scan5_name": "Third-Party Data Collection Scan",
        "priv_scan5_result": priv_scan5_result,
        "final_score": final_score
    }

@app.get("/logs")
async def logs():
    return get_all_logs()

if __name__ == '__main__':
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)

'''

'''

from fastapi import FastAPI
from pydantic import BaseModel
from database import init_db, insert_log, get_all_logs, get_log_by_url
# Import Security Scan functions
from Security_scans.httpscan import scan_url
from Security_scans.security_headers_checker import check_security_headers
from Security_scans.scanner_cookie_security_check import check_cookie_security
from Security_scans.cross_site_scripting_scan import check_cross_site_scripting
from Security_scans.sql_injection_scan import check_sql_injection
from Security_scans.ssl_tls_configuration_scan import check_ssl_tls_configuration
from Security_scans.crrf_scan import check_crrf
from Security_scans.broken_authentication_scan import check_broken_authentication
from Security_scans.directory_listing_check_scan import check_directory_listing
from Security_scans.open_redirect_check_scan import check_open_redirect

# Import Privacy Scan functions
from Privacy_scan.privacy_policy_scan import check_privacy_policy
from Privacy_scan.tracker_detection_scan import check_tracker_detection
from Privacy_scan.cookie_privacy_scan import check_cookie_privacy
from Privacy_scan.do_not_track_support_scan import check_do_not_track_support
from Privacy_scan.third_party_data_collection_scan import check_third_party_data_collection

# Import the final score calculator
from score_calculator import calculate_final_score

from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import asyncio
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

def normalize_url(url: str) -> str:
    """
    Normalize the URL to its base form:
    - Keep scheme, netloc and a normalized path (without trailing slashes, defaulting to '/')
    - Drop query parameters and fragments.
    """
    parsed = urlparse(url)
    # Remove trailing slashes from path; if empty, use '/'
    normalized_path = parsed.path.rstrip('/')
    if normalized_path == '':
        normalized_path = '/'
    return urlunparse((parsed.scheme, parsed.netloc, normalized_path, '', '', ''))

@app.on_event("startup")
def startup_event():
    init_db()

@app.post("/log")
async def log_url(data: URLRequest):
    original_url = data.url
    normalized_url = normalize_url(original_url)

    # Check if we already have a recent scan for this URL.
    existing_entry = get_log_by_url(normalized_url)
    if existing_entry:
        timestamp_str = existing_entry['timestamp']
        # Try parsing without microseconds first; if that fails, try with them.
        try:
            entry_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            entry_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        # If the entry is less than one week old, return it immediately.
        if datetime.now() - entry_time < timedelta(weeks=1):
            return existing_entry

    # Otherwise, run the scan tasks concurrently.
    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, scan_url, normalized_url),                       # sec_scan1: HTTPS Scan
        loop.run_in_executor(None, check_security_headers, normalized_url),           # sec_scan2
        loop.run_in_executor(None, check_cookie_security, normalized_url),            # sec_scan3
        loop.run_in_executor(None, check_cross_site_scripting, normalized_url),         # sec_scan4
        loop.run_in_executor(None, check_sql_injection, normalized_url),              # sec_scan5
        loop.run_in_executor(None, check_ssl_tls_configuration, normalized_url),      # sec_scan6
        loop.run_in_executor(None, check_crrf, normalized_url),                       # sec_scan7
        loop.run_in_executor(None, check_broken_authentication, normalized_url),      # sec_scan8
        loop.run_in_executor(None, check_directory_listing, normalized_url),          # sec_scan9
        loop.run_in_executor(None, check_open_redirect, normalized_url),              # sec_scan10
        loop.run_in_executor(None, check_privacy_policy, normalized_url),             # priv_scan1
        loop.run_in_executor(None, check_tracker_detection, normalized_url),          # priv_scan2
        loop.run_in_executor(None, check_cookie_privacy, normalized_url),             # priv_scan3
        loop.run_in_executor(None, check_do_not_track_support, normalized_url),       # priv_scan4
        loop.run_in_executor(None, check_third_party_data_collection, normalized_url)   # priv_scan5
    ]

    results = await asyncio.gather(*tasks)

    # Unpack scan results for clarity.
    sec_scan1_result = results[0]
    sec_scan2_result = results[1]
    sec_scan3_result = results[2]
    sec_scan4_result = results[3]
    sec_scan5_result = results[4]
    sec_scan6_result = results[5]
    sec_scan7_result = results[6]
    sec_scan8_result = results[7]
    sec_scan9_result = results[8]
    sec_scan10_result = results[9]
    priv_scan1_result = results[10]
    priv_scan2_result = results[11]
    priv_scan3_result = results[12]
    priv_scan4_result = results[13]
    priv_scan5_result = results[14]

    # Calculate the final score.
    final_score = calculate_final_score(
        sec_scan1_result, sec_scan2_result, sec_scan3_result, sec_scan4_result,
        sec_scan5_result, sec_scan6_result, sec_scan7_result, sec_scan8_result,
        sec_scan9_result, sec_scan10_result,
        priv_scan1_result, priv_scan2_result, priv_scan3_result, priv_scan4_result,
        priv_scan5_result
    )

    # Insert (or update) the log into the database using the normalized URL.
    insert_log(
        normalized_url,
        "HTTPS Scan", sec_scan1_result,
        "Security Headers Checker", sec_scan2_result,
        "Cookie Security Check", sec_scan3_result,
        "Cross-Site Scripting Scan", sec_scan4_result,
        "SQL Injection Scan", sec_scan5_result,
        "SSL-TLS Configuration Scan", sec_scan6_result,
        "CRRF Scan", sec_scan7_result,
        "Broken Authentication and Session Management Check Scan", sec_scan8_result,
        "Directory Listing Check Scan", sec_scan9_result,
        "Open Redirect Check Scan", sec_scan10_result,
        "Privacy Policy Scan", priv_scan1_result,
        "Tracker Detection Scan", priv_scan2_result,
        "Cookie Privacy Scan", priv_scan3_result,
        "Do Not Track Support Scan", priv_scan4_result,
        "Third-Party Data Collection Scan", priv_scan5_result,
        final_score
    )

    # Return the combined results.
    return {
        "url": normalized_url,
        "sec_scan1_name": "HTTPS Scan",
        "sec_scan1_result": sec_scan1_result,
        "sec_scan2_name": "Security Headers Checker",
        "sec_scan2_result": sec_scan2_result,
        "sec_scan3_name": "Cookie Security Check",
        "sec_scan3_result": sec_scan3_result,
        "sec_scan4_name": "Cross-Site Scripting Scan",
        "sec_scan4_result": sec_scan4_result,
        "sec_scan5_name": "SQL Injection Scan",
        "sec_scan5_result": sec_scan5_result,
        "sec_scan6_name": "SSL-TLS Configuration Scan",
        "sec_scan6_result": sec_scan6_result,
        "sec_scan7_name": "CRRF Scan",
        "sec_scan7_result": sec_scan7_result,
        "sec_scan8_name": "Broken Authentication and Session Management Check Scan",
        "sec_scan8_result": sec_scan8_result,
        "sec_scan9_name": "Directory Listing Check Scan",
        "sec_scan9_result": sec_scan9_result,
        "sec_scan10_name": "Open Redirect Check Scan",
        "sec_scan10_result": sec_scan10_result,
        "priv_scan1_name": "Privacy Policy Scan",
        "priv_scan1_result": priv_scan1_result,
        "priv_scan2_name": "Tracker Detection Scan",
        "priv_scan2_result": priv_scan2_result,
        "priv_scan3_name": "Cookie Privacy Scan",
        "priv_scan3_result": priv_scan3_result,
        "priv_scan4_name": "Do Not Track Support Scan",
        "priv_scan4_result": priv_scan4_result,
        "priv_scan5_name": "Third-Party Data Collection Scan",
        "priv_scan5_result": priv_scan5_result,
        "final_score": final_score
    }

@app.get("/logs")
async def logs():
    return get_all_logs()

if __name__ == '__main__':
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)

'''



'''
#server/server.py
from fastapi import FastAPI, Request
from pydantic import BaseModel
from database import init_db, insert_log, get_all_logs, get_log_by_url

# Import Security Scan functions
from Security_scans.httpscan import scan_url
from Security_scans.security_headers_checker import check_security_headers
from Security_scans.scanner_cookie_security_check import check_cookie_security
from Security_scans.cross_site_scripting_scan import check_cross_site_scripting
from Security_scans.sql_injection_scan import check_sql_injection
from Security_scans.ssl_tls_configuration_scan import check_ssl_tls_configuration
from Security_scans.crrf_scan import check_crrf
from Security_scans.broken_authentication_scan import check_broken_authentication
from Security_scans.directory_listing_check_scan import check_directory_listing
from Security_scans.open_redirect_check_scan import check_open_redirect

# Import Privacy Scan functions
from Privacy_scan.privacy_policy_scan import check_privacy_policy
from Privacy_scan.tracker_detection_scan import check_tracker_detection
from Privacy_scan.cookie_privacy_scan import check_cookie_privacy
from Privacy_scan.do_not_track_support_scan import check_do_not_track_support
from Privacy_scan.third_party_data_collection_scan import check_third_party_data_collection

# Import the final score calculator
from score_calculator import calculate_final_score

from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import asyncio
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse
import logging

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

def normalize_url(url: str) -> str:
    """
    Normalize the URL to its base form:
    - Keep scheme, netloc and a normalized path (without trailing slashes, defaulting to '/')
    - Drop query parameters and fragments.
    """
    parsed = urlparse(url)
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

    # Check if we already have a recent scan for this URL.
    existing_entry = get_log_by_url(normalized_url)
    if existing_entry:
        timestamp_str = existing_entry['timestamp']
        try:
            entry_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            entry_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        if datetime.now() - entry_time < timedelta(weeks=1):
            # Log the access with the normalized URL.
            log_access(request, normalized_url)
            return existing_entry

    # Otherwise, run the scan tasks concurrently.
    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, scan_url, normalized_url),                    
        loop.run_in_executor(None, check_security_headers, normalized_url),        
        loop.run_in_executor(None, check_cookie_security, normalized_url),         
        loop.run_in_executor(None, check_cross_site_scripting, normalized_url),      
        loop.run_in_executor(None, check_sql_injection, normalized_url),           
        loop.run_in_executor(None, check_ssl_tls_configuration, normalized_url),   
        loop.run_in_executor(None, check_crrf, normalized_url),                    
        loop.run_in_executor(None, check_broken_authentication, normalized_url),   
        loop.run_in_executor(None, check_directory_listing, normalized_url),       
        loop.run_in_executor(None, check_open_redirect, normalized_url),           
        loop.run_in_executor(None, check_privacy_policy, normalized_url),          
        loop.run_in_executor(None, check_tracker_detection, normalized_url),       
        loop.run_in_executor(None, check_cookie_privacy, normalized_url),          
        loop.run_in_executor(None, check_do_not_track_support, normalized_url),    
        loop.run_in_executor(None, check_third_party_data_collection, normalized_url)
    ]
    results = await asyncio.gather(*tasks)

    # Unpack scan results.
    sec_scan1_result = results[0]
    sec_scan2_result = results[1]
    sec_scan3_result = results[2]
    sec_scan4_result = results[3]
    sec_scan5_result = results[4]
    sec_scan6_result = results[5]
    sec_scan7_result = results[6]
    sec_scan8_result = results[7]
    sec_scan9_result = results[8]
    sec_scan10_result = results[9]
    priv_scan1_result = results[10]
    priv_scan2_result = results[11]
    priv_scan3_result = results[12]
    priv_scan4_result = results[13]
    priv_scan5_result = results[14]

    # Calculate the final score.
    final_score = calculate_final_score(
        sec_scan1_result, sec_scan2_result, sec_scan3_result, sec_scan4_result,
        sec_scan5_result, sec_scan6_result, sec_scan7_result, sec_scan8_result,
        sec_scan9_result, sec_scan10_result,
        priv_scan1_result, priv_scan2_result, priv_scan3_result, priv_scan4_result,
        priv_scan5_result
    )

    # Insert (or update) the log into the database.
    insert_log(
        normalized_url,
        "HTTPS Scan", sec_scan1_result,
        "Security Headers Checker", sec_scan2_result,
        "Cookie Security Check", sec_scan3_result,
        "Cross-Site Scripting Scan", sec_scan4_result,
        "SQL Injection Scan", sec_scan5_result,
        "SSL-TLS Configuration Scan", sec_scan6_result,
        "CRRF Scan", sec_scan7_result,
        "Broken Authentication and Session Management Check Scan", sec_scan8_result,
        "Directory Listing Check Scan", sec_scan9_result,
        "Open Redirect Check Scan", sec_scan10_result,
        "Privacy Policy Scan", priv_scan1_result,
        "Tracker Detection Scan", priv_scan2_result,
        "Cookie Privacy Scan", priv_scan3_result,
        "Do Not Track Support Scan", priv_scan4_result,
        "Third-Party Data Collection Scan", priv_scan5_result,
        final_score
    )

    # Log the access with the normalized URL.
    log_access(request, normalized_url)

    return {
        "url": normalized_url,
        "sec_scan1_name": "HTTPS Scan",
        "sec_scan1_result": sec_scan1_result,
        "sec_scan2_name": "Security Headers Checker",
        "sec_scan2_result": sec_scan2_result,
        "sec_scan3_name": "Cookie Security Check",
        "sec_scan3_result": sec_scan3_result,
        "sec_scan4_name": "Cross-Site Scripting Scan",
        "sec_scan4_result": sec_scan4_result,
        "sec_scan5_name": "SQL Injection Scan",
        "sec_scan5_result": sec_scan5_result,
        "sec_scan6_name": "SSL-TLS Configuration Scan",
        "sec_scan6_result": sec_scan6_result,
        "sec_scan7_name": "CRRF Scan",
        "sec_scan7_result": sec_scan7_result,
        "sec_scan8_name": "Broken Authentication and Session Management Check Scan",
        "sec_scan8_result": sec_scan8_result,
        "sec_scan9_name": "Directory Listing Check Scan",
        "sec_scan9_result": sec_scan9_result,
        "sec_scan10_name": "Open Redirect Check Scan",
        "sec_scan10_result": sec_scan10_result,
        "priv_scan1_name": "Privacy Policy Scan",
        "priv_scan1_result": priv_scan1_result,
        "priv_scan2_name": "Tracker Detection Scan",
        "priv_scan2_result": priv_scan2_result,
        "priv_scan3_name": "Cookie Privacy Scan",
        "priv_scan3_result": priv_scan3_result,
        "priv_scan4_name": "Do Not Track Support Scan",
        "priv_scan4_result": priv_scan4_result,
        "priv_scan5_name": "Third-Party Data Collection Scan",
        "priv_scan5_result": priv_scan5_result,
        "final_score": final_score
    }

def log_access(request: Request, normalized_url: str):
    """
    Log a custom access log message that appends the normalized URL.
    This function uses a dedicated logger ("custom_access") with its own handler.
    """
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

@app.get("/logs")
async def logs():
    return get_all_logs()

if __name__ == '__main__':
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)

'''

from fastapi import FastAPI, Request
from pydantic import BaseModel
from database import init_db, insert_log, get_all_logs, get_log_by_url

# Import Security Scan functions
from Security_scans.httpscan import scan_url
from Security_scans.security_headers_checker import check_security_headers
from Security_scans.scanner_cookie_security_check import check_cookie_security
from Security_scans.cross_site_scripting_scan import check_cross_site_scripting
from Security_scans.sql_injection_scan import check_sql_injection
from Security_scans.ssl_tls_configuration_scan import check_ssl_tls_configuration
from Security_scans.crrf_scan import check_crrf
from Security_scans.broken_authentication_scan import check_broken_authentication
from Security_scans.directory_listing_check_scan import check_directory_listing
from Security_scans.open_redirect_check_scan import check_open_redirect

# Import Privacy Scan functions
from Privacy_scan.privacy_policy_scan import check_privacy_policy
from Privacy_scan.tracker_detection_scan import check_tracker_detection
from Privacy_scan.cookie_privacy_scan import check_cookie_privacy
from Privacy_scan.do_not_track_support_scan import check_do_not_track_support
from Privacy_scan.third_party_data_collection_scan import check_third_party_data_collection

# Import the final score calculator
from score_calculator import calculate_final_score

from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import asyncio
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse
import logging

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

def normalize_url(url: str) -> str:
    """
    Normalize the URL to its base form:
    - Keep scheme, netloc and a normalized path (without trailing slashes, defaulting to '/')
    - Drop query parameters and fragments.
    """
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip('/')
    if normalized_path == '':
        normalized_path = '/'
    return urlunparse((parsed.scheme, parsed.netloc, normalized_path, '', '', ''))

@app.on_event("startup")
def startup_event():
    init_db()

@app.post("/log")
async def log_url(data: URLRequest, request: Request):
    # Use the full URL (with query parameters) for scanning
    original_url = data.url
    # Use the normalized URL for logging and DB deduplication
    normalized_url = normalize_url(original_url)

    # Check if we already have a recent scan for this normalized URL.
    existing_entry = get_log_by_url(normalized_url)
    if existing_entry:
        timestamp_str = existing_entry['timestamp']
        try:
            entry_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            entry_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
        if datetime.now() - entry_time < timedelta(weeks=1):
            # Log the access with the normalized URL.
            log_access(request, normalized_url)
            return existing_entry

    # Otherwise, run the scan tasks concurrently using the original URL.
    loop = asyncio.get_event_loop()
    tasks = [
        loop.run_in_executor(None, scan_url, original_url),                    
        loop.run_in_executor(None, check_security_headers, original_url),        
        loop.run_in_executor(None, check_cookie_security, original_url),         
        loop.run_in_executor(None, check_cross_site_scripting, original_url),      
        loop.run_in_executor(None, check_sql_injection, original_url),           
        loop.run_in_executor(None, check_ssl_tls_configuration, original_url),   
        loop.run_in_executor(None, check_crrf, original_url),                    
        loop.run_in_executor(None, check_broken_authentication, original_url),   
        loop.run_in_executor(None, check_directory_listing, original_url),       
        loop.run_in_executor(None, check_open_redirect, original_url),           
        loop.run_in_executor(None, check_privacy_policy, original_url),          
        loop.run_in_executor(None, check_tracker_detection, original_url),       
        loop.run_in_executor(None, check_cookie_privacy, original_url),          
        loop.run_in_executor(None, check_do_not_track_support, original_url),    
        loop.run_in_executor(None, check_third_party_data_collection, original_url)
    ]
    results = await asyncio.gather(*tasks)

    # Unpack scan results.
    sec_scan1_result = results[0]
    sec_scan2_result = results[1]
    sec_scan3_result = results[2]
    sec_scan4_result = results[3]
    sec_scan5_result = results[4]
    sec_scan6_result = results[5]
    sec_scan7_result = results[6]
    sec_scan8_result = results[7]
    sec_scan9_result = results[8]
    sec_scan10_result = results[9]
    priv_scan1_result = results[10]
    priv_scan2_result = results[11]
    priv_scan3_result = results[12]
    priv_scan4_result = results[13]
    priv_scan5_result = results[14]

    # Calculate the final score.
    final_score = calculate_final_score(
        sec_scan1_result, sec_scan2_result, sec_scan3_result, sec_scan4_result,
        sec_scan5_result, sec_scan6_result, sec_scan7_result, sec_scan8_result,
        sec_scan9_result, sec_scan10_result,
        priv_scan1_result, priv_scan2_result, priv_scan3_result, priv_scan4_result,
        priv_scan5_result
    )

    # Insert (or update) the log into the database using the normalized URL.
    insert_log(
        normalized_url,
        "HTTPS Scan", sec_scan1_result,
        "Security Headers Checker", sec_scan2_result,
        "Cookie Security Check", sec_scan3_result,
        "Cross-Site Scripting Scan", sec_scan4_result,
        "SQL Injection Scan", sec_scan5_result,
        "SSL-TLS Configuration Scan", sec_scan6_result,
        "CRRF Scan", sec_scan7_result,
        "Broken Authentication and Session Management Check Scan", sec_scan8_result,
        "Directory Listing Check Scan", sec_scan9_result,
        "Open Redirect Check Scan", sec_scan10_result,
        "Privacy Policy Scan", priv_scan1_result,
        "Tracker Detection Scan", priv_scan2_result,
        "Cookie Privacy Scan", priv_scan3_result,
        "Do Not Track Support Scan", priv_scan4_result,
        "Third-Party Data Collection Scan", priv_scan5_result,
        final_score
    )

    # Log the access with the normalized URL.
    log_access(request, normalized_url)

    return {
        "url": normalized_url,
        "sec_scan1_name": "HTTPS Scan",
        "sec_scan1_result": sec_scan1_result,
        "sec_scan2_name": "Security Headers Checker",
        "sec_scan2_result": sec_scan2_result,
        "sec_scan3_name": "Cookie Security Check",
        "sec_scan3_result": sec_scan3_result,
        "sec_scan4_name": "Cross-Site Scripting Scan",
        "sec_scan4_result": sec_scan4_result,
        "sec_scan5_name": "SQL Injection Scan",
        "sec_scan5_result": sec_scan5_result,
        "sec_scan6_name": "SSL-TLS Configuration Scan",
        "sec_scan6_result": sec_scan6_result,
        "sec_scan7_name": "CRRF Scan",
        "sec_scan7_result": sec_scan7_result,
        "sec_scan8_name": "Broken Authentication and Session Management Check Scan",
        "sec_scan8_result": sec_scan8_result,
        "sec_scan9_name": "Directory Listing Check Scan",
        "sec_scan9_result": sec_scan9_result,
        "sec_scan10_name": "Open Redirect Check Scan",
        "sec_scan10_result": sec_scan10_result,
        "priv_scan1_name": "Privacy Policy Scan",
        "priv_scan1_result": priv_scan1_result,
        "priv_scan2_name": "Tracker Detection Scan",
        "priv_scan2_result": priv_scan2_result,
        "priv_scan3_name": "Cookie Privacy Scan",
        "priv_scan3_result": priv_scan3_result,
        "priv_scan4_name": "Do Not Track Support Scan",
        "priv_scan4_result": priv_scan4_result,
        "priv_scan5_name": "Third-Party Data Collection Scan",
        "priv_scan5_result": priv_scan5_result,
        "final_score": final_score
    }

def log_access(request: Request, normalized_url: str):
    """
    Log a custom access log message that appends the normalized URL.
    This function uses a dedicated logger ("custom_access") with its own handler.
    """
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

@app.get("/logs")
async def logs():
    return get_all_logs()

if __name__ == '__main__':
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
