# server/server.py
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

    # --- Security Scans (10) ---
    sec_scan1_name = "HTTPS Scan"
    sec_scan1_result = scan_url(url)

    sec_scan2_name = "Security Headers Checker"
    sec_scan2_result = check_security_headers(url)

    sec_scan3_name = "Cookie Security Check"
    sec_scan3_result = check_cookie_security(url)

    sec_scan4_name = "Cross-Site Scripting Scan"
    sec_scan4_result = check_cross_site_scripting(url)

    sec_scan5_name = "SQL Injection Scan"
    sec_scan5_result = check_sql_injection(url)

    sec_scan6_name = "SSL-TLS Configuration Scan"
    sec_scan6_result = check_ssl_tls_configuration(url)

    sec_scan7_name = "CRRF Scan"
    sec_scan7_result = check_crrf(url)

    sec_scan8_name = "Broken Authentication and Session Management Check Scan"
    sec_scan8_result = check_broken_authentication(url)

    sec_scan9_name = "Directory Listing Check Scan"
    sec_scan9_result = check_directory_listing(url)

    sec_scan10_name = "Open Redirect Check Scan"
    sec_scan10_result = check_open_redirect(url)

    # --- Privacy Scans (5) ---
    priv_scan1_name = "Privacy Policy Scan"
    priv_scan1_result = check_privacy_policy(url)

    priv_scan2_name = "Tracker Detection Scan"
    priv_scan2_result = check_tracker_detection(url)

    priv_scan3_name = "Cookie Privacy Scan"
    priv_scan3_result = check_cookie_privacy(url)

    priv_scan4_name = "Do Not Track Support Scan"
    priv_scan4_result = check_do_not_track_support(url)

    priv_scan5_name = "Third-Party Data Collection Scan"
    priv_scan5_result = check_third_party_data_collection(url)

    # --- Calculate the final score using all scan results ---
    final_score = calculate_final_score(
        sec_scan1_result, sec_scan2_result, sec_scan3_result, sec_scan4_result,
        sec_scan5_result, sec_scan6_result, sec_scan7_result, sec_scan8_result,
        sec_scan9_result, sec_scan10_result,
        priv_scan1_result, priv_scan2_result, priv_scan3_result, priv_scan4_result,
        priv_scan5_result
    )

    # Insert into the database (note: we now include final_score as the last value before the timestamp)
    insert_log(url,
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
               final_score)
    
    # Return all scan results along with the final score
    return {
        "url": url,
        "sec_scan1_name": sec_scan1_name,
        "sec_scan1_result": sec_scan1_result,
        "sec_scan2_name": sec_scan2_name,
        "sec_scan2_result": sec_scan2_result,
        "sec_scan3_name": sec_scan3_name,
        "sec_scan3_result": sec_scan3_result,
        "sec_scan4_name": sec_scan4_name,
        "sec_scan4_result": sec_scan4_result,
        "sec_scan5_name": sec_scan5_name,
        "sec_scan5_result": sec_scan5_result,
        "sec_scan6_name": sec_scan6_name,
        "sec_scan6_result": sec_scan6_result,
        "sec_scan7_name": sec_scan7_name,
        "sec_scan7_result": sec_scan7_result,
        "sec_scan8_name": sec_scan8_name,
        "sec_scan8_result": sec_scan8_result,
        "sec_scan9_name": sec_scan9_name,
        "sec_scan9_result": sec_scan9_result,
        "sec_scan10_name": sec_scan10_name,
        "sec_scan10_result": sec_scan10_result,
        "priv_scan1_name": priv_scan1_name,
        "priv_scan1_result": priv_scan1_result,
        "priv_scan2_name": priv_scan2_name,
        "priv_scan2_result": priv_scan2_result,
        "priv_scan3_name": priv_scan3_name,
        "priv_scan3_result": priv_scan3_result,
        "priv_scan4_name": priv_scan4_name,
        "priv_scan4_result": priv_scan4_result,
        "priv_scan5_name": priv_scan5_name,
        "priv_scan5_result": priv_scan5_result,
        "final_score": final_score
    }

@app.get("/logs")
async def logs():
    return get_all_logs()

if __name__ == '__main__':
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
