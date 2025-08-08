import os
import sys
import logging
import pprint
import re
from datetime import datetime

import yaml
import pandas as pd
import requests
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from dateutil import parser as dateparser
from difflib import get_close_matches
import traceback

# Immediate debug visibility
print("DEBUG: script invoked", sys.executable, "cwd:", os.getcwd())
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")

# Load config
CONFIG_PATH = "config.yaml"
if not os.path.exists(CONFIG_PATH):
    logging.error("config.yaml not found.")
    sys.exit(1)

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)

# Zoho config
zoho_cfg = cfg.get("zoho", {})
ZOHO_CLIENT_ID = zoho_cfg.get("client_id")
ZOHO_CLIENT_SECRET = zoho_cfg.get("client_secret")
ZOHO_REFRESH_TOKEN = zoho_cfg.get("refresh_token")
ZOHO_TOKEN_URL = zoho_cfg.get("token_url", "https://accounts.zoho.in/oauth/v2/token")
ZOHO_API_BASE = zoho_cfg.get("api_base", "https://www.zohoapis.in").rstrip("/")
LAYOUT_ID_TENANT = zoho_cfg.get("layout_id_tenant")
if not all([ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET, ZOHO_REFRESH_TOKEN, LAYOUT_ID_TENANT]):
    logging.error("Incomplete Zoho configuration.")
    sys.exit(1)
ZOHO_LEADS_ENDPOINT = f"{ZOHO_API_BASE}/crm/v2/Leads"

# Google Sheets config
google_cfg = cfg.get("google", {})
GOOGLE_SERVICE_ACCOUNT_FILE = google_cfg.get("service_account_file")
GOOGLE_SHEET_NAME = google_cfg.get("sheet_name")
SHEET_99_ACRES_NAME = google_cfg.get("sheets", {}).get("acres")
SHEET_HOUSING_NAME = google_cfg.get("sheets", {}).get("housing")
if not all([GOOGLE_SERVICE_ACCOUNT_FILE, GOOGLE_SHEET_NAME, SHEET_99_ACRES_NAME, SHEET_HOUSING_NAME]):
    logging.error("Incomplete Google Sheets configuration.")
    sys.exit(1)

# Files
files_cfg = cfg.get("files", {})
FILE_99ACRES = files_cfg.get("file_99acres")
FILE_HOUSING = files_cfg.get("file_housing")
if not all([FILE_99ACRES, FILE_HOUSING]):
    logging.error("Missing source filenames.")
    sys.exit(1)

# Picklist normalization
PICKLIST_NORMALIZE = cfg.get("picklist_normalize", {})

# Corporate tabs
CORP_99_ACRES_TAB = "99 Acres Corporate"
CORP_HOUSING_TAB = "Housing Corporate"

# Helpers
def canonicalize_id(s):
    if s is None:
        return ""
    return str(s).strip().lower()

def safe_value(v):
    if isinstance(v, (pd.Timestamp, datetime)):
        try:
            return v.strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            return str(v)
    if v is None:
        return ""
    return str(v)

def format_date_british(raw):
    if raw is None or (isinstance(raw, float) and pd.isna(raw)):
        return ""
    try:
        dt = dateparser.parse(str(raw))
        return dt.strftime("%d/%m/%Y")
    except Exception:
        return str(raw)

def convert_price_to_number(text: str):
    if not isinstance(text, str):
        return None
    t = text.strip()
    t = re.sub(r"[₹Rs\.,\s]+", "", t, flags=re.IGNORECASE)
    t = t.replace("|", "")
    tl = t.lower()
    try:
        if tl.endswith("k"):
            return int(float(tl[:-1]) * 1_000)
        if "lac" in tl or tl.endswith("l"):
            m = re.match(r"([\d\.]+)", tl)
            if m:
                return int(float(m.group(1)) * 100_000)
        digits = re.sub(r"[^\d\.]", "", tl)
        if digits:
            return int(float(digits))
    except Exception:
        pass
    return None

def normalize_phone(raw):
    if raw is None:
        return ""
    s = str(raw)
    digits = re.sub(r"\D", "", s)
    if len(digits) >= 10:
        digits = digits[-10:]
        return "91" + digits
    return digits

def normalize_picklist(field_api_name, value, allowed_values):
    if not value:
        return value
    manual = PICKLIST_NORMALIZE.get(field_api_name, {}).get(value)
    if manual:
        return manual
    for v in allowed_values:
        if v.lower() == str(value).lower():
            return v
    if value in allowed_values:
        return value
    close = get_close_matches(str(value), allowed_values, n=1, cutoff=0.8)
    if close:
        return close[0]
    logging.warning("Unmapped picklist %s='%s'; allowed: %s", field_api_name, value, allowed_values)
    return value

# Zoho OAuth & metadata
def get_zoho_access_token():
    data = {
        "refresh_token": ZOHO_REFRESH_TOKEN,
        "client_id": ZOHO_CLIENT_ID,
        "client_secret": ZOHO_CLIENT_SECRET,
        "grant_type": "refresh_token",
    }
    r = requests.post(ZOHO_TOKEN_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    if r.status_code != 200:
        logging.error("Zoho token refresh failed: %s %s", r.status_code, r.text)
        raise Exception(f"Zoho token refresh failed: {r.status_code} {r.text}")
    token = r.json().get("access_token")
    logging.debug("Obtained Zoho access token.")
    return token

def fetch_picklist_options(access_token, module="Leads"):
    headers = {"Authorization": f"Zoho-oauthtoken {access_token}"}
    url = f"{ZOHO_API_BASE}/crm/v2/settings/fields?module={module}"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        logging.warning("Could not fetch picklist metadata: %s %s", resp.status_code, resp.text)
        return {}
    fields = resp.json().get("fields", [])
    picklists = {}
    for field in fields:
        if field.get("data_type") in ("picklist", "multiselect"):
            api_name = field.get("api_name")
            picklists[api_name] = [opt.get("display_value") for opt in field.get("pick_list_values", [])]
    return picklists

def send_lead_to_zoho(access_token, lead_payload):
    headers = {
        "Authorization": f"Zoho-oauthtoken {access_token}",
        "Content-Type": "application/json;charset=UTF-8",
    }
    body = {"data": [lead_payload], "trigger": []}
    logging.info("Sending to Zoho: %s", lead_payload)
    resp = requests.post(ZOHO_LEADS_ENDPOINT, json=body, headers=headers)
    logging.info("Zoho response status: %s body: %s", resp.status_code, resp.text)
    if resp.status_code not in (200, 201, 202):
        return False, resp.text
    try:
        return True, resp.json()
    except Exception:
        return False, resp.text

# Google Sheets
def authorize_google_sheet():
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_name(GOOGLE_SERVICE_ACCOUNT_FILE, scope)
    client = gspread.authorize(creds)
    return client

def append_rows_to_sheet_tracked(client, tab_name, rows):
    ws = client.open(GOOGLE_SHEET_NAME).worksheet(tab_name)
    success = 0
    errors = []
    for idx, row in enumerate(rows):
        try:
            flat = [safe_value(c) for c in row]
            ws.append_row(flat, value_input_option="USER_ENTERED")
            success += 1
        except Exception as e:
            errors.append({"row_index": idx, "error": str(e), "row": row})
    return success, errors

def append_housing_row_filtered_tracked(client, lead, exclude_columns=None):
    if exclude_columns is None:
        exclude_columns = ["Call done by"]
    ws = client.open(GOOGLE_SHEET_NAME).worksheet(SHEET_HOUSING_NAME)
    header = ws.row_values(1)
    raw = lead["Raw"]
    row = []
    for col in header:
        if col in exclude_columns:
            continue
        row.append(safe_value(raw.get(col, "")))
    try:
        ws.append_row(row, value_input_option="USER_ENTERED")
        return True, None
    except Exception as e:
        return False, str(e)

def load_corporate_lookups(sheet_client):
    acres_lookup = {}
    housing_lookup = {}
    try:
        ws = sheet_client.open(GOOGLE_SHEET_NAME).worksheet(CORP_99_ACRES_TAB)
        for r in ws.get_all_records():
            key = canonicalize_id(r.get("Listing ID") or r.get("listing id"))
            if not key:
                continue
            acres_lookup[key] = {
                "Project": r.get("Project", "").strip(),
                "Configuration": r.get("Configuration", "").strip(),
                "Price": r.get("Price", ""),
                "Locality": r.get("Location", "").strip(),
                "City": r.get("Main Location", "").strip(),
            }
    except Exception as e:
        logging.warning("Failed loading %s: %s", CORP_99_ACRES_TAB, e)
    try:
        ws = sheet_client.open(GOOGLE_SHEET_NAME).worksheet(CORP_HOUSING_TAB)
        for r in ws.get_all_records():
            key = canonicalize_id(r.get("Listing ID") or r.get("listing id"))
            if not key:
                continue
            housing_lookup[key] = {
                "Project": r.get("Project", "").strip(),
                "Configuration": r.get("Configuration", "").strip(),
                "Price": r.get("Price", ""),
                "Locality": r.get("Location", "").strip(),
                "City": r.get("Main Location", "").strip(),
            }
    except Exception as e:
        logging.warning("Failed loading %s: %s", CORP_HOUSING_TAB, e)
    return acres_lookup, housing_lookup

# Source processing (no fallback)
def process_99acres_sheet(acres_corp_lookup):
    if not os.path.exists(FILE_99ACRES):
        logging.warning("99acres source file missing: %s", FILE_99ACRES)
        return []
    df = pd.read_csv(FILE_99ACRES)
    leads = []
    for _, row in df.iterrows():
        raw = row.to_dict()
        listing_id = canonicalize_id(raw.get("ProductCode"))
        if not listing_id:
            logging.warning("Skipping 99acres row without ProductCode: %s", raw)
            continue
        clean = acres_corp_lookup.get(listing_id)
        if not clean:
            logging.warning("No corporate match for 99acres ProductCode %s; skipping", listing_id)
            continue

        name = raw.get("Name", "")
        type_ = raw.get("Type", "")
        date_brit = format_date_british(raw.get("ReceivedDate"))
        response_type = raw.get("ResponseType", "")
        lead_score = raw.get("LeadScore", "")
        mobile = normalize_phone(raw.get("ContactNo", ""))

        project = clean.get("Project", "")
        configuration = clean.get("Configuration", "")
        locality = clean.get("Locality", "")
        city = clean.get("City", "")
        budget = convert_price_to_number(str(clean.get("Price", "")))

        lead = {
            "source": "99acres",
            "Listing_ID": listing_id,
            "Name": name,
            "Type": type_,
            "Date": date_brit,
            "ResponseType": response_type,
            "ProductCode": raw.get("ProductCode", ""),
            "LeadScore": lead_score,
            "Project": project,
            "Configuration": configuration,
            "Locality": locality,
            "Budget": budget,
            "City": city,
            "Mobile": mobile,
            "Raw": raw,
        }
        leads.append(lead)
    return leads

def process_housing_sheet(housing_corp_lookup):
    if not os.path.exists(FILE_HOUSING):
        logging.warning("housing source file missing: %s", FILE_HOUSING)
        return []
    try:
        df = pd.read_excel(FILE_HOUSING, engine="openpyxl")
    except Exception as e:
        logging.error("Failed reading housing file: %s", e)
        return []
    leads = []
    for _, row in df.iterrows():
        raw = row.to_dict()
        listing_id = canonicalize_id(raw.get("Property/Project ID"))
        if not listing_id:
            logging.warning("Skipping housing row without Property/Project ID: %s", raw)
            continue
        clean = housing_corp_lookup.get(listing_id)
        if not clean:
            logging.warning("No corporate match for housing Listing ID %s; skipping", listing_id)
            continue

        lead_name = raw.get("Lead Name", "")
        mobile = normalize_phone(raw.get("Lead Phone Number", ""))

        project = clean.get("Project", "")
        configuration = clean.get("Configuration", "")
        locality = clean.get("Locality", "")
        city = clean.get("City", "")
        price = convert_price_to_number(str(clean.get("Price", "")))
        property_id = raw.get("Property/Project ID", "")

        lead = {
            "source": "Housing.com",
            "Listing_ID": listing_id,   
            "Lead Name": lead_name,
            "Mobile": mobile,
            "Project": project,
            "Configuration": configuration,
            "Price": price,
            "Locality": locality,
            "City": city,
            "Property/Project ID": property_id,
            "Raw": raw,
        }
        leads.append(lead)
    return leads

# Zoho payloads with Call_Done_By and layout
def build_zoho_payload_from_99acres(lead, picklists):
    return {
        "Last_Name": lead.get("Name") or "Unknown",
        "Mobile": lead.get("Mobile"),
        "acres99__Project_Name": lead.get("Project", ""),
        "acres99__Query_ID": lead.get("ProductCode", ""),
        "Layout": {"id": LAYOUT_ID_TENANT},
        "Potential_Project": lead.get("Project", ""),
        "Lead_Source": normalize_picklist("Lead_Source", "99acres", picklists.get("Lead_Source", [])),
        "Call_Done_By": normalize_picklist("Call_Done_By", lead.get("Raw", {}).get("Call done by", ""), picklists.get("Call_Done_By", [])),
        "Rent_Tenant_Configuration": lead.get("Configuration", ""),
        "Rent_Tenant_Locality": lead.get("Locality", ""),
        "Rent_Tenant_Budget_Correct": lead.get("Budget", None),
        "Rent_Tenant_City": lead.get("City", ""),
    }

def build_zoho_payload_from_housing(lead, picklists):
    return {
        "Last_Name": lead.get("Lead Name") or "Unknown",
        "Mobile": lead.get("Mobile"),
        "Housing_Project_Name": lead.get("Project", ""),
        "Housing_Project_Id": str(lead.get("Property/Project ID", "")),
        "Layout": {"id": LAYOUT_ID_TENANT},
        "Potential_Project": lead.get("Project", ""),
        "Lead_Source": normalize_picklist("Lead_Source", "Housing.com", picklists.get("Lead_Source", [])),
        "Call_Done_By": normalize_picklist("Call_Done_By", lead.get("Raw", {}).get("Call done by", ""), picklists.get("Call_Done_By", [])),
        "Rent_Tenant_Configuration": lead.get("Configuration", ""),
        "Rent_Tenant_Locality": lead.get("Locality", ""),
        "Rent_Tenant_Budget_Correct": lead.get("Price", None),
        "Rent_Tenant_City": lead.get("City", ""),
    }

# Main orchestrator
def main():
    logging.info("=== Starting ingestion run ===")
    pprint.pprint({
        "99acres_file": FILE_99ACRES,
        "housing_file": FILE_HOUSING,
        "sheet": GOOGLE_SHEET_NAME,
        "tabs": [SHEET_99_ACRES_NAME, SHEET_HOUSING_NAME],
        "layout": LAYOUT_ID_TENANT,
    })

    # Google Sheets auth
    try:
        sheet_client = authorize_google_sheet()
    except Exception as e:
        logging.error("Google Sheets authorization failed: %s", e)
        return

    # Load corporate lookups
    acres_lookup, housing_lookup = load_corporate_lookups(sheet_client)

    # Zoho token + picklists
    try:
        access_token = get_zoho_access_token()
    except Exception as e:
        logging.error("Zoho OAuth failed: %s", e)
        return
    picklists = fetch_picklist_options(access_token)

    # Process source files
    leads_99 = process_99acres_sheet(acres_lookup)
    leads_housing = process_housing_sheet(housing_lookup)

    # Summary holders
    sheet_summary = {
        "99acres": {"attempted": len(leads_99), "appended": 0, "errors": []},
        "Housing.com": {"attempted": len(leads_housing), "appended": 0, "errors": []},
    }
    crm_summary = {
        "99acres": {"success": [], "fail": []},
        "Housing.com": {"success": [], "fail": []},
    }

    # Write to Google Sheets
    try:
        # 99 Acres Responses: start from column B
        rows_99 = []
        for lead in leads_99:
            rows_99.append([
                "",  # blank to shift into column B
                lead.get("Name", ""),
                lead.get("Type", ""),
                lead.get("Date", ""),
                lead.get("ResponseType", ""),
                lead.get("ProductCode", ""),
                lead.get("LeadScore", ""),
                lead.get("Project", ""),
            ])
        success_99, errors_99 = append_rows_to_sheet_tracked(sheet_client, SHEET_99_ACRES_NAME, rows_99)
        sheet_summary["99acres"]["appended"] = success_99
        sheet_summary["99acres"]["errors"] = errors_99

        # Housing Responses: skip "Call done by"
        for lead in leads_housing:
            ok, err = append_housing_row_filtered_tracked(sheet_client, lead)
            if ok:
                sheet_summary["Housing.com"]["appended"] += 1
            else:
                sheet_summary["Housing.com"]["errors"].append({"lead": lead.get("Listing_ID"), "error": err})

        logging.info("Appended to Google Sheets.")
    except Exception as e:
        logging.error("Failed appending to sheets: %s", e)

    # Push to Zoho CRM
    for lead in leads_99:
        payload = build_zoho_payload_from_99acres(lead, picklists)
        ok, resp = send_lead_to_zoho(access_token, payload)
        if ok:
            crm_summary["99acres"]["success"].append(payload.get("Last_Name"))
        else:
            crm_summary["99acres"]["fail"].append({"name": payload.get("Last_Name"), "error": resp})

    for lead in leads_housing:
        payload = build_zoho_payload_from_housing(lead, picklists)
        ok, resp = send_lead_to_zoho(access_token, payload)
        if ok:
            crm_summary["Housing.com"]["success"].append(payload.get("Last_Name"))
        else:
            crm_summary["Housing.com"]["fail"].append({"name": payload.get("Last_Name"), "error": resp})

    # Final summary log
    logging.info("=== RUN SUMMARY ===")
    # Sheets summary
    logging.info("Google Sheets ingestion summary:")
    for source in ("99acres", "Housing.com"):
        s = sheet_summary[source]
        logging.info(
            "  %s: attempted=%d, appended=%d, sheet errors=%d",
            source,
            s["attempted"],
            s["appended"],
            len(s["errors"]) if isinstance(s["errors"], list) else 0,
        )
        if s["errors"]:
            # show up to 3 errors each
            for err in s["errors"][:3]:
                logging.warning("    %s error: %s", source, err)

    # CRM summary
    logging.info("Zoho CRM ingestion summary:")
    for source_label, key in [("99acres", "99acres"), ("Housing.com", "Housing.com")]:
        c = crm_summary[key]
        logging.info("  %s: success=%d, failures=%d", source_label, len(c["success"]), len(c["fail"]))
        if c["fail"]:
            for f in c["fail"][:3]:
                logging.warning("    %s lead failed: %s error: %s", source_label, f.get("name"), f.get("error"))

    logging.info("=== Ingestion complete ===")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception("Uncaught exception")
        print("ERROR:", e)
        traceback.print_exc()
        sys.exit(1)
