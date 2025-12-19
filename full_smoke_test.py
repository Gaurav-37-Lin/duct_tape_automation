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

# ============================================================
# DEBUG / LOGGING SETUP
# ============================================================
print("DEBUG: script invoked", sys.executable, "cwd:", os.getcwd())
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")

# ============================================================
# Load config
# ============================================================
CONFIG_PATH = "config.yaml"
if not os.path.exists(CONFIG_PATH):
    logging.error("config.yaml not found at: %s", os.path.abspath(CONFIG_PATH))
    sys.exit(1)

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)

# ============================================================
# Zoho config
# ============================================================
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

# ============================================================
# Google Sheets config
# ============================================================
google_cfg = cfg.get("google", {})
GOOGLE_SERVICE_ACCOUNT_FILE = google_cfg.get("service_account_file")
GOOGLE_SHEET_NAME = google_cfg.get("sheet_name")
SHEET_99_ACRES_NAME = google_cfg.get("sheets", {}).get("acres")
SHEET_HOUSING_NAME = google_cfg.get("sheets", {}).get("housing")

if not all([GOOGLE_SERVICE_ACCOUNT_FILE, GOOGLE_SHEET_NAME, SHEET_99_ACRES_NAME, SHEET_HOUSING_NAME]):
    logging.error("Incomplete Google Sheets configuration.")
    sys.exit(1)

# ============================================================
# Files
# ============================================================
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


# ============================================================
# Helpers
# ============================================================
def canonicalize_id(s):
    """Robust ID canonicalization to prevent matching failures and hidden-char issues."""
    if s is None:
        return ""
    try:
        if pd.isna(s):
            return ""
    except Exception:
        pass

    # If a numeric key comes as float
    if isinstance(s, float):
        if s.is_integer():
            s = str(int(s))
        else:
            s = str(s)

    s = str(s)
    s = s.replace("\u00A0", " ").replace("\u200b", "")  # NBSP + zero-width
    s = s.strip().lower()
    s = re.sub(r"\s+", "", s)  # remove all whitespace (including internal)

    # strip trailing .0 (if any)
    if re.fullmatch(r"\d+\.0", s):
        s = s[:-2]

    return s


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


# ============================================================
# Zoho OAuth & metadata
# ============================================================
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
    logging.info("Fetched %d picklist/multiselect fields for module=%s", len(picklists), module)
    return picklists


def send_lead_to_zoho(access_token, lead_payload):
    headers = {
        "Authorization": f"Zoho-oauthtoken {access_token}",
        "Content-Type": "application/json;charset=UTF-8",
    }
    body = {"data": [lead_payload], "trigger": []}
    logging.debug("Sending to Zoho payload: %s", lead_payload)
    resp = requests.post(ZOHO_LEADS_ENDPOINT, json=body, headers=headers)
    logging.info("Zoho response: status=%s body=%s", resp.status_code, resp.text)
    if resp.status_code not in (200, 201, 202):
        return False, resp.text
    try:
        return True, resp.json()
    except Exception:
        return False, resp.text


# ============================================================
# Google Sheets
# ============================================================
def authorize_google_sheet():
    scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
    creds = ServiceAccountCredentials.from_json_keyfile_name(GOOGLE_SERVICE_ACCOUNT_FILE, scope)
    client = gspread.authorize(creds)
    return client


def _log_ws_state(ws, label):
    """Logs worksheet state to catch 'appending far below' and other issues."""
    try:
        all_vals_len = len(ws.get_all_values())
        header = ws.row_values(1)
        logging.info("[%s] ws='%s' get_all_values rows=%d header_cols=%d", label, ws.title, all_vals_len, len(header))
        logging.info("[%s] ws='%s' header=%s", label, ws.title, header)
    except Exception as e:
        logging.warning("[%s] Could not log worksheet state for ws='%s': %s", label, ws.title, e)


def append_rows_to_sheet_tracked(client, tab_name, rows):
    """
    Append rows in batch and log updatedRange.
    This method is robust and should be preferred for ingestion sheets.
    """
    ws = client.open(GOOGLE_SHEET_NAME).worksheet(tab_name)
    _log_ws_state(ws, "BEFORE_APPEND")

    if not rows:
        logging.info("No rows to append for tab='%s'", tab_name)
        return 0, []

    flat_rows = [[safe_value(c) for c in row] for row in rows]
    logging.info("Appending rows to tab='%s' count=%d first_row=%s last_row=%s",
                 tab_name, len(flat_rows), flat_rows[0], flat_rows[-1])

    try:
        resp = ws.append_rows(flat_rows, value_input_option="USER_ENTERED")
        upd = (resp or {}).get("updates", {}) if isinstance(resp, dict) else {}
        logging.info(
            "append_rows OK tab='%s' updatedRange=%s updatedRows=%s updatedColumns=%s updatedCells=%s",
            tab_name,
            upd.get("updatedRange"),
            upd.get("updatedRows"),
            upd.get("updatedColumns"),
            upd.get("updatedCells"),
        )
        _log_ws_state(ws, "AFTER_APPEND")
        return len(rows), []
    except Exception as e:
        logging.error("append_rows failed for tab='%s': %s", tab_name, e)
        return 0, [{"error": str(e)}]


def get_effective_last_row(ws):
    """
    Reliable last-row detection based on actual values returned.
    """
    vals = ws.get_all_values()
    return len(vals) if vals else 1


def insert_row_then_update(ws, row_values, start_col=1):
    """
    FIX for Housing sheet overwriting same row:
    - Insert a new blank row after the current last used row
    - Update that row with your values
    """
    last_row = get_effective_last_row(ws)
    target_row = last_row + 1

    logging.info("insert_row_then_update ws='%s': last_row=%d -> target_row=%d", ws.title, last_row, target_row)

    # Insert blank row (width = max of current header or row length)
    header_len = len(ws.row_values(1))
    width = max(header_len, len(row_values), 1)
    ws.insert_row([""] * width, index=target_row)

    # Update the inserted row
    col_count = len(row_values)
    start_cell = gspread.utils.rowcol_to_a1(target_row, start_col)
    end_cell = gspread.utils.rowcol_to_a1(target_row, start_col + col_count - 1)
    a1_range = f"{start_cell}:{end_cell}"

    logging.info("Updating inserted row range=%s col_count=%d", a1_range, col_count)
    ws.update(a1_range, [row_values], value_input_option="USER_ENTERED")

    return a1_range


def append_housing_row_filtered_tracked(client, lead, exclude_columns=None):
    """
    Housing sheet FIXED:
    Do NOT use append_row (it overwrites the same row in your sheet).
    Instead: insert a new row then update it.
    """
    if exclude_columns is None:
        exclude_columns = ["Call done by"]

    ws = client.open(GOOGLE_SHEET_NAME).worksheet(SHEET_HOUSING_NAME)

    header = ws.row_values(1)
    logging.debug("Housing header cols=%d exclude_columns=%s header=%s", len(header), exclude_columns, header)

    raw = lead["Raw"]

    # Build row aligned to header order, skipping excluded columns
    row = []
    used_cols = []
    for col in header:
        if col in exclude_columns:
            continue
        used_cols.append(col)
        row.append(safe_value(raw.get(col, "")))

    logging.info(
        "Housing prepared row listing_id=%s cols_used=%d first5=%s last5=%s",
        lead.get("Listing_ID"),
        len(row),
        row[:5],
        row[-5:] if len(row) >= 5 else row,
    )

    try:
        written_range = insert_row_then_update(ws, row, start_col=1)
        logging.info("Housing write OK listing_id=%s written_range=%s", lead.get("Listing_ID"), written_range)
        return True, None
    except Exception as e:
        logging.error("Housing write FAILED listing_id=%s error=%s", lead.get("Listing_ID"), e)
        return False, str(e)


def _log_sheet_columns(sheet_client, tab_name):
    try:
        ws = sheet_client.open(GOOGLE_SHEET_NAME).worksheet(tab_name)
        header = ws.row_values(1)
        logging.info("Sheet '%s' header (%d cols): %s", tab_name, len(header), header)
    except Exception as e:
        logging.warning("Could not read header for '%s': %s", tab_name, e)


def load_corporate_lookups(sheet_client):
    acres_lookup = {}
    housing_lookup = {}

    _log_sheet_columns(sheet_client, CORP_99_ACRES_TAB)
    _log_sheet_columns(sheet_client, CORP_HOUSING_TAB)

    # 99 Acres Corporate
    try:
        ws = sheet_client.open(GOOGLE_SHEET_NAME).worksheet(CORP_99_ACRES_TAB)
        records = ws.get_all_records()
        logging.info("Loaded %d records from '%s'", len(records), CORP_99_ACRES_TAB)
        if records:
            logging.info("'%s' first record keys: %s", CORP_99_ACRES_TAB, list(records[0].keys()))

        for r in records:
            key_raw = (
                r.get("Listing ID") or r.get("listing id") or
                r.get("Product Code") or r.get("ProductCode") or r.get("Product code")
            )
            key = canonicalize_id(key_raw)
            if not key:
                continue
            acres_lookup[key] = {
                "Project": (r.get("Project") or "").strip(),
                "Configuration": (r.get("Configuration") or "").strip(),
                "Price": r.get("Price", ""),
                "Locality": (r.get("Location") or "").strip(),
                "City": (r.get("Main Location") or "").strip(),
            }

        logging.info("acres_lookup size=%d sample_keys=%s", len(acres_lookup), list(acres_lookup.keys())[:10])
    except Exception as e:
        logging.warning("Failed loading '%s': %s", CORP_99_ACRES_TAB, e)

    # Housing Corporate
    try:
        ws = sheet_client.open(GOOGLE_SHEET_NAME).worksheet(CORP_HOUSING_TAB)
        records = ws.get_all_records()
        logging.info("Loaded %d records from '%s'", len(records), CORP_HOUSING_TAB)
        if records:
            logging.info("'%s' first record keys: %s", CORP_HOUSING_TAB, list(records[0].keys()))

        for r in records:
            key_raw = (
                r.get("Listing ID") or r.get("listing id") or
                r.get("Property/Project ID") or r.get("Property Project ID")
            )
            key = canonicalize_id(key_raw)
            if not key:
                continue
            housing_lookup[key] = {
                "Project": (r.get("Project") or "").strip(),
                "Configuration": (r.get("Configuration") or "").strip(),
                "Price": r.get("Price", ""),
                "Locality": (r.get("Location") or "").strip(),
                "City": (r.get("Main Location") or "").strip(),
            }

        logging.info("housing_lookup size=%d sample_keys=%s", len(housing_lookup), list(housing_lookup.keys())[:10])
    except Exception as e:
        logging.warning("Failed loading '%s': %s", CORP_HOUSING_TAB, e)

    return acres_lookup, housing_lookup


# ============================================================
# Source processing
# ============================================================
def process_99acres_sheet(acres_corp_lookup):
    if not os.path.exists(FILE_99ACRES):
        logging.warning("99acres source file missing: %s", FILE_99ACRES)
        return []

    logging.info("Reading 99acres CSV: %s", os.path.abspath(FILE_99ACRES))
    df = pd.read_csv(FILE_99ACRES, dtype=str, keep_default_na=False)
    logging.info("99acres CSV rows=%d columns=%d", len(df), len(df.columns))
    logging.info("99acres CSV columns=%s", list(df.columns))

    # sample log
    for i in range(min(5, len(df))):
        raw0 = df.iloc[i].to_dict()
        pid_raw = raw0.get("ProductCode")
        pid = canonicalize_id(pid_raw)
        logging.info("99acres sample[%d] ProductCode raw='%s' canon='%s' in_lookup=%s",
                     i, pid_raw, pid, pid in acres_corp_lookup)

    leads = []
    missing_code = 0
    no_match = 0

    for _, row in df.iterrows():
        raw = row.to_dict()
        listing_id = canonicalize_id(raw.get("ProductCode"))
        if not listing_id:
            missing_code += 1
            continue
        clean = acres_corp_lookup.get(listing_id)
        if not clean:
            no_match += 1
            continue

        budget = convert_price_to_number(str(clean.get("Price", "")))

        leads.append({
            "source": "99acres",
            "Listing_ID": listing_id,
            "Name": raw.get("Name", ""),
            "Type": raw.get("Type", ""),
            "Date": format_date_british(raw.get("ReceivedDate")),
            "ResponseType": raw.get("ResponseType", ""),
            "ProductCode": raw.get("ProductCode", ""),
            "LeadScore": raw.get("LeadScore", ""),
            "Project": clean.get("Project", ""),
            "Configuration": clean.get("Configuration", ""),
            "Locality": clean.get("Locality", ""),
            "Budget": budget,
            "City": clean.get("City", ""),
            "Mobile": normalize_phone(raw.get("ContactNo", "")),
            "Raw": raw,
        })

    logging.info("99acres processed: total_rows=%d leads_built=%d missing_ProductCode=%d no_corporate_match=%d",
                 len(df), len(leads), missing_code, no_match)
    return leads


def process_housing_sheet(housing_corp_lookup):
    if not os.path.exists(FILE_HOUSING):
        logging.warning("housing source file missing: %s", FILE_HOUSING)
        return []

    logging.info("Reading housing Excel: %s", os.path.abspath(FILE_HOUSING))
    try:
        df = pd.read_excel(FILE_HOUSING, dtype=str, engine="openpyxl", keep_default_na=False)
    except Exception as e:
        logging.error("Failed reading housing file: %s", e)
        return []

    logging.info("housing Excel rows=%d columns=%d", len(df), len(df.columns))
    logging.info("housing Excel columns=%s", list(df.columns))

    for i in range(min(5, len(df))):
        raw0 = df.iloc[i].to_dict()
        lid_raw = raw0.get("Property/Project ID")
        lid = canonicalize_id(lid_raw)
        logging.info("housing sample[%d] Property/Project ID raw='%s' canon='%s' in_lookup=%s",
                     i, lid_raw, lid, lid in housing_corp_lookup)

    leads = []
    missing_id = 0
    no_match = 0

    for _, row in df.iterrows():
        raw = row.to_dict()
        listing_id = canonicalize_id(raw.get("Property/Project ID"))
        if not listing_id:
            missing_id += 1
            continue
        clean = housing_corp_lookup.get(listing_id)
        if not clean:
            no_match += 1
            continue

        leads.append({
            "source": "Housing.com",
            "Listing_ID": listing_id,
            "Lead Name": raw.get("Lead Name", ""),
            "Mobile": normalize_phone(raw.get("Lead Phone Number", "")),
            "Project": clean.get("Project", ""),
            "Configuration": clean.get("Configuration", ""),
            "Price": convert_price_to_number(str(clean.get("Price", ""))),
            "Locality": clean.get("Locality", ""),
            "City": clean.get("City", ""),
            "Property/Project ID": raw.get("Property/Project ID", ""),
            "Raw": raw,
        })

    logging.info("housing processed: total_rows=%d leads_built=%d missing_PropertyProjectID=%d no_corporate_match=%d",
                 len(df), len(leads), missing_id, no_match)
    return leads


# ============================================================
# Zoho payloads
# ============================================================
def build_zoho_payload_from_99acres(lead, picklists):
    return {
        "Last_Name": lead.get("Name") or "Unknown",
        "Mobile": lead.get("Mobile"),
        "acres99__Project_Name": lead.get("Project", ""),
        "acres99__Query_ID": lead.get("ProductCode", ""),
        "Layout": {"id": LAYOUT_ID_TENANT},
        "Potential_Project": lead.get("Project", ""),
        "Lead_Source": normalize_picklist("Lead_Source", "99acres", picklists.get("Lead_Source", [])),
        "Call_Done_By": normalize_picklist(
            "Call_Done_By",
            lead.get("Raw", {}).get("Call done by", ""),
            picklists.get("Call_Done_By", [])
        ),
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
        "Call_Done_By": normalize_picklist(
            "Call_Done_By",
            lead.get("Raw", {}).get("Call done by", ""),
            picklists.get("Call_Done_By", [])
        ),
        "Rent_Tenant_Configuration": lead.get("Configuration", ""),
        "Rent_Tenant_Locality": lead.get("Locality", ""),
        "Rent_Tenant_Budget_Correct": lead.get("Price", None),
        "Rent_Tenant_City": lead.get("City", ""),
    }


# ============================================================
# Main
# ============================================================
def main():
    logging.info("=== Starting ingestion run ===")
    pprint.pprint({
        "99acres_file": FILE_99ACRES,
        "housing_file": FILE_HOUSING,
        "sheet": GOOGLE_SHEET_NAME,
        "tabs": [SHEET_99_ACRES_NAME, SHEET_HOUSING_NAME],
        "layout": LAYOUT_ID_TENANT,
    })

    # Google auth
    try:
        sheet_client = authorize_google_sheet()
        logging.info("Google Sheets authorisation OK.")
    except Exception as e:
        logging.error("Google Sheets authorisation failed: %s", e)
        return

    # Open spreadsheet sanity
    try:
        ss = sheet_client.open(GOOGLE_SHEET_NAME)
        logging.info("Opened spreadsheet OK: '%s' url=%s", ss.title, ss.url)
        logging.info("Spreadsheet tabs: %s", [w.title for w in ss.worksheets()])
    except Exception as e:
        logging.error("Could not open spreadsheet '%s': %s", GOOGLE_SHEET_NAME, e)
        return

    # Load lookups
    acres_lookup, housing_lookup = load_corporate_lookups(sheet_client)

    # Zoho token + picklists
    try:
        access_token = get_zoho_access_token()
    except Exception as e:
        logging.error("Zoho OAuth failed: %s", e)
        return

    picklists = fetch_picklist_options(access_token)

    # Process files
    leads_99 = process_99acres_sheet(acres_lookup)
    leads_housing = process_housing_sheet(housing_lookup)
    logging.info("Leads built: 99acres=%d Housing=%d", len(leads_99), len(leads_housing))

    sheet_summary = {
        "99acres": {"attempted": len(leads_99), "appended": 0, "errors": []},
        "Housing.com": {"attempted": len(leads_housing), "appended": 0, "errors": []},
    }
    crm_summary = {
        "99acres": {"success": [], "fail": []},
        "Housing.com": {"success": [], "fail": []},
    }

    # ------------------------------------------------------------
    # Append to Google Sheets
    # ------------------------------------------------------------
    try:
        # 99acres batch append (robust)
        rows_99 = []
        for lead in leads_99:
            rows_99.append([
                "",  # shift into column B
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

        # Housing FIXED (insert+update so it never overwrites)
        for lead in leads_housing:
            ok, err = append_housing_row_filtered_tracked(sheet_client, lead)
            if ok:
                sheet_summary["Housing.com"]["appended"] += 1
            else:
                sheet_summary["Housing.com"]["errors"].append({"lead": lead.get("Listing_ID"), "error": err})

        logging.info("Appended to Google Sheets (code path complete).")
    except Exception as e:
        logging.error("Failed appending to sheets: %s", e)

    # ------------------------------------------------------------
    # Push to Zoho CRM
    # ------------------------------------------------------------
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

    # ------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------
    logging.info("=== RUN SUMMARY ===")
    logging.info("Google Sheets ingestion summary:")
    for source in ("99acres", "Housing.com"):
        s = sheet_summary[source]
        logging.info("  %s: attempted=%d appended=%d sheet_errors=%d",
                     source, s["attempted"], s["appended"],
                     len(s["errors"]) if isinstance(s["errors"], list) else 0)
        if s["errors"]:
            for err in s["errors"][:3]:
                logging.warning("    %s error sample: %s", source, err)

    logging.info("Zoho CRM ingestion summary:")
    for source_label, key in [("99acres", "99acres"), ("Housing.com", "Housing.com")]:
        c = crm_summary[key]
        logging.info("  %s: success=%d failures=%d", source_label, len(c["success"]), len(c["fail"]))
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
