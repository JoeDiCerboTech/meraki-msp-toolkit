import csv
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

# Meraki SSID Security Report - REST Version
#
# Prompts for:
# - Meraki API key
# - Organization to search
#
# This version DOES NOT use the Meraki Python module.
# It sends the API key directly with the X-Cisco-Meraki-API-Key header.
# Use this if the Meraki Python module gives:
# 401 Unauthorized - No valid authentication method found
#
# Exports:
# Org, Network, SSID, Enabled, Auth Mode, Encryption, VLAN, PSK/Enterprise
#
# Extra columns:
# SSID Number, WPA Mode, VLAN Tagging, Splash Page, Visibility, Band Selection,
# Min Bitrate, Availability, Risk Level, Security Notes, Dashboard URL
#
# IMPORTANT:
# - API key is entered visibly for PowerShell compatibility.
# - Do not screenshot or share the console while the key is visible.
# - Revoke/delete the API key when finished if it was exposed.

BASE_URL = "https://api.meraki.com/api/v1"


def prompt_api_key():
    print("Paste your Meraki API key below.")
    print("WARNING: It WILL be visible while you paste/type it. Do not screenshot this window.")
    api_key = input("Meraki API key: ").strip().strip('"').strip("'")

    if not api_key:
        raise SystemExit("No API key entered.")

    print(f"API key received. Length: {len(api_key)} characters.")
    return api_key


def safe_filename(value):
    value = str(value or "all_orgs")
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return value.strip("_") or "all_orgs"


def yes_no(value):
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if value is None:
        return ""
    return str(value)


def build_url(path, params=None):
    url = BASE_URL.rstrip("/") + path
    if params:
        query = urllib.parse.urlencode(params)
        url = f"{url}?{query}"
    return url


def get_next_link(link_header):
    if not link_header:
        return None

    parts = link_header.split(",")
    for part in parts:
        section = part.strip()
        if 'rel="next"' in section or "rel=next" in section:
            start = section.find("<")
            end = section.find(">")
            if start != -1 and end != -1 and end > start:
                return section[start + 1:end]

    return None


def meraki_get(api_key, path=None, params=None, full_url=None):
    url = full_url if full_url else build_url(path, params)

    headers = {
        "X-Cisco-Meraki-API-Key": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Meraki-MSP-Toolkit-SSID-Security-Report"
    }

    while True:
        req = urllib.request.Request(url, headers=headers, method="GET")

        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                raw = response.read().decode("utf-8", errors="replace")
                data = json.loads(raw) if raw.strip() else None
                next_link = get_next_link(response.headers.get("Link"))
                return data, next_link

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")

            if e.code == 429:
                retry_after = e.headers.get("Retry-After")
                wait_seconds = int(retry_after) if retry_after and retry_after.isdigit() else 2
                print(f"Rate limited. Waiting {wait_seconds} seconds...")
                time.sleep(wait_seconds)
                continue

            raise Exception(f"HTTP {e.code} {e.reason}: {body}")

        except urllib.error.URLError as e:
            raise Exception(f"URL error: {e}")


def meraki_get_all(api_key, path, params=None):
    all_items = []
    data, next_link = meraki_get(api_key, path=path, params=params)

    if isinstance(data, list):
        all_items.extend(data)
    elif data is not None:
        return data

    while next_link:
        data, next_link = meraki_get(api_key, full_url=next_link)
        if isinstance(data, list):
            all_items.extend(data)

    return all_items


def classify_auth(auth_mode, encryption_mode, wpa_mode, enabled):
    auth = str(auth_mode or "").lower()
    enc = str(encryption_mode or "").lower()
    wpa = str(wpa_mode or "").lower()

    if not enabled:
        return "Disabled"

    if "8021x" in auth:
        return "Enterprise"

    if "ipsk" in auth:
        return "iPSK"

    if auth == "psk" or "psk" in auth:
        return "PSK"

    if "open" in auth:
        if "radius" in auth:
            return "Open with RADIUS"
        if "enhanced" in auth or "owe" in enc or "owe" in wpa:
            return "Enhanced Open"
        return "Open"

    if enc == "wpa-eap":
        return "Enterprise"

    return "Other/Unknown"


def assess_risk(enabled, auth_mode, encryption_mode, wpa_mode, ssid_name):
    notes = []
    level = "Informational"

    auth = str(auth_mode or "").lower()
    enc = str(encryption_mode or "").lower()
    wpa = str(wpa_mode or "").lower()
    name = str(ssid_name or "").lower()

    if not enabled:
        return "Disabled", "SSID is disabled."

    if "open" in auth and "enhanced" not in auth:
        level = "High"
        notes.append("Open authentication.")

    if enc == "open" and "open" not in auth:
        level = "High"
        notes.append("Encryption mode is open.")

    if enc == "wep":
        level = "High"
        notes.append("WEP encryption detected.")

    if "wpa1" in wpa or "wpa and wpa2" in wpa:
        if level != "High":
            level = "Medium"
        notes.append("WPA1 or WPA/WPA2 mixed mode may be enabled.")

    if "psk" in auth and level not in ["High", "Medium"]:
        level = "Medium"
        notes.append("Pre-shared key SSID. Confirm PSK rotation and access control.")

    if "guest" in name and "open" in auth:
        notes.append("Guest SSID is open. Confirm splash/segmentation/firewall rules.")

    if "8021x" in auth and level == "Informational":
        level = "Low"
        notes.append("Enterprise authentication detected.")

    if "ipsk" in auth and level == "Informational":
        level = "Low"
        notes.append("Identity PSK detected.")

    if "enhanced" in auth and level == "Informational":
        level = "Medium"
        notes.append("Enhanced Open detected. Encrypted, but no normal user authentication.")

    if not notes:
        notes.append("No obvious weak setting flagged by script.")

    return level, " ".join(notes)


def get_vlan_summary(ssid):
    use_vlan = ssid.get("useVlanTagging")
    default_vlan = ssid.get("defaultVlanId")

    if use_vlan is True:
        if default_vlan not in [None, ""]:
            return str(default_vlan)
        return "VLAN tagging enabled"

    if use_vlan is False:
        return "No VLAN tagging"

    if default_vlan not in [None, ""]:
        return str(default_vlan)

    return ""


def get_availability(ssid):
    available_all = ssid.get("availableOnAllAps")
    tags = ssid.get("availabilityTags")

    if available_all is True:
        return "All APs"

    if tags:
        if isinstance(tags, list):
            return "AP tags: " + ", ".join(str(t) for t in tags)
        return str(tags)

    if available_all is False:
        return "Limited AP availability"

    return ""


def select_organizations(orgs):
    print("")
    print("Accessible Meraki organizations:")
    for idx, org in enumerate(orgs, start=1):
        print(f"{idx}. {org.get('name', '')} ({org.get('id', '')})")

    print("")
    print("Select organization to report on.")
    print("- Enter ALL or leave blank to search all orgs.")
    print("- Enter a number from the list to search one org.")
    print("- Enter part of an org name or an org ID to search matching orgs.")
    selection = input("Org selection: ").strip()

    if selection == "" or selection.lower() == "all":
        return orgs, "all_orgs"

    if selection.isdigit():
        index = int(selection)
        if 1 <= index <= len(orgs):
            return [orgs[index - 1]], orgs[index - 1].get("name", "selected_org")

    selection_lower = selection.lower()
    matches = [
        org for org in orgs
        if selection_lower in str(org.get("name", "")).lower()
        or selection_lower in str(org.get("id", "")).lower()
    ]

    if not matches:
        raise SystemExit(f"No organizations matched: {selection}")

    if len(matches) == 1:
        return matches, matches[0].get("name", selection)

    print("")
    print("Multiple organizations matched:")
    for idx, org in enumerate(matches, start=1):
        print(f"{idx}. {org.get('name', '')} ({org.get('id', '')})")

    print("")
    print("Enter ALL to search all matches, or enter a number to search one match.")
    pick = input("Matched org selection: ").strip()

    if pick == "" or pick.lower() == "all":
        return matches, selection

    if pick.isdigit():
        index = int(pick)
        if 1 <= index <= len(matches):
            return [matches[index - 1]], matches[index - 1].get("name", selection)

    raise SystemExit("Invalid organization selection.")


api_key = prompt_api_key()

rows = []
errors = []

print("")
print("Getting Meraki organizations using direct REST API...")
print("")

try:
    orgs = meraki_get_all(api_key, "/organizations", params={"perPage": 1000})
except Exception as e:
    raise SystemExit(
        "Could not list Meraki organizations.\n"
        f"Error: {e}\n\n"
        "Most likely causes:\n"
        "- The API key was not pasted correctly.\n"
        "- The API key was revoked or expired.\n"
        "- The key belongs to a Meraki admin with no org access.\n"
        "- Extra characters were copied with the key.\n"
    )

selected_orgs, scope_name = select_organizations(orgs)

print("")
print(f"Building Meraki SSID security report for {len(selected_orgs)} organization(s)...")
print("")

for org in selected_orgs:
    org_id = org.get("id", "")
    org_name = org.get("name", "")

    print(f"Checking org: {org_name}")

    try:
        networks = meraki_get_all(api_key, f"/organizations/{org_id}/networks", params={"perPage": 1000})
    except Exception as e:
        errors.append(f"{org_name}: could not list networks - {e}")
        continue

    wireless_networks = []
    for net in networks:
        product_types = net.get("productTypes", [])
        if isinstance(product_types, list) and "wireless" in product_types:
            wireless_networks.append(net)

    if not wireless_networks:
        print("  No wireless networks found.")
        continue

    for net in wireless_networks:
        net_id = net.get("id", "")
        net_name = net.get("name", "")

        print(f"  Checking wireless network: {net_name}")

        try:
            ssids = meraki_get_all(api_key, f"/networks/{net_id}/wireless/ssids")
        except Exception as e:
            errors.append(f"{org_name} | {net_name}: could not read SSIDs - {e}")
            continue

        for ssid in ssids:
            ssid_number = ssid.get("number", "")
            ssid_name = ssid.get("name", "")
            enabled = ssid.get("enabled", False)
            auth_mode = ssid.get("authMode", "")
            encryption_mode = ssid.get("encryptionMode", "")
            wpa_mode = ssid.get("wpaEncryptionMode", "")
            vlan = get_vlan_summary(ssid)
            psk_enterprise = classify_auth(auth_mode, encryption_mode, wpa_mode, enabled)
            risk_level, security_notes = assess_risk(enabled, auth_mode, encryption_mode, wpa_mode, ssid_name)

            dashboard_url = f"https://dashboard.meraki.com/network/{net_id}/configure/wireless/ssids/{ssid_number}"

            rows.append({
                "Org": org_name,
                "Org ID": org_id,
                "Network": net_name,
                "Network ID": net_id,
                "SSID Number": ssid_number,
                "SSID": ssid_name,
                "Enabled": yes_no(enabled),
                "Auth Mode": auth_mode,
                "Encryption": encryption_mode,
                "WPA Mode": wpa_mode,
                "VLAN Tagging": yes_no(ssid.get("useVlanTagging")),
                "VLAN": vlan,
                "PSK/Enterprise": psk_enterprise,
                "Splash Page": ssid.get("splashPage", ""),
                "Visibility": "Hidden" if ssid.get("visible") is False else "Visible",
                "Band Selection": ssid.get("bandSelection", ""),
                "Min Bitrate": ssid.get("minBitrate", ""),
                "Availability": get_availability(ssid),
                "Risk Level": risk_level,
                "Security Notes": security_notes,
                "Dashboard URL": dashboard_url
            })

print("")

if rows:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = f"Meraki_SSID_Security_Report_{safe_filename(scope_name)}_{timestamp}.csv"

    fieldnames = [
        "Org",
        "Org ID",
        "Network",
        "Network ID",
        "SSID Number",
        "SSID",
        "Enabled",
        "Auth Mode",
        "Encryption",
        "WPA Mode",
        "VLAN Tagging",
        "VLAN",
        "PSK/Enterprise",
        "Splash Page",
        "Visibility",
        "Band Selection",
        "Min Bitrate",
        "Availability",
        "Risk Level",
        "Security Notes",
        "Dashboard URL",
    ]

    rows.sort(key=lambda r: (
        str(r.get("Org", "")),
        str(r.get("Network", "")),
        int(r.get("SSID Number") or 0)
    ))

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("SSID SECURITY REPORT:")
    print("")
    for r in rows:
        print(
            f'{r["Org"]} | {r["Network"]} | SSID {r["SSID Number"]}: {r["SSID"]} | '
            f'Enabled: {r["Enabled"]} | Auth: {r["Auth Mode"]} | '
            f'Encryption: {r["Encryption"]} {r["WPA Mode"]} | '
            f'VLAN: {r["VLAN"]} | Type: {r["PSK/Enterprise"]} | Risk: {r["Risk Level"]}'
        )

    print("")
    print(f"Saved CSV: {csv_file}")

else:
    print("No SSIDs found or no wireless networks were accessible.")

if errors:
    print("")
    print("Skipped/errors:")
    for err in errors:
        print(f" - {err}")
