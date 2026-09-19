import csv
from datetime import datetime, timezone
import meraki

# Meraki License Expiration Report
#
# Prompts for a Meraki API key and exports:
# - Org
# - License Status
# - Expiration Date
# - Days Remaining
#
# IMPORTANT:
# - API key is entered visibly for PowerShell compatibility.
# - Do not screenshot or share the console while the key is visible.
# - Revoke/delete the API key when finished if it was exposed.
#
# NOTE:
# This script passes the API key as the FIRST positional argument to DashboardAPI.
# This avoids "401 Unauthorized - No valid authentication method found" issues
# seen with some installed versions of the Meraki Python module.


def prompt_api_key():
    print("Paste your Meraki API key below.")
    print("WARNING: It WILL be visible while you paste/type it. Do not screenshot this window.")
    api_key = input("Meraki API key: ").strip().strip('"').strip("'")

    if not api_key:
        raise SystemExit("No API key entered.")

    print(f"API key received. Length: {len(api_key)} characters.")
    return api_key


def parse_meraki_date(value):
    """
    Meraki dates may be returned in different formats depending on endpoint/licensing model.
    Examples:
    - Feb 8, 2020 UTC
    - 2020-10-30T15:01:46Z
    - 2020-10-30
    """
    if not value:
        return None

    text = str(value).strip()

    formats = [
        "%b %d, %Y UTC",
        "%B %d, %Y UTC",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(text, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    try:
        iso_text = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def days_remaining(expiration_text):
    dt = parse_meraki_date(expiration_text)
    if not dt:
        return ""

    now = datetime.now(timezone.utc)
    return (dt.date() - now.date()).days


def get_state_count(overview, state_name):
    try:
        return overview.get("states", {}).get(state_name, {}).get("count", "")
    except Exception:
        return ""


def build_per_device_status(overview):
    active = get_state_count(overview, "active")
    expiring = get_state_count(overview, "expiring")
    expired = get_state_count(overview, "expired")
    unused = get_state_count(overview, "unused")
    unused_active = get_state_count(overview, "unusedActive")
    recently_queued = get_state_count(overview, "recentlyQueued")

    parts = []
    if active != "":
        parts.append(f"active={active}")
    if expiring != "":
        parts.append(f"expiring={expiring}")
    if expired != "":
        parts.append(f"expired={expired}")
    if unused != "":
        parts.append(f"unused={unused}")
    if unused_active != "":
        parts.append(f"unusedActive={unused_active}")
    if recently_queued != "":
        parts.append(f"recentlyQueued={recently_queued}")

    if parts:
        return "Per-device: " + ", ".join(parts)

    return "Per-device or unknown"


def get_soonest_license_expiration(licenses):
    """
    For per-device licensing, find the soonest expiration among license records.
    """
    candidates = []

    for lic in licenses:
        expiration = lic.get("expirationDate")
        parsed = parse_meraki_date(expiration)

        if parsed:
            candidates.append((
                parsed,
                expiration,
                lic.get("state", ""),
                lic.get("licenseType", ""),
                lic.get("deviceSerial", "")
            ))

    if not candidates:
        return "", ""

    candidates.sort(key=lambda x: x[0])
    parsed, expiration, state, license_type, serial = candidates[0]

    note = f"Soonest individual license: state={state}, type={license_type}, serial={serial}"
    return expiration, note


api_key = prompt_api_key()

# IMPORTANT: use positional API key argument for compatibility.
dashboard = meraki.DashboardAPI(
    api_key,
    suppress_logging=True,
    output_log=False,
    print_console=False
)

rows = []
errors = []

print("")
print("Building Meraki license expiration report for all accessible organizations...")
print("")

try:
    orgs = dashboard.organizations.getOrganizations(total_pages="all")
except Exception as e:
    raise SystemExit(
        "Could not list Meraki organizations.\n"
        f"Error: {e}\n\n"
        "Most likely causes:\n"
        "- The API key was not pasted correctly.\n"
        "- The API key was revoked or expired.\n"
        "- The key belongs to a Meraki admin with no org access.\n"
        "- Extra characters were copied with the key.\n"
        "- The installed Meraki Python module needs an update.\n\n"
        "Try this:\n"
        "python -m pip install --upgrade meraki\n"
    )

for org in orgs:
    org_id = org.get("id", "")
    org_name = org.get("name", "")

    print(f"Checking org: {org_name}")

    row = {
        "Org": org_name,
        "License Status": "",
        "Expiration Date": "",
        "Days Remaining": "",
        "Org ID": org_id,
        "Licensing Notes": "",
        "Active Count": "",
        "Expiring Count": "",
        "Expired Count": "",
        "Unused Count": "",
    }

    try:
        overview = dashboard.organizations.getOrganizationLicensesOverview(org_id)

        row["Active Count"] = get_state_count(overview, "active")
        row["Expiring Count"] = get_state_count(overview, "expiring")
        row["Expired Count"] = get_state_count(overview, "expired")
        row["Unused Count"] = get_state_count(overview, "unused")

        overview_status = overview.get("status", "")
        overview_expiration = overview.get("expirationDate", "")

        if overview_status:
            row["License Status"] = overview_status

        if overview_expiration:
            row["Expiration Date"] = overview_expiration
            row["Days Remaining"] = days_remaining(overview_expiration)
            row["Licensing Notes"] = "Co-termination org-level expiration"
        else:
            row["License Status"] = build_per_device_status(overview)

            try:
                licenses = dashboard.organizations.getOrganizationLicenses(
                    org_id,
                    total_pages="all"
                )

                soonest_expiration, note = get_soonest_license_expiration(licenses)
                row["Expiration Date"] = soonest_expiration
                row["Days Remaining"] = days_remaining(soonest_expiration)
                row["Licensing Notes"] = note or "No individual license expiration found"

            except Exception as e:
                row["Licensing Notes"] = f"Could not list individual licenses: {e}"
                errors.append(f"{org_name}: could not list individual licenses - {e}")

    except Exception as e:
        row["License Status"] = "API Error"
        row["Licensing Notes"] = str(e)
        errors.append(f"{org_name}: license overview failed - {e}")

    rows.append(row)

print("")

if rows:
    def sort_key(r):
        val = r.get("Days Remaining", "")
        if val == "" or val is None:
            return 999999
        try:
            return int(val)
        except Exception:
            return 999999

    rows.sort(key=sort_key)

    print("LICENSE REPORT:")
    print("")

    for r in rows:
        print(
            f'{r["Org"]} | '
            f'Status: {r["License Status"]} | '
            f'Expiration: {r["Expiration Date"]} | '
            f'Days Remaining: {r["Days Remaining"]}'
        )

    csv_file = "Meraki_License_Expiration_Report.csv"

    fieldnames = [
        "Org",
        "License Status",
        "Expiration Date",
        "Days Remaining",
        "Org ID",
        "Licensing Notes",
        "Active Count",
        "Expiring Count",
        "Expired Count",
        "Unused Count",
    ]

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("")
    print(f"Saved CSV: {csv_file}")

else:
    print("No organizations returned.")

if errors:
    print("")
    print("Skipped/errors:")
    for err in errors:
        print(f" - {err}")
