import csv
import json
import meraki

# Search all Meraki orgs/networks for either a MAC address OR serial number.
#
# Prompts for:
# 1. Meraki API key
# 2. Search value: MAC address or serial number
#
# Examples:
# - 0c:7b:c8:cb:11:89
# - 0c7bc8cb1189
# - Q2XX-XXXX-XXXX
#
# Notes:
# - The API key is entered visibly because some Windows PowerShell sessions do not handle hidden input cleanly.
# - Do not screenshot or share the window while the key is visible.
# - Revoke the key when finished if it was exposed.
#
# Checks:
# 1. Meraki hardware devices: MX, MS, MR, MV, MG, etc.
# 2. Meraki inventory devices, including claimed/unassigned inventory when available.
# 3. Clients seen on networks in the last 31 days.
#
# Client search is mainly useful for MACs. Meraki clients usually do not have Meraki serial numbers.

CLIENT_TIMESPAN_SECONDS = 2678400  # 31 days, Meraki client endpoint max lookback


def normalize_mac(value):
    return str(value or "").lower().replace(":", "").replace("-", "").replace(".", "").replace(" ", "").strip()


def normalize_serial(value):
    return str(value or "").upper().replace(" ", "").strip()


def normalize_serial_loose(value):
    return normalize_serial(value).replace("-", "")


def mac_is_valid(mac_norm):
    return len(mac_norm) == 12 and all(c in "0123456789abcdef" for c in mac_norm)


def format_mac(mac_norm):
    return ":".join(mac_norm[i:i + 2] for i in range(0, 12, 2))


def prompt_api_key():
    print("Paste your Meraki API key below.")
    print("WARNING: It WILL be visible while you paste/type it. Do not screenshot this window.")
    api_key = input("Meraki API key: ").strip().strip('"').strip("'")
    if not api_key:
        raise SystemExit("No API key entered.")
    print(f"API key received. Length: {len(api_key)} characters.")
    return api_key


def contains_mac_anywhere(obj, target_mac_norm):
    try:
        text = json.dumps(obj, default=str).lower()
        text = text.replace(":", "").replace("-", "").replace(".", "").replace(" ", "")
        return target_mac_norm in text
    except Exception:
        return False


def contains_serial_anywhere(obj, target_serial):
    try:
        text = json.dumps(obj, default=str).upper()
        text_tight = text.replace(" ", "")
        text_loose = text_tight.replace("-", "")
        return target_serial in text_tight or normalize_serial_loose(target_serial) in text_loose
    except Exception:
        return False


def add_match(matches, data):
    key = (
        data.get("Match Type", ""),
        data.get("Org ID", ""),
        data.get("Network ID", ""),
        data.get("Serial", ""),
        normalize_mac(data.get("MAC", "")),
        data.get("URL", ""),
    )

    existing_keys = {
        (
            m.get("Match Type", ""),
            m.get("Org ID", ""),
            m.get("Network ID", ""),
            m.get("Serial", ""),
            normalize_mac(m.get("MAC", "")),
            m.get("URL", ""),
        )
        for m in matches
    }

    if key not in existing_keys:
        matches.append(data)


def device_matches_search(device, search_type, target_mac_norm, target_serial):
    if search_type == "MAC":
        mac_candidates = [
            device.get("mac"),
            device.get("lanMac"),
            device.get("wan1Mac"),
            device.get("wan2Mac"),
        ]
        direct_match = any(normalize_mac(m) == target_mac_norm for m in mac_candidates)
        fallback_match = contains_mac_anywhere(device, target_mac_norm)
        return direct_match or fallback_match

    serial = normalize_serial(device.get("serial", ""))
    serial_loose = normalize_serial_loose(device.get("serial", ""))
    direct_match = (
        serial == target_serial or
        serial_loose == normalize_serial_loose(target_serial)
    )
    fallback_match = contains_serial_anywhere(device, target_serial)
    return direct_match or fallback_match


def client_matches_search(client, search_type, target_mac_norm, target_serial):
    if search_type == "MAC":
        direct_match = normalize_mac(client.get("mac", "")) == target_mac_norm
        fallback_match = contains_mac_anywhere(client, target_mac_norm)
        return direct_match or fallback_match

    # Clients usually do not have Meraki serial numbers, but this checks any returned field just in case.
    return contains_serial_anywhere(client, target_serial)


api_key = prompt_api_key()

search_input = input("Enter MAC address OR serial number to search: ").strip().strip('"').strip("'")
if not search_input:
    raise SystemExit("No search value entered.")

search_mac_norm = normalize_mac(search_input)

if mac_is_valid(search_mac_norm):
    search_type = "MAC"
    target_mac_norm = search_mac_norm
    target_mac_display = format_mac(target_mac_norm)
    target_serial = ""
    safe_filename_value = target_mac_norm
else:
    search_type = "SERIAL"
    target_mac_norm = ""
    target_serial = normalize_serial(search_input)
    target_mac_display = ""
    safe_filename_value = normalize_serial_loose(target_serial)

dashboard = meraki.DashboardAPI(
    api_key=api_key,
    suppress_logging=True,
    output_log=False,
    print_console=False
)

matches = []
errors = []

print("")
if search_type == "MAC":
    print(f"Searching all accessible Meraki orgs for MAC: {target_mac_display}")
else:
    print(f"Searching all accessible Meraki orgs for serial: {target_serial}")
print("This checks Meraki hardware, inventory, and clients seen in the last 31 days.")
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
    )

for org in orgs:
    org_id = org.get("id")
    org_name = org.get("name", "")
    print(f"Checking org: {org_name}")

    networks = []
    network_map = {}

    try:
        networks = dashboard.organizations.getOrganizationNetworks(
            org_id,
            total_pages="all"
        )
        for net in networks:
            network_map[net.get("id")] = net.get("name", "")
    except Exception as e:
        errors.append(f"{org_name}: could not list networks - {e}")

    # Search Meraki hardware devices assigned to networks.
    try:
        devices = dashboard.organizations.getOrganizationDevices(
            org_id,
            total_pages="all"
        )

        for device in devices:
            if not device_matches_search(device, search_type, target_mac_norm, target_serial):
                continue

            net_id = device.get("networkId", "")
            net_name = network_map.get(net_id, "")

            add_match(matches, {
                "Match Type": "Meraki Device",
                "Search Type": search_type,
                "Search Value": target_mac_display if search_type == "MAC" else target_serial,
                "Org": org_name,
                "Org ID": org_id,
                "Network": net_name,
                "Network ID": net_id,
                "Name": device.get("name", ""),
                "Model": device.get("model", ""),
                "Serial": device.get("serial", ""),
                "MAC": device.get("mac", ""),
                "LAN IP": device.get("lanIp", ""),
                "Public IP": device.get("publicIp", ""),
                "URL": device.get("url", "")
            })

    except Exception as e:
        errors.append(f"{org_name}: device search failed - {e}")

    # Search inventory devices, including devices that may not be assigned to a network.
    try:
        inventory = dashboard.organizations.getOrganizationInventoryDevices(
            org_id,
            total_pages="all"
        )

        for item in inventory:
            if not device_matches_search(item, search_type, target_mac_norm, target_serial):
                continue

            net_id = item.get("networkId", "")
            net_name = network_map.get(net_id, "")

            add_match(matches, {
                "Match Type": "Inventory Device",
                "Search Type": search_type,
                "Search Value": target_mac_display if search_type == "MAC" else target_serial,
                "Org": org_name,
                "Org ID": org_id,
                "Network": net_name,
                "Network ID": net_id,
                "Name": item.get("name", ""),
                "Model": item.get("model", ""),
                "Serial": item.get("serial", ""),
                "MAC": item.get("mac", ""),
                "LAN IP": "",
                "Public IP": "",
                "URL": item.get("url", "")
            })

    except Exception as e:
        errors.append(f"{org_name}: inventory search failed - {e}")

    # Search clients seen in each network within the last 31 days.
    for net in networks:
        net_id = net.get("id")
        net_name = net.get("name", "")
        print(f"  Searching clients: {net_name}")

        try:
            clients = dashboard.networks.getNetworkClients(
                net_id,
                timespan=CLIENT_TIMESPAN_SECONDS,
                perPage=5000,
                total_pages="all"
            )

            for client in clients:
                if not client_matches_search(client, search_type, target_mac_norm, target_serial):
                    continue

                add_match(matches, {
                    "Match Type": "Client",
                    "Search Type": search_type,
                    "Search Value": target_mac_display if search_type == "MAC" else target_serial,
                    "Org": org_name,
                    "Org ID": org_id,
                    "Network": net_name,
                    "Network ID": net_id,
                    "Name": client.get("description", ""),
                    "Model": "",
                    "Serial": client.get("serial", ""),
                    "MAC": client.get("mac", ""),
                    "LAN IP": client.get("ip", ""),
                    "Public IP": "",
                    "VLAN": client.get("vlan", ""),
                    "SSID": client.get("ssid", ""),
                    "Switchport": client.get("switchport", ""),
                    "Manufacturer": client.get("manufacturer", ""),
                    "OS": client.get("os", ""),
                    "Status": client.get("status", ""),
                    "First Seen": client.get("firstSeen", ""),
                    "Last Seen": client.get("lastSeen", ""),
                    "URL": f"https://dashboard.meraki.com/network/{net_id}/clients"
                })

        except Exception as e:
            errors.append(f"{org_name} | {net_name}: client search failed - {e}")

print("")

if matches:
    print("MATCHES FOUND:")
    print("")
    for m in matches:
        print(
            f'{m.get("Match Type", "")}: '
            f'{m.get("Org", "")} | '
            f'{m.get("Network", "")} | '
            f'{m.get("Name", "")} | '
            f'Model: {m.get("Model", "")} | '
            f'Serial: {m.get("Serial", "")} | '
            f'MAC: {m.get("MAC", "")} | '
            f'IP: {m.get("LAN IP", "")} | '
            f'URL: {m.get("URL", "")}'
        )

    csv_file = f"Meraki_Search_{search_type}_{safe_filename_value}.csv"
    all_fields = sorted(set().union(*(m.keys() for m in matches)))

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_fields)
        writer.writeheader()
        writer.writerows(matches)

    print("")
    print(f"Saved CSV: {csv_file}")

else:
    print("No matches found.")
    print("")
    print("Notes:")
    print("- Client history only goes back 31 days.")
    print("- Expired/unlicensed orgs may return 403 and cannot be searched by API.")
    print("- Serial search is most useful for Meraki hardware/inventory, not client devices.")
    print("- If a client MAC is behind another device/NAT or has never connected, it may not appear as a client.")

if errors:
    print("")
    print("Skipped/errors:")
    for err in errors:
        print(f" - {err}")
