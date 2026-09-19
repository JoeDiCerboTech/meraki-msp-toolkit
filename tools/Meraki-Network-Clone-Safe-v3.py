#!/usr/bin/env python3
"""
Meraki Network Clone - Safe Wrapper
===================================

Creates a new Meraki network by using the Dashboard API's native
copyFromNetworkId capability, but defaults to DRY RUN and performs a
post-clone review of settings that can be site-specific.

No third-party Python packages are required.

IMPORTANT:
- DRY RUN is the default.
- This script does NOT claim or move devices.
- It does NOT modify WAN/static device addressing.
- It does NOT automatically "fix" copied VLAN/VPN/NAT settings.
- Review the generated risk report BEFORE adding devices to the new network.\n- Source/target alert settings are captured and compared after cloning.\n- APPLY mode requires an explicit timezone decision.
"""

import argparse
import getpass
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib import request, error

BASE_URL = "https://api.meraki.com/api/v1"
USER_AGENT = "Meraki-MSP-Toolkit-Network-Clone/1.2"


class MerakiAPI:
    def __init__(self, api_key, max_retries=6):
        self.api_key = api_key
        self.max_retries = max_retries

    def _call(self, method, path, body=None, allow_error=False):
        url = path if path.startswith("http") else BASE_URL + path
        payload = None if body is None else json.dumps(body).encode("utf-8")

        headers = {
            "X-Cisco-Meraki-API-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        if body is not None:
            headers["Content-Type"] = "application/json"

        for attempt in range(1, self.max_retries + 1):
            req = request.Request(url, data=payload, headers=headers, method=method)
            try:
                with request.urlopen(req, timeout=90) as response:
                    raw = response.read()
                    if not raw:
                        return None
                    return json.loads(raw.decode("utf-8"))
            except error.HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                retry_after = exc.headers.get("Retry-After") if exc.headers else None

                if exc.code == 429 and attempt < self.max_retries:
                    try:
                        sleep_for = max(1, int(retry_after or "2"))
                    except ValueError:
                        sleep_for = 2
                    print(f"Meraki rate limit hit. Waiting {sleep_for} second(s)...")
                    time.sleep(sleep_for)
                    continue

                if allow_error:
                    return {
                        "_error": True,
                        "status": exc.code,
                        "message": raw or str(exc),
                        "path": path,
                    }

                raise RuntimeError(
                    f"Meraki API {method} {path} failed with HTTP {exc.code}: {raw}"
                ) from exc

            except error.URLError as exc:
                if attempt < self.max_retries:
                    time.sleep(2)
                    continue
                if allow_error:
                    return {
                        "_error": True,
                        "status": None,
                        "message": str(exc),
                        "path": path,
                    }
                raise RuntimeError(f"Meraki API connection failed: {exc}") from exc

        raise RuntimeError(f"Meraki API request failed after retries: {method} {path}")

    def get(self, path, allow_error=False):
        return self._call("GET", path, allow_error=allow_error)

    def post(self, path, body):
        return self._call("POST", path, body=body)


def get_api_key():
    key = os.getenv("MERAKI_DASHBOARD_API_KEY") or os.getenv("MERAKI_API_KEY")
    if key:
        return key.strip()

    print("No Meraki API key environment variable was found.")
    key = getpass.getpass("Enter Meraki Dashboard API key: ").strip()
    if not key:
        raise SystemExit("No API key supplied.")
    return key


def choose_from_list(items, label, display_fn):
    if not items:
        raise SystemExit(f"No {label} found.")

    print(f"\nAvailable {label}:")
    for index, item in enumerate(items, 1):
        print(f"  {index:>3}. {display_fn(item)}")

    while True:
        singular = label[:-1] if label.endswith("s") else label
        raw = input(f"Select {singular} [1-{len(items)}]: ").strip()
        try:
            selected = int(raw)
            if 1 <= selected <= len(items):
                return items[selected - 1]
        except ValueError:
            pass
        print("Invalid selection.")


def is_api_error(value):
    return isinstance(value, dict) and value.get("_error") is True


def canonicalize(value):
    """Create a stable representation for comparisons."""
    if isinstance(value, dict):
        return {k: canonicalize(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        normalized = [canonicalize(v) for v in value]
        try:
            return sorted(normalized, key=lambda v: json.dumps(v, sort_keys=True))
        except TypeError:
            return normalized
    return value


def collect_alert_snapshot(api, network):
    """Read and summarize a network's alert settings without changing them."""
    network_id = network["id"]
    settings = api.get(
        f"/networks/{network_id}/alerts/settings",
        allow_error=True,
    )

    if is_api_error(settings):
        return {
            "available": False,
            "error": settings,
            "totalAlertTypes": 0,
            "enabledAlertTypes": 0,
            "disabledAlertTypes": 0,
            "settings": None,
        }

    alerts = list(settings.get("alerts") or []) if isinstance(settings, dict) else []
    enabled = sum(1 for alert in alerts if alert.get("enabled") is True)

    return {
        "available": True,
        "error": None,
        "totalAlertTypes": len(alerts),
        "enabledAlertTypes": enabled,
        "disabledAlertTypes": len(alerts) - enabled,
        "settings": settings,
    }


def compare_alert_snapshots(source_snapshot, target_snapshot):
    """Compare source and target alert settings and return a human-readable summary."""
    result = {
        "comparable": False,
        "match": False,
        "defaultDestinationsMatch": False,
        "missingAlertTypes": [],
        "extraAlertTypes": [],
        "changedAlertTypes": [],
        "sourceSummary": {
            "total": source_snapshot.get("totalAlertTypes", 0),
            "enabled": source_snapshot.get("enabledAlertTypes", 0),
            "disabled": source_snapshot.get("disabledAlertTypes", 0),
        },
        "targetSummary": {
            "total": target_snapshot.get("totalAlertTypes", 0),
            "enabled": target_snapshot.get("enabledAlertTypes", 0),
            "disabled": target_snapshot.get("disabledAlertTypes", 0),
        },
    }

    if not source_snapshot.get("available") or not target_snapshot.get("available"):
        result["reason"] = "Source or target alert settings could not be read."
        return result

    source = source_snapshot["settings"] or {}
    target = target_snapshot["settings"] or {}

    result["comparable"] = True
    result["defaultDestinationsMatch"] = (
        canonicalize(source.get("defaultDestinations"))
        == canonicalize(target.get("defaultDestinations"))
    )

    source_by_type = {
        str(a.get("type")): a for a in (source.get("alerts") or []) if a.get("type")
    }
    target_by_type = {
        str(a.get("type")): a for a in (target.get("alerts") or []) if a.get("type")
    }

    source_types = set(source_by_type)
    target_types = set(target_by_type)

    result["missingAlertTypes"] = sorted(source_types - target_types)
    result["extraAlertTypes"] = sorted(target_types - source_types)

    for alert_type in sorted(source_types & target_types):
        if canonicalize(source_by_type[alert_type]) != canonicalize(target_by_type[alert_type]):
            result["changedAlertTypes"].append(alert_type)

    result["match"] = (
        result["defaultDestinationsMatch"]
        and not result["missingAlertTypes"]
        and not result["extraAlertTypes"]
        and not result["changedAlertTypes"]
    )
    return result


def print_alert_snapshot(label, snapshot):
    if not snapshot.get("available"):
        print(f"{label} alert settings: unable to read")
        return

    print(
        f"{label} alert settings: "
        f"{snapshot['totalAlertTypes']} types, "
        f"{snapshot['enabledAlertTypes']} enabled, "
        f"{snapshot['disabledAlertTypes']} disabled"
    )


def print_alert_comparison(comparison):
    print("\nAlert settings verification:")
    print("-" * 72)

    if not comparison.get("comparable"):
        print("UNABLE TO COMPARE - source or target alert settings could not be read.")
        print("-" * 72)
        return

    if comparison.get("match"):
        print("MATCH - the cloned network alert settings match the source network.")
    else:
        print("DIFFERENT - Meraki did not return an exact alert-settings match.")
        print(
            "Default destinations: "
            + ("MATCH" if comparison.get("defaultDestinationsMatch") else "DIFFERENT")
        )

        if comparison.get("missingAlertTypes"):
            print("Missing on target: " + ", ".join(comparison["missingAlertTypes"]))
        if comparison.get("extraAlertTypes"):
            print("Extra on target: " + ", ".join(comparison["extraAlertTypes"]))
        if comparison.get("changedAlertTypes"):
            print("Changed alert types: " + ", ".join(comparison["changedAlertTypes"]))

        print("No alert settings were overwritten automatically.")

    print("-" * 72)


def collect_risk_review(api, network):
    network_id = network["id"]
    products = set(network.get("productTypes") or [])
    findings = []
    raw = {}

    def add(severity, category, summary, details=None):
        findings.append({
            "severity": severity,
            "category": category,
            "summary": summary,
            "details": details,
        })

    if "appliance" in products:
        vlan_settings = api.get(
            f"/networks/{network_id}/appliance/vlans/settings",
            allow_error=True,
        )
        raw["vlanSettings"] = vlan_settings

        if not is_api_error(vlan_settings) and vlan_settings:
            if vlan_settings.get("vlansEnabled"):
                vlans = api.get(
                    f"/networks/{network_id}/appliance/vlans",
                    allow_error=True,
                )
                raw["vlans"] = vlans
                if not is_api_error(vlans) and isinstance(vlans, list):
                    copied_vlans = [
                        {
                            "id": v.get("id"),
                            "name": v.get("name"),
                            "subnet": v.get("subnet"),
                            "applianceIp": v.get("applianceIp"),
                        }
                        for v in vlans
                    ]
                    if copied_vlans:
                        add(
                            "HIGH",
                            "VLAN addressing",
                            f"{len(copied_vlans)} VLAN(s) are configured. Review subnets before connecting this site to routed/VPN networks.",
                            copied_vlans,
                        )
            else:
                single_lan = api.get(
                    f"/networks/{network_id}/appliance/singleLan",
                    allow_error=True,
                )
                raw["singleLan"] = single_lan
                if not is_api_error(single_lan) and single_lan:
                    add(
                        "HIGH",
                        "LAN addressing",
                        "Single-LAN addressing is configured. Review the subnet before connecting the new site.",
                        {
                            "subnet": single_lan.get("subnet"),
                            "applianceIp": single_lan.get("applianceIp"),
                        },
                    )

        vpn = api.get(
            f"/networks/{network_id}/appliance/vpn/siteToSiteVpn",
            allow_error=True,
        )
        raw["siteToSiteVpn"] = vpn
        if not is_api_error(vpn) and vpn:
            mode = str(vpn.get("mode", "none"))
            if mode.lower() != "none":
                add(
                    "HIGH",
                    "Site-to-site VPN",
                    f"AutoVPN/site-to-site VPN mode is '{mode}'. Review this before claiming or connecting an MX.",
                    vpn,
                )

        static_routes = api.get(
            f"/networks/{network_id}/appliance/staticRoutes",
            allow_error=True,
        )
        raw["staticRoutes"] = static_routes
        if not is_api_error(static_routes) and isinstance(static_routes, list) and static_routes:
            add(
                "HIGH",
                "Static routes",
                f"{len(static_routes)} static route(s) are configured.",
                [
                    {
                        "name": r.get("name"),
                        "subnet": r.get("subnet"),
                        "gatewayIp": r.get("gatewayIp"),
                        "enabled": r.get("enabled"),
                    }
                    for r in static_routes
                ],
            )

        nat_checks = [
            ("portForwardingRules", "Port forwarding",
             f"/networks/{network_id}/appliance/firewall/portForwardingRules"),
            ("oneToOneNatRules", "1:1 NAT",
             f"/networks/{network_id}/appliance/firewall/oneToOneNatRules"),
            ("oneToManyNatRules", "1:Many NAT",
             f"/networks/{network_id}/appliance/firewall/oneToManyNatRules"),
        ]

        for key, label, path in nat_checks:
            value = api.get(path, allow_error=True)
            raw[key] = value
            if is_api_error(value) or not value:
                continue

            rules = value.get("rules", []) if isinstance(value, dict) else []
            if rules:
                add(
                    "HIGH",
                    label,
                    f"{len(rules)} {label} rule(s) are configured. These are normally site-specific.",
                    rules,
                )

        l3_rules = api.get(
            f"/networks/{network_id}/appliance/firewall/l3FirewallRules",
            allow_error=True,
        )
        raw["applianceL3FirewallRules"] = l3_rules
        if not is_api_error(l3_rules) and isinstance(l3_rules, dict):
            rules = l3_rules.get("rules", [])
            if rules:
                add(
                    "MEDIUM",
                    "MX L3 firewall",
                    f"{len(rules)} custom MX L3 firewall rule(s) are configured. Review CIDRs for references to source-site networks.",
                    rules,
                )

    if "wireless" in products:
        ssids = api.get(
            f"/networks/{network_id}/wireless/ssids",
            allow_error=True,
        )
        raw["ssids"] = ssids
        if not is_api_error(ssids) and isinstance(ssids, list):
            enabled_ssids = [
                {
                    "number": s.get("number"),
                    "name": s.get("name"),
                    "enabled": s.get("enabled"),
                    "authMode": s.get("authMode"),
                    "encryptionMode": s.get("encryptionMode"),
                    "ipAssignmentMode": s.get("ipAssignmentMode"),
                    "useVlanTagging": s.get("useVlanTagging"),
                    "defaultVlanId": s.get("defaultVlanId"),
                }
                for s in ssids
                if s.get("enabled")
            ]
            if enabled_ssids:
                add(
                    "MEDIUM",
                    "Wireless SSIDs",
                    f"{len(enabled_ssids)} enabled SSID(s) found. Review authentication, VLAN tagging, and site-specific addressing before deployment.",
                    enabled_ssids,
                )

    netflow = api.get(f"/networks/{network_id}/netflow", allow_error=True)
    raw["netflow"] = netflow
    if not is_api_error(netflow) and isinstance(netflow, dict):
        collector = netflow.get("collectorIp")
        if collector:
            add(
                "MEDIUM",
                "NetFlow",
                "A NetFlow collector is configured. Meraki's native clone documentation says NetFlow is not copied, so verify this is intentional.",
                netflow,
            )

    if not findings:
        add(
            "INFO",
            "Review",
            "No high-risk site-specific settings were detected by this limited scan. Manual review is still required.",
        )

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 9))
    return {"findings": findings, "raw": raw}


def write_report(
    output_root,
    mode,
    org,
    source,
    target_name,
    payload,
    source_review,
    source_alerts,
    target=None,
    target_review=None,
    target_alerts=None,
    alert_comparison=None,
):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = Path(output_root).expanduser().resolve() / f"Meraki-Clone-{mode}-{stamp}"
    folder.mkdir(parents=True, exist_ok=True)

    summary = {
        "mode": mode,
        "organization": {"id": org.get("id"), "name": org.get("name")},
        "sourceNetwork": {
            "id": source.get("id"),
            "name": source.get("name"),
            "productTypes": source.get("productTypes"),
            "timeZone": source.get("timeZone"),
            "isBoundToConfigTemplate": source.get("isBoundToConfigTemplate"),
        },
        "targetName": target_name,
        "createPayload": payload,
        "targetNetwork": target,
        "alertSettingsMatch": (
            alert_comparison.get("match")
            if isinstance(alert_comparison, dict)
            else None
        ),
        "generatedAt": datetime.now().isoformat(timespec="seconds"),
    }

    (folder / "clone-summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    (folder / "source-risk-review.json").write_text(
        json.dumps(source_review, indent=2), encoding="utf-8"
    )
    (folder / "source-alert-settings.json").write_text(
        json.dumps(source_alerts, indent=2), encoding="utf-8"
    )

    if target_review is not None:
        (folder / "target-risk-review.json").write_text(
            json.dumps(target_review, indent=2), encoding="utf-8"
        )

    if target_alerts is not None:
        (folder / "target-alert-settings.json").write_text(
            json.dumps(target_alerts, indent=2), encoding="utf-8"
        )

    if alert_comparison is not None:
        (folder / "alert-comparison.json").write_text(
            json.dumps(alert_comparison, indent=2), encoding="utf-8"
        )

    return folder


def print_findings(review):
    print("\nRisk review:")
    print("-" * 72)
    for item in review["findings"]:
        print(f"[{item['severity']}] {item['category']}: {item['summary']}")
    print("-" * 72)


def parse_args():
    default_output = Path.home() / "Documents" / "Meraki-Clone-Reports"

    parser = argparse.ArgumentParser(
        description="Dry-run-first wrapper around Meraki's native network clone API."
    )
    parser.add_argument("--org-id", help="Meraki organization ID.")
    parser.add_argument("--source-network-id", help="Source Meraki network ID.")
    parser.add_argument("--target-name", help="Name for the new cloned network.")
    parser.add_argument(
        "--timezone",
        help="Override target timezone. Defaults to the source network timezone.",
    )
    parser.add_argument(
        "--copy-tags",
        action="store_true",
        help="Copy source network tags. Default is to create the target with no tags.",
    )
    parser.add_argument(
        "--keep-source-timezone",
        action="store_true",
        help="Explicitly allow APPLY mode to keep the source network timezone.",
    )
    parser.add_argument(
        "--notes",
        default="Created with Meraki Network Clone safe wrapper. Review site-specific settings before claiming devices.",
        help="Notes to place on the target network.",
    )
    parser.add_argument(
        "--output",
        default=str(default_output),
        help=f"Report output directory. Default: {default_output}",
    )
    parser.add_argument(
        "--public-display",
        action="store_true",
        help="Mask organization/network names and IDs in console output for screenshots/video.",
    )
    parser.add_argument(
        "--org-index",
        type=int,
        help="1-based organization number from the sorted list. Useful with --public-display.",
    )
    parser.add_argument(
        "--source-network-index",
        type=int,
        help="1-based network number from the sorted list. Useful with --public-display.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually create the cloned network. Without this switch, no network is created.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    api = MerakiAPI(get_api_key())

    print("\nMERAKI NETWORK CLONE - SAFE WRAPPER")
    print("=" * 72)
    print("Mode:", "APPLY" if args.apply else "DRY RUN")
    if args.public_display:
        print("Public display: ON (organization/network names and IDs are masked on screen)")
    if not args.apply:
        print("No Meraki network will be created in this mode.")

    orgs = api.get("/organizations?perPage=9000")
    if not isinstance(orgs, list):
        raise SystemExit("Unexpected organizations response from Meraki.")
    orgs = sorted(orgs, key=lambda x: (x.get("name") or "").lower())

    if args.org_id:
        org = next((x for x in orgs if str(x.get("id")) == args.org_id), None)
        if not org:
            raise SystemExit(f"Organization ID not found: {args.org_id}")
    elif args.org_index is not None:
        if args.org_index < 1 or args.org_index > len(orgs):
            raise SystemExit(f"--org-index must be between 1 and {len(orgs)}")
        org = orgs[args.org_index - 1]
        if args.public_display:
            print(f"\nOrganization selected: Organization {args.org_index:02d}")
        else:
            print(f"\nOrganization selected: {org.get('name')} [{org.get('id')}]")
    else:
        if args.public_display:
            org = choose_from_list(
                orgs,
                "organizations",
                lambda x: f"Organization {orgs.index(x) + 1:02d}",
            )
        else:
            org = choose_from_list(
                orgs,
                "organizations",
                lambda x: f"{x.get('name')}  [{x.get('id')}]",
            )

    networks = api.get(f"/organizations/{org['id']}/networks?perPage=1000")
    if not isinstance(networks, list):
        raise SystemExit("Unexpected networks response from Meraki.")
    networks = sorted(networks, key=lambda x: (x.get("name") or "").lower())

    if args.source_network_id:
        source = next(
            (x for x in networks if str(x.get("id")) == args.source_network_id),
            None,
        )
        if not source:
            raise SystemExit(
                "Source network ID was not found in the selected organization."
                if args.public_display else
                f"Source network ID was not found in '{org.get('name')}': {args.source_network_id}"
            )
    elif args.source_network_index is not None:
        if args.source_network_index < 1 or args.source_network_index > len(networks):
            raise SystemExit(f"--source-network-index must be between 1 and {len(networks)}")
        source = networks[args.source_network_index - 1]
        if args.public_display:
            print(f"Network selected: Source Network {args.source_network_index:02d}")
        else:
            print(f"Network selected: {source.get('name')} [{source.get('id')}]")
    else:
        if args.public_display:
            source = choose_from_list(
                networks,
                "networks",
                lambda x: (
                    f"Source Network {networks.index(x) + 1:02d} "
                    f"[{', '.join(x.get('productTypes') or [])}]"
                ),
            )
        else:
            source = choose_from_list(
                networks,
                "networks",
                lambda x: (
                    f"{x.get('name')}  "
                    f"[{', '.join(x.get('productTypes') or [])}]  "
                    f"[{x.get('id')}]"
                ),
            )

    if source.get("isBoundToConfigTemplate"):
        raise SystemExit(
            "Source network is bound to a configuration template. "
            "This first safe-clone version intentionally refuses template-bound sources."
        )

    target_name = (args.target_name or input("\nNew network name: ")).strip()
    if not target_name:
        raise SystemExit("Target network name cannot be blank.")

    duplicate = next(
        (x for x in networks if (x.get("name") or "").casefold() == target_name.casefold()),
        None,
    )
    if duplicate:
        if args.public_display:
            raise SystemExit(f"A network named '{target_name}' already exists in this organization.")
        raise SystemExit(
            f"A network named '{target_name}' already exists in this organization "
            f"(ID: {duplicate.get('id')})."
        )

    product_types = list(source.get("productTypes") or [])
    if not product_types:
        raise SystemExit("Source network has no productTypes; refusing to continue.")

    source_timezone = source.get("timeZone") or "UTC"

    if args.apply and not args.timezone and not args.keep_source_timezone:
        raise SystemExit(
            "APPLY mode requires an explicit timezone decision. "
            "Use --timezone <IANA_TIMEZONE> or --keep-source-timezone."
        )

    target_timezone = args.timezone or source_timezone

    payload = {
        "name": target_name,
        "productTypes": product_types,
        "timeZone": target_timezone,
        "copyFromNetworkId": source["id"],
        "tags": list(source.get("tags") or []) if args.copy_tags else [],
        "notes": args.notes,
    }

    print("\nClone plan:")
    if args.public_display:
        print("Organization:  Demo Organization")
        print("Source:        Source Network")
    else:
        print(f"Organization:  {org.get('name')} [{org.get('id')}]")
        print(f"Source:        {source.get('name')} [{source.get('id')}]")
    print(f"Products:      {', '.join(product_types)}")
    print(f"Target:        {target_name}")
    print(f"Source TZ:     {source_timezone}")
    print(f"Target TZ:     {payload['timeZone']}")
    if not args.timezone and not args.keep_source_timezone:
        print("Timezone note: dry run is using the source timezone; APPLY will require an explicit choice.")
    print(f"Tags:          {'copied' if args.copy_tags else 'NOT copied'}")
    print("\nMeraki create payload:")
    display_payload = dict(payload)
    if args.public_display:
        display_payload["copyFromNetworkId"] = "SOURCE_NETWORK_ID_HIDDEN"
    print(json.dumps(display_payload, indent=2))

    print("\nScanning SOURCE for site-specific settings that may be inherited...")
    source_review = collect_risk_review(api, source)
    print_findings(source_review)

    print("\nCapturing SOURCE alert settings for post-clone verification...")
    source_alerts = collect_alert_snapshot(api, source)
    print_alert_snapshot("Source", source_alerts)

    if not args.apply:
        report_folder = write_report(
            args.output,
            "DRY-RUN",
            org,
            source,
            target_name,
            payload,
            source_review,
            source_alerts,
        )
        print(f"\nDry-run report saved to:\n  {report_folder}")
        print("\nNO NETWORK WAS CREATED.")
        print(
            "\nWhen ready, run the same command with --apply. "
            "You will still be required to type CREATE."
        )
        return 0

    print("\nAPPLY MODE")
    print("This will CREATE a new network in Meraki Dashboard.")
    print("It will NOT claim or move any devices.")
    confirmation = input("Type CREATE to continue: ").strip()
    if confirmation != "CREATE":
        print("Cancelled. No network was created.")
        return 0

    created = api.post(f"/organizations/{org['id']}/networks", payload)
    if not isinstance(created, dict) or not created.get("id"):
        raise RuntimeError(f"Unexpected create-network response: {created}")

    print("\nNETWORK CREATED")
    print(f"Name: {created.get('name')}")
    if args.public_display:
        print("ID:   [hidden]")
        if created.get("url"):
            print("URL:  [hidden]")
    else:
        print(f"ID:   {created.get('id')}")
        if created.get("url"):
            print(f"URL:  {created.get('url')}")

    print("\nReading the new network back and running post-clone risk review...")
    target = api.get(f"/networks/{created['id']}")
    target_review = collect_risk_review(api, target)
    print_findings(target_review)

    print("\nReading TARGET alert settings and comparing them to the source...")
    target_alerts = collect_alert_snapshot(api, target)
    print_alert_snapshot("Target", target_alerts)
    alert_comparison = compare_alert_snapshots(source_alerts, target_alerts)
    print_alert_comparison(alert_comparison)

    report_folder = write_report(
        args.output,
        "APPLY",
        org,
        source,
        target_name,
        payload,
        source_review,
        source_alerts,
        target=target,
        target_review=target_review,
        target_alerts=target_alerts,
        alert_comparison=alert_comparison,
    )

    print(f"\nApply report saved to:\n  {report_folder}")
    print("\nNEXT STEP:")
    print("Review every HIGH/MEDIUM item before claiming or moving devices into the new network.")
    if alert_comparison.get("match"):
        print("Alert verification: MATCH")
    else:
        print("Alert verification: DIFFERENT - review alert-comparison.json before changing alerts.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        sys.exit(1)
