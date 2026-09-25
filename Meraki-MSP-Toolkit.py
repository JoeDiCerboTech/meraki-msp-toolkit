#!/usr/bin/env python3
"""Meraki MSP Toolkit v0.2.2

Single-window controller for Meraki MSP automation tools.
- Standard-library only (Tkinter + urllib)
- API key is held in memory only; it is never written to disk
- Destructive/write actions default to DRY RUN and require typed confirmation

v0.1 native modules:
- Device Search
- License Audit
- SSID Security Audit
- Alert Baseline Review / Apply
- Network Builder (No Clone or Clone Existing) with guarded LAN/VLAN addressing
- Post-Build workspace: alerts, site/location, wireless, switches, appliance inspection, and scoped compliance
- Guarded network deletion with hardware disposition (Holding / keep customer inventory / unclaim) and exact-ID verification
- Hardware / Inventory: Holding outbound/return, guarded brand-new hardware claim, and client-offboarding unclaim + verify
- Admin Access: add/change admins, selected-network access, removal, and all-org employee offboarding
- Native Organization Cleanup audit / guarded org deletion

Bundled safe launchers:
- Multi-Org Compliance Report
- Legacy Network Clone safe wrapper
"""
from __future__ import annotations

import csv
import hashlib
import datetime as dt
import json
import ipaddress
import os
import queue
import re
import subprocess
import sys
import threading
import traceback
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog

APP_NAME = "Meraki MSP Toolkit"
APP_VERSION = "0.2.2"
BASE_URL = "https://api.meraki.com/api/v1"
ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / "tools"
REPORTS = ROOT / "Reports"
REPORTS.mkdir(exist_ok=True)

REQUIRED_ALERTS = {
    "applianceDown": "MX unreachable",
    "dhcpNoLeases": "MX DHCP pool exhausted",
    "rogueDhcp": "Rogue DHCP server detected",
    "ampMalwareBlocked": "Malware download blocked",
    "ampMalwareDetected": "Downloaded content later identified as malware",
    "switchDown": "Switch unreachable",
    "newDhcpServer": "New DHCP server detected",
    "powerSupplyDown": "Switch power supply failure",
    "rpsBackup": "Redundant power supply active",
    "udldError": "UDLD error",
    "switchCriticalTemperature": "Critical switch temperature",
    "gatewayDown": "Gateway AP unreachable",
    "repeaterDown": "Repeater AP unreachable",
    "gatewayToRepeater": "Wired AP fell back to repeater",
    "cameraDown": "Camera unreachable",
    "cellularGatewayDown": "Cellular gateway unreachable",
    "nodeHardwareFailure": "Node hardware failure",
    "sensorDown": "Sensor unreachable",
    "sensorBatteryPercentage": "Sensor low battery",
    "pccExpiredApnsCert": "APNS certificate expiration",
}
OFFLINE_ALERT_TYPES = {
    "applianceDown", "switchDown", "gatewayDown", "repeaterDown",
    "cameraDown", "cellularGatewayDown", "sensorDown",
}


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "report"


def nowstamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def norm_mac(value: str) -> str:
    return re.sub(r"[^0-9a-f]", "", value.lower())


def norm_serial(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", value.upper())


SITE_ADDRESS_PREFIX = "Site Address:"
SITE_JSON_PREFIX = "[MSP_SITE_JSON]"
SITE_KEYS = ("street", "line2", "city", "state", "postal", "country")


def normalize_site_address(site) -> dict:
    site = site or {}
    return {key: str(site.get(key) or "").strip() for key in SITE_KEYS}


def format_site_address(site) -> str:
    site = normalize_site_address(site)
    if not any(site[key] for key in ("street", "line2", "city", "state", "postal")):
        return ""
    parts = []
    if site["street"]:
        parts.append(site["street"])
    if site["line2"]:
        parts.append(site["line2"])
    if site["city"]:
        parts.append(site["city"])
    region = " ".join(x for x in (site["state"], site["postal"]) if x)
    if region:
        parts.append(region)
    if site["country"]:
        parts.append(site["country"])
    return ", ".join(parts)


def notes_with_site_address(notes: str, site) -> str:
    """Preserve user notes while maintaining a readable + machine-readable site address marker."""
    cleaned = []
    for line in str(notes or "").splitlines():
        stripped = line.strip()
        if stripped.startswith(SITE_ADDRESS_PREFIX) or stripped.startswith(SITE_JSON_PREFIX):
            continue
        cleaned.append(line.rstrip())
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()
    site = normalize_site_address(site)
    full = format_site_address(site)
    if full:
        if cleaned:
            cleaned.append("")
        cleaned.append(f"{SITE_ADDRESS_PREFIX} {full}")
        cleaned.append(SITE_JSON_PREFIX + json.dumps(site, separators=(",", ":"), ensure_ascii=False))
    return "\n".join(cleaned).strip()


def site_address_from_notes(notes: str) -> dict:
    raw = str(notes or "")
    readable = ""
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith(SITE_JSON_PREFIX):
            try:
                data = json.loads(stripped[len(SITE_JSON_PREFIX):])
                site = normalize_site_address(data)
                if format_site_address(site):
                    return site
            except Exception:
                pass
        if stripped.startswith(SITE_ADDRESS_PREFIX):
            readable = stripped[len(SITE_ADDRESS_PREFIX):].strip()
    if readable:
        # Legacy/fallback marker: keep the full address intact in the first field.
        return normalize_site_address({"street": readable})
    return normalize_site_address({})


class MerakiAPI:
    def __init__(self, api_key: str):
        self.api_key = api_key.strip()

    def request(self, method: str, path: str, body=None, timeout=45):
        url = path if path.startswith("http") else BASE_URL + path
        data = None
        headers = {
            "X-Cisco-Meraki-API-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": f"Meraki-MSP-Toolkit/{APP_VERSION}",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        for attempt in range(6):
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read()
                    if not raw:
                        return None
                    return json.loads(raw.decode("utf-8"))
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                if exc.code == 429 and attempt < 5:
                    try:
                        wait = max(float(exc.headers.get("Retry-After", "2")), 1.0)
                    except ValueError:
                        wait = 2.0
                    time.sleep(wait)
                    continue
                raise RuntimeError(f"HTTP {exc.code}: {raw or exc.reason}") from exc
            except urllib.error.URLError as exc:
                raise RuntimeError(f"Connection failed: {exc}") from exc
        raise RuntimeError("Meraki API retry limit reached")

    def get(self, path: str):
        return self.request("GET", path)

    def post(self, path: str, body=None):
        return self.request("POST", path, body)

    def put(self, path: str, body=None):
        return self.request("PUT", path, body)

    def delete(self, path: str, body=None):
        return self.request("DELETE", path, body)

    def get_all(self, path: str, per_page=1000):
        sep = "&" if "?" in path else "?"
        url = f"{path}{sep}perPage={per_page}"
        out = []
        while url:
            full = url if url.startswith("http") else BASE_URL + url
            req = urllib.request.Request(
                full,
                headers={
                    "X-Cisco-Meraki-API-Key": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": f"Meraki-MSP-Toolkit/{APP_VERSION}",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=45) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    if isinstance(data, list):
                        out.extend(data)
                    else:
                        return data
                    link = resp.headers.get("Link", "")
                    m = re.search(r'<([^>]+)>;\s*rel="next"', link)
                    url = m.group(1) if m else ""
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"HTTP {exc.code}: {raw or exc.reason}") from exc
        return out


class Toolkit(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1420x900")
        self.minsize(1180, 760)
        self.configure(bg="#0f141c")
        self.api: MerakiAPI | None = None
        self.orgs = []
        self.networks = []
        self.holding_org = None
        self.holding_networks = []
        self.current_identity = {}
        self.work_q = queue.Queue()
        self.status_var = tk.StringVar(value="Not connected")
        self.selected_org_var = tk.StringVar(value="ALL ORGANIZATIONS")
        self.public_var = tk.BooleanVar(value=False)
        self.search_busy = False
        self._configure_style()
        self._build_shell()
        self._install_context_menus()
        self.after(100, self._drain_queue)

    def report_callback_exception(self, exc, val, tb):
        """Log unhandled Tk callback errors when the GUI is launched without a console."""
        try:
            log_dir = ROOT / "Logs"
            log_dir.mkdir(exist_ok=True)
            log_path = log_dir / "Meraki-MSP-Toolkit-crash.log"
            stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"\n[{stamp}] Unhandled Tk callback exception\n")
                traceback.print_exception(exc, val, tb, file=fh)
            messagebox.showerror(
                "Meraki MSP Toolkit error",
                f"An unexpected error occurred.\n\nDetails were written to:\n{log_path}",
            )
        except Exception:
            traceback.print_exception(exc, val, tb)

    def _install_context_menus(self):
        """Add Windows-style right-click editing menus to text-entry controls."""
        self.bind_class("TEntry", "<Button-3>", self._show_text_context_menu, add="+")
        self.bind_class("Entry", "<Button-3>", self._show_text_context_menu, add="+")
        self.bind_class("Text", "<Button-3>", self._show_text_context_menu, add="+")

    def _show_text_context_menu(self, event):
        widget = event.widget
        try:
            widget.focus_set()
            # Put the insertion cursor near the click when the widget supports it.
            if isinstance(widget, tk.Text):
                widget.mark_set("insert", f"@{event.x},{event.y}")
            else:
                try:
                    widget.icursor(widget.index(f"@{event.x}"))
                except Exception:
                    pass
        except Exception:
            pass

        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Cut", command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_command(label="Copy", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Paste", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_separator()

        def select_all():
            try:
                if isinstance(widget, tk.Text):
                    widget.tag_add("sel", "1.0", "end-1c")
                    widget.mark_set("insert", "1.0")
                    widget.see("insert")
                else:
                    widget.selection_range(0, "end")
                    widget.icursor("end")
            except Exception:
                pass

        menu.add_command(label="Select All", command=select_all)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return "break"

    def _configure_style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TFrame", background="#0f141c")
        s.configure("Panel.TFrame", background="#171f2a")
        s.configure("TLabel", background="#0f141c", foreground="#eaf0f6", font=("Segoe UI", 10))
        s.configure("Muted.TLabel", background="#0f141c", foreground="#9eacbb")
        s.configure("Panel.TLabel", background="#171f2a", foreground="#eaf0f6")
        s.configure("Title.TLabel", background="#0f141c", foreground="#ffffff", font=("Segoe UI Semibold", 23))
        s.configure("Section.TLabel", background="#171f2a", foreground="#ffffff", font=("Segoe UI Semibold", 14))
        s.configure("TButton", font=("Segoe UI Semibold", 10), padding=(10, 7))
        s.configure("Accent.TButton", background="#2d7ff9", foreground="white")
        s.map("Accent.TButton", background=[("active", "#4b92ff")])
        s.configure("Danger.TButton", background="#9d2d35", foreground="white")
        s.map("Danger.TButton", background=[("active", "#ba3a44")])
        s.configure("TCheckbutton", background="#0f141c", foreground="#eaf0f6")
        s.configure("Panel.TCheckbutton", background="#171f2a", foreground="#eaf0f6")
        s.configure("TNotebook", background="#0f141c", borderwidth=0)
        s.configure("TNotebook.Tab", padding=(12, 8), background="#1a2430", foreground="#dce6ef")
        s.map("TNotebook.Tab", background=[("selected", "#263646")])
        s.configure("Treeview", background="#111821", fieldbackground="#111821", foreground="#eaf0f6", rowheight=25)
        s.configure("Treeview.Heading", background="#263646", foreground="#ffffff", font=("Segoe UI Semibold", 9))

    def _build_shell(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=18, pady=(16, 8))
        ttk.Label(top, text="MERAKI MSP TOOLKIT", style="Title.TLabel").pack(side="left")
        ttk.Label(top, text=f"Video 9 build · v{APP_VERSION}", style="Muted.TLabel").pack(side="left", padx=12, pady=(9, 0))

        connect = ttk.Frame(self, style="Panel.TFrame")
        connect.pack(fill="x", padx=18, pady=6)
        ttk.Label(connect, text="Meraki API key", style="Panel.TLabel").pack(side="left", padx=(14, 8), pady=12)
        self.key_entry = ttk.Entry(connect, width=50, show="•")
        self.key_entry.pack(side="left", pady=12)
        self.connect_button = ttk.Button(connect, text="Connect / Refresh", style="Accent.TButton", command=self.connect)
        self.connect_button.pack(side="left", padx=8)
        ttk.Label(connect, textvariable=self.status_var, style="Panel.TLabel").pack(side="left", padx=10)
        ttk.Checkbutton(connect, text="Public display", variable=self.public_var, style="Panel.TCheckbutton").pack(side="right", padx=14)

        scope = ttk.Frame(self)
        scope.pack(fill="x", padx=18, pady=(3, 8))
        ttk.Label(scope, text="Organization:").pack(side="left")
        self.org_combo = ttk.Combobox(scope, textvariable=self.selected_org_var, width=70, state="readonly")
        self.org_combo["values"] = ["ALL ORGANIZATIONS"]
        self.org_combo.pack(side="left", padx=8)
        self.org_combo.bind("<<ComboboxSelected>>", lambda e: self.on_org_change())

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=18, pady=(0, 8))
        self._build_home()
        self._build_search()
        self._build_license()
        self._build_ssid()
        self._build_alerts()
        self._build_builder()
        self._build_postbuild()
        self._build_network_cleanup()
        self._build_holding()
        self._build_admin_access()
        self._build_org_cleanup()
        self._build_launchers()

        logwrap = ttk.Frame(self, style="Panel.TFrame")
        logwrap.pack(fill="both", padx=18, pady=(0, 14))
        loghead = ttk.Frame(logwrap, style="Panel.TFrame")
        loghead.pack(fill="x")
        ttk.Label(loghead, text="Activity log", style="Panel.TLabel").pack(side="left", padx=10, pady=6)
        ttk.Button(loghead, text="Clear", command=lambda: self.log.delete("1.0", "end")).pack(side="right", padx=8, pady=4)
        self.log = tk.Text(logwrap, height=9, bg="#0b1016", fg="#d7e1ea", insertbackground="white", relief="flat", font=("Cascadia Mono", 9), wrap="word")
        self.log.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.write_log("Toolkit ready. API key is never saved to disk.")

    def _panel(self, title, subtitle=""):
        f = ttk.Frame(self.nb, style="Panel.TFrame")
        head = ttk.Frame(f, style="Panel.TFrame")
        head.pack(fill="x", padx=18, pady=(18, 10))
        ttk.Label(head, text=title, style="Section.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(head, text=subtitle, style="Panel.TLabel").pack(anchor="w", pady=(4, 0))
        return f

    def _build_home(self):
        f = self._panel("One Meraki session. Multiple tools.", "Connect once, select an organization, then run read-only audits or guarded changes.")
        self.nb.add(f, text="Home")
        grid = ttk.Frame(f, style="Panel.TFrame")
        grid.pack(fill="both", expand=True, padx=18, pady=10)
        items = [
            ("Compliance Audit", "Read-only multi-org compliance report", "Read only"),
            ("Alert Baseline", "Review and standardize approved alert settings", "Dry run first"),
            ("Device Search", "Find hardware, inventory, and recent clients", "Read only"),
            ("SSID Security", "Audit enabled SSIDs and weak security modes", "Read only"),
            ("Licensing", "Review license state and expirations", "Read only"),
            ("Network Builder", "Existing or new org + guarded network creation", "Dry run first"),
            ("Post-Build Setup", "Alerts, site/location, wireless, switch management, appliance inspection, and scoped compliance", "Dry run + verify"),
            ("Delete Network", "Hardware disposition + exact-ID verified deletion", "Dry run + typed delete"),
            ("Hardware / Inventory", "Move existing hardware, return to Holding, or claim brand-new serials", "Dry run + verify"),
            ("Admin Access", "Add/change admins, network-scoped access, or offboard an employee everywhere", "Dry run + verify"),
            ("Org Cleanup", "Audit blockers, remove extra admins, then delete only when safe", "Audit + typed confirmation"),
        ]
        for i, (name, desc, guard) in enumerate(items):
            r, c = divmod(i, 2)
            card = tk.Frame(grid, bg="#111821", highlightbackground="#293646", highlightthickness=1)
            card.grid(row=r, column=c, sticky="nsew", padx=7, pady=7)
            tk.Label(card, text=name, bg="#111821", fg="white", font=("Segoe UI Semibold", 13)).pack(anchor="w", padx=14, pady=(12, 4))
            tk.Label(card, text=desc, bg="#111821", fg="#9eacbb", font=("Segoe UI", 9)).pack(anchor="w", padx=14)
            tk.Label(card, text=guard, bg="#111821", fg="#52df88", font=("Segoe UI Semibold", 9)).pack(anchor="w", padx=14, pady=(7, 12))
        for n in range(2): grid.columnconfigure(n, weight=1)
        for n in range(6): grid.rowconfigure(n, weight=1)

    def _build_search(self):
        f = self._panel("Device Search", "Search selected organization or all organizations for a Meraki serial/MAC. Optional recent-client search covers the last 31 days.")
        self.nb.add(f, text="Device Search")
        bar = ttk.Frame(f, style="Panel.TFrame"); bar.pack(fill="x", padx=18, pady=6)
        self.search_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.search_var, width=38).pack(side="left")
        self.search_clients_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Include recent clients", variable=self.search_clients_var, style="Panel.TCheckbutton").pack(side="left", padx=10)
        self.search_button = ttk.Button(bar, text="Search", style="Accent.TButton", command=self.search_devices)
        self.search_button.pack(side="left")
        self.search_status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.search_status_var, style="Panel.TLabel").pack(side="left", padx=12)
        cols = ("type","org","network","name","model","serial","mac","ip")
        self.search_tree = ttk.Treeview(f, columns=cols, show="headings", height=14)
        for c, w in zip(cols, (90,180,180,150,90,130,130,120)):
            self.search_tree.heading(c, text=c.title()); self.search_tree.column(c, width=w, anchor="w")
        self.search_tree.pack(fill="both", expand=True, padx=18, pady=10)

    def _build_license(self):
        f = self._panel("License Audit", "Reads the current licensing overview for the selected scope and exports a CSV.")
        self.nb.add(f, text="Licensing")
        bar = ttk.Frame(f, style="Panel.TFrame"); bar.pack(fill="x", padx=18, pady=8)
        self.license_button = ttk.Button(bar, text="Run License Audit", style="Accent.TButton", command=self.run_license_audit)
        self.license_button.pack(side="left")
        self.license_status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.license_status_var, style="Panel.TLabel").pack(side="left", padx=12)
        cols=("org","status","expiration","days","active","expiring","expired")
        self.lic_tree=ttk.Treeview(f, columns=cols, show="headings", height=15)
        for c,w in zip(cols,(220,150,170,90,80,80,80)):
            self.lic_tree.heading(c,text=c.title()); self.lic_tree.column(c,width=w,anchor="w")
        self.lic_tree.pack(fill="both",expand=True,padx=18,pady=10)

    def _build_ssid(self):
        f = self._panel("SSID Security Audit", "Read-only wireless audit for open, WEP, WPA1/mixed, PSK and enterprise configurations.")
        self.nb.add(f, text="SSID Security")
        bar = ttk.Frame(f, style="Panel.TFrame"); bar.pack(fill="x", padx=18, pady=8)
        self.ssid_button = ttk.Button(bar, text="Run SSID Audit", style="Accent.TButton", command=self.run_ssid_audit)
        self.ssid_button.pack(side="left")
        self.ssid_status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.ssid_status_var, style="Panel.TLabel").pack(side="left", padx=12)
        cols=("risk","org","network","ssid","enabled","auth","encryption","wpa")
        self.ssid_tree=ttk.Treeview(f, columns=cols, show="headings", height=15)
        for c,w in zip(cols,(90,180,180,160,70,130,110,160)):
            self.ssid_tree.heading(c,text=c.title()); self.ssid_tree.column(c,width=w,anchor="w")
        self.ssid_tree.pack(fill="both",expand=True,padx=18,pady=10)

    def _build_alerts(self):
        f = self._panel("Alert Baseline", "Compare selected networks against the approved core-alert baseline. Apply preserves destinations and only changes approved alert enable/timeout fields.")
        self.nb.add(f, text="Alerts")
        row=ttk.Frame(f,style="Panel.TFrame"); row.pack(fill="x",padx=18,pady=6)
        ttk.Label(row,text="Network",style="Panel.TLabel").pack(side="left")
        self.alert_net_var=tk.StringVar()
        self.alert_net_combo=ttk.Combobox(row,textvariable=self.alert_net_var,width=55,state="readonly"); self.alert_net_combo.pack(side="left",padx=8)
        self.settings_changed_var=tk.BooleanVar(value=False)
        ttk.Checkbutton(row,text="Require Settings Changed alert",variable=self.settings_changed_var,style="Panel.TCheckbutton").pack(side="left",padx=8)
        ttk.Label(row,text="Offline timeout",style="Panel.TLabel").pack(side="left",padx=(12,4))
        self.timeout_var=tk.StringVar(value="5"); ttk.Entry(row,textvariable=self.timeout_var,width=5).pack(side="left")
        self.alert_dry_button = ttk.Button(row,text="Dry Run",command=self.alert_dry_run)
        self.alert_dry_button.pack(side="left",padx=8)
        self.alert_apply_button = ttk.Button(row,text="Apply",style="Danger.TButton",command=self.alert_apply)
        self.alert_apply_button.pack(side="left")
        self.alert_status_var = tk.StringVar(value="Ready")
        ttk.Label(row,textvariable=self.alert_status_var,style="Panel.TLabel").pack(side="left",padx=12)
        self.alert_text=tk.Text(f,bg="#0b1016",fg="#d7e1ea",insertbackground="white",font=("Cascadia Mono",9),relief="flat")
        self.alert_text.pack(fill="both",expand=True,padx=18,pady=10)

    def _build_builder(self):
        f = self._panel("Network Builder", "Create a network in an existing organization or create a brand-new organization first. Preview is mandatory before Apply.")
        self.nb.add(f, text="Network Builder")
        form=ttk.Frame(f,style="Panel.TFrame"); form.pack(fill="x",padx=18,pady=6)

        ttk.Label(form,text="Destination",style="Panel.TLabel").grid(row=0,column=0,sticky="w",pady=4)
        self.build_destination=tk.StringVar(value="Existing Organization")
        self.build_destination_combo=ttk.Combobox(
            form,textvariable=self.build_destination,
            values=["Existing Organization","New Organization"],state="readonly",width=24
        )
        self.build_destination_combo.grid(row=0,column=1,sticky="w",padx=8)
        self.build_destination.trace_add("write",lambda *_: self._builder_destination_changed())
        self.builder_destination_help_var=tk.StringVar(value="Uses the organization selected at the top of the window.")
        ttk.Label(form,textvariable=self.builder_destination_help_var,style="Panel.TLabel").grid(row=0,column=2,sticky="w",padx=8)

        ttk.Label(form,text="New organization name",style="Panel.TLabel").grid(row=1,column=0,sticky="w",pady=4)
        self.build_new_org_name=tk.StringVar()
        self.build_new_org_entry=ttk.Entry(form,textvariable=self.build_new_org_name,width=45,state="disabled")
        self.build_new_org_entry.grid(row=1,column=1,sticky="w",padx=8)

        ttk.Label(form,text="Additional admins",style="Panel.TLabel").grid(row=2,column=0,sticky="nw",pady=4)
        admins_box=ttk.Frame(form,style="Panel.TFrame")
        admins_box.grid(row=2,column=1,sticky="w",padx=8,pady=2)

        ttk.Label(admins_box,text="Name",style="Panel.TLabel").grid(row=0,column=0,sticky="w")
        ttk.Label(admins_box,text="Email",style="Panel.TLabel").grid(row=0,column=1,sticky="w",padx=(8,0))
        ttk.Label(admins_box,text="Access",style="Panel.TLabel").grid(row=0,column=2,sticky="w",padx=(8,0))

        self.build_admin_name=tk.StringVar()
        self.build_admin_email=tk.StringVar()
        self.build_admin_access=tk.StringVar(value="full")
        self.build_admin_name_entry=ttk.Entry(admins_box,textvariable=self.build_admin_name,width=24,state="disabled")
        self.build_admin_email_entry=ttk.Entry(admins_box,textvariable=self.build_admin_email,width=32,state="disabled")
        self.build_admin_access_combo=ttk.Combobox(
            admins_box,textvariable=self.build_admin_access,
            values=["full","read-only","enterprise","none"],state="disabled",width=14
        )
        self.build_admin_name_entry.grid(row=1,column=0,sticky="w")
        self.build_admin_email_entry.grid(row=1,column=1,sticky="w",padx=(8,0))
        self.build_admin_access_combo.grid(row=1,column=2,sticky="w",padx=(8,0))
        self.build_admin_add_button=ttk.Button(admins_box,text="Add Admin",command=self._builder_add_admin,state="disabled")
        self.build_admin_add_button.grid(row=1,column=3,sticky="w",padx=(8,0))
        self.build_admin_remove_button=ttk.Button(admins_box,text="Remove Selected",command=self._builder_remove_admin,state="disabled")
        self.build_admin_remove_button.grid(row=1,column=4,sticky="w",padx=(8,0))

        self.build_admin_tree=ttk.Treeview(
            admins_box,columns=("name","email","access"),show="headings",height=3
        )
        self.build_admin_tree.heading("name",text="Name")
        self.build_admin_tree.heading("email",text="Email")
        self.build_admin_tree.heading("access",text="Access")
        self.build_admin_tree.column("name",width=175,anchor="w")
        self.build_admin_tree.column("email",width=245,anchor="w")
        self.build_admin_tree.column("access",width=100,anchor="w")
        self.build_admin_tree.grid(row=2,column=0,columnspan=5,sticky="w",pady=(6,0))
        self.pending_admins=[]

        ttk.Label(
            form,
            text="Optional for new orgs. Enter Name, Email and Access, then click Add Admin. Add as many as needed.",
            style="Panel.TLabel"
        ).grid(row=2,column=2,sticky="nw",padx=8,pady=4)

        ttk.Label(form,text="Mode",style="Panel.TLabel").grid(row=3,column=0,sticky="w",pady=4)
        self.build_mode=tk.StringVar(value="No Clone")
        self.build_mode_combo=ttk.Combobox(form,textvariable=self.build_mode,values=["No Clone","Clone Existing"],state="readonly",width=22)
        self.build_mode_combo.grid(row=3,column=1,sticky="w",padx=8)
        self.build_mode.trace_add("write",lambda *_: self._builder_mode_changed())

        ttk.Label(form,text="Network name",style="Panel.TLabel").grid(row=4,column=0,sticky="w",pady=4)
        self.build_name=tk.StringVar(); self.build_name_entry=ttk.Entry(form,textvariable=self.build_name,width=45); self.build_name_entry.grid(row=4,column=1,sticky="w",padx=8)
        ttk.Label(form,text="Timezone",style="Panel.TLabel").grid(row=5,column=0,sticky="w",pady=4)
        self.build_tz=tk.StringVar(value="America/New_York"); self.build_tz_entry=ttk.Entry(form,textvariable=self.build_tz,width=30); self.build_tz_entry.grid(row=5,column=1,sticky="w",padx=8)
        ttk.Label(form,text="Clone source",style="Panel.TLabel").grid(row=6,column=0,sticky="w",pady=4)
        self.build_source=tk.StringVar(); self.build_source_combo=ttk.Combobox(form,textvariable=self.build_source,width=55,state="disabled"); self.build_source_combo.grid(row=6,column=1,sticky="w",padx=8)
        self.build_source.trace_add("write",lambda *_: self._builder_source_changed())
        ttk.Label(form,text="Products (No Clone)",style="Panel.TLabel").grid(row=7,column=0,sticky="nw",pady=4)
        prods=ttk.Frame(form,style="Panel.TFrame"); prods.grid(row=7,column=1,sticky="w",padx=8)
        self.product_vars={}
        self.product_checkbuttons={}
        labels=[("appliance","MX / Z / Teleworker"),("switch","Switch"),("wireless","Wireless"),("camera","Camera"),("sensor","Sensor"),("cellularGateway","Cellular Gateway")]
        for i,(p,label) in enumerate(labels):
            v=tk.BooleanVar(value=(p in {"appliance","switch","wireless"})); self.product_vars[p]=v
            cb=ttk.Checkbutton(
                prods,text=label,variable=v,style="Panel.TCheckbutton",
                command=self._builder_products_changed
            )
            cb.grid(row=i//3,column=i%3,sticky="w",padx=(0,12))
            self.product_checkbuttons[p]=cb

        ttk.Label(form,text="Addressing",style="Panel.TLabel").grid(row=8,column=0,sticky="w",pady=4)
        addr_box=ttk.Frame(form,style="Panel.TFrame")
        addr_box.grid(row=8,column=1,sticky="w",padx=8,pady=2)
        self.build_addressing_mode=tk.StringVar(value="Choose...")
        self.build_addressing_combo=ttk.Combobox(
            addr_box,textvariable=self.build_addressing_mode,
            values=["Choose...","VLANs","Single LAN","Skip for now"],state="readonly",width=18
        )
        self.build_addressing_combo.pack(side="left")
        self.build_addressing_combo.bind("<<ComboboxSelected>>",lambda e:self._builder_addressing_changed())
        self.build_addressing_button=ttk.Button(addr_box,text="Configure...",command=self._builder_configure_addressing)
        self.build_addressing_button.pack(side="left",padx=(8,0))
        self.build_addressing_summary_var=tk.StringVar(value="Choose how MX/Z addressing should be configured.")
        ttk.Label(form,textvariable=self.build_addressing_summary_var,style="Panel.TLabel").grid(row=8,column=2,sticky="w",padx=8,pady=4)
        self.builder_vlans=[]
        self.builder_vlan_allow_non_rfc1918=False
        self.builder_single_lan={"subnet":"","applianceIp":"","allowNonRfc1918":False}

        ttk.Label(form,text="Physical site",style="Panel.TLabel").grid(row=9,column=0,sticky="nw",pady=4)
        sitebox=ttk.Frame(form,style="Panel.TFrame")
        sitebox.grid(row=9,column=1,sticky="w",padx=8,pady=2)
        self.build_site_street=tk.StringVar(); self.build_site_line2=tk.StringVar()
        self.build_site_city=tk.StringVar(); self.build_site_state=tk.StringVar()
        self.build_site_postal=tk.StringVar(); self.build_site_country=tk.StringVar(value="USA")
        ttk.Label(sitebox,text="Street",style="Panel.TLabel").grid(row=0,column=0,sticky="w")
        self.build_site_street_entry=ttk.Entry(sitebox,textvariable=self.build_site_street,width=28); self.build_site_street_entry.grid(row=0,column=1,sticky="w",padx=(4,10))
        ttk.Label(sitebox,text="Address 2",style="Panel.TLabel").grid(row=0,column=2,sticky="w")
        self.build_site_line2_entry=ttk.Entry(sitebox,textvariable=self.build_site_line2,width=22); self.build_site_line2_entry.grid(row=0,column=3,sticky="w",padx=(4,10))
        ttk.Label(sitebox,text="City",style="Panel.TLabel").grid(row=1,column=0,sticky="w",pady=(4,0))
        self.build_site_city_entry=ttk.Entry(sitebox,textvariable=self.build_site_city,width=20); self.build_site_city_entry.grid(row=1,column=1,sticky="w",padx=(4,10),pady=(4,0))
        ttk.Label(sitebox,text="State",style="Panel.TLabel").grid(row=1,column=2,sticky="w",pady=(4,0))
        self.build_site_state_entry=ttk.Entry(sitebox,textvariable=self.build_site_state,width=8); self.build_site_state_entry.grid(row=1,column=3,sticky="w",padx=(4,10),pady=(4,0))
        ttk.Label(sitebox,text="ZIP / Postal",style="Panel.TLabel").grid(row=1,column=4,sticky="w",pady=(4,0))
        self.build_site_postal_entry=ttk.Entry(sitebox,textvariable=self.build_site_postal,width=11); self.build_site_postal_entry.grid(row=1,column=5,sticky="w",padx=(4,10),pady=(4,0))
        ttk.Label(sitebox,text="Country",style="Panel.TLabel").grid(row=1,column=6,sticky="w",pady=(4,0))
        self.build_site_country_entry=ttk.Entry(sitebox,textvariable=self.build_site_country,width=12); self.build_site_country_entry.grid(row=1,column=7,sticky="w",padx=(4,0),pady=(4,0))
        ttk.Label(form,text="Stored with the network and automatically applied to hardware when it is moved/claimed into the site.",style="Panel.TLabel").grid(row=9,column=2,sticky="nw",padx=8,pady=4)

        ttk.Label(form,text="Note",style="Panel.TLabel").grid(row=10,column=0,sticky="w",pady=4)
        self.build_note=tk.StringVar(value="Created with Meraki MSP Toolkit. Review site-specific settings before claiming devices.")
        self.build_note_entry=ttk.Entry(form,textvariable=self.build_note,width=90)
        self.build_note_entry.grid(row=10,column=1,sticky="w",padx=8)
        buttons=ttk.Frame(f,style="Panel.TFrame"); buttons.pack(fill="x",padx=18,pady=7)
        self.builder_preview_button = ttk.Button(buttons,text="Preview / Dry Run",command=self.builder_preview)
        self.builder_preview_button.pack(side="left")
        self.builder_create_button = ttk.Button(buttons,text="CREATE",style="Danger.TButton",command=self.builder_apply)
        self.builder_create_button.pack(side="left",padx=8)
        self.builder_reset_button = ttk.Button(buttons,text="New Build / Reset",command=self.builder_reset,state="disabled")
        self.builder_reset_button.pack(side="left",padx=(0,8))
        self.builder_status_var = tk.StringVar(value="Ready")
        ttk.Label(buttons,textvariable=self.builder_status_var,style="Panel.TLabel").pack(side="left",padx=12)


        self.builder_text=tk.Text(f,bg="#0b1016",fg="#d7e1ea",insertbackground="white",font=("Cascadia Mono",9),relief="flat")
        self.builder_text.pack(fill="both",expand=True,padx=18,pady=10)
        self.last_build_signature=None
        self.builder_completed=False
        self.builder_completed_network_id=None
        self.builder_completed_network_name=None
        self.last_delete_signature=None
        self._builder_destination_changed()

    def _build_postbuild(self):
        f = self._panel(
            "Post-Build Setup",
            "Configure and verify the site after network creation. Target one network, then work through Alerts, Site / Location, Wireless, Switches, Appliance, and Compliance."
        )
        self.nb.add(f, text="Post-Build")

        target=ttk.Frame(f,style="Panel.TFrame"); target.pack(fill="x",padx=18,pady=(4,6))
        ttk.Label(target,text="Network",style="Panel.TLabel").pack(side="left")
        self.post_net_var=tk.StringVar()
        self.post_net_combo=ttk.Combobox(target,textvariable=self.post_net_var,width=58,state="readonly")
        self.post_net_combo.pack(side="left",padx=8)
        self.post_net_combo.bind("<<ComboboxSelected>>",lambda e:self._postbuild_target_changed())
        self.post_status_var=tk.StringVar(value="Select a network")
        ttk.Label(target,textvariable=self.post_status_var,style="Panel.TLabel").pack(side="left",padx=12)

        self.post_nb=ttk.Notebook(f)
        self.post_nb.pack(fill="both",expand=True,padx=18,pady=(4,10))

        # Alerts ---------------------------------------------------------
        alerts=ttk.Frame(self.post_nb,style="Panel.TFrame")
        self.post_nb.add(alerts,text="Alerts")

        row2=ttk.Frame(alerts,style="Panel.TFrame"); row2.pack(fill="x",padx=12,pady=(12,6))
        ttk.Label(row2,text="Alert destination email(s)",style="Panel.TLabel").pack(side="left")
        self.post_emails_var=tk.StringVar()
        ttk.Entry(row2,textvariable=self.post_emails_var,width=62).pack(side="left",padx=8)
        ttk.Label(row2,text="Comma/semicolon separated. Existing default emails are preserved.",style="Panel.TLabel").pack(side="left",padx=8)

        row3=ttk.Frame(alerts,style="Panel.TFrame"); row3.pack(fill="x",padx=12,pady=6)
        self.post_apply_baseline_var=tk.BooleanVar(value=True)
        ttk.Checkbutton(row3,text="Apply approved alert baseline",variable=self.post_apply_baseline_var,style="Panel.TCheckbutton").pack(side="left")
        self.post_settings_changed_var=tk.BooleanVar(value=False)
        ttk.Checkbutton(row3,text="Require Settings Changed alert",variable=self.post_settings_changed_var,style="Panel.TCheckbutton").pack(side="left",padx=12)
        ttk.Label(row3,text="Offline timeout",style="Panel.TLabel").pack(side="left",padx=(8,4))
        self.post_timeout_var=tk.StringVar(value="5")
        ttk.Entry(row3,textvariable=self.post_timeout_var,width=5).pack(side="left")
        ttk.Label(row3,text="minutes",style="Panel.TLabel").pack(side="left",padx=(4,12))

        row4=ttk.Frame(alerts,style="Panel.TFrame"); row4.pack(fill="x",padx=12,pady=8)
        self.post_preview_button=ttk.Button(row4,text="Preview / Dry Run",command=self.postbuild_preview)
        self.post_preview_button.pack(side="left")
        self.post_apply_button=ttk.Button(row4,text="APPLY + VERIFY",style="Danger.TButton",command=self.postbuild_apply,state="disabled")
        self.post_apply_button.pack(side="left",padx=8)

        self.post_text=tk.Text(alerts,bg="#0b1016",fg="#d7e1ea",insertbackground="white",font=("Cascadia Mono",9),relief="flat")
        self.post_text.pack(fill="both",expand=True,padx=12,pady=(2,12))
        self.last_postbuild_signature=None
        self.postbuild_preferred_network_name=None

        # Site / Location ------------------------------------------------
        site=ttk.Frame(self.post_nb,style="Panel.TFrame")
        self.post_nb.add(site,text="Site / Location")
        sitehead=ttk.Frame(site,style="Panel.TFrame"); sitehead.pack(fill="x",padx=12,pady=(12,6))
        self.post_site_load_button=ttk.Button(sitehead,text="Load Current Site",command=self.post_site_refresh)
        self.post_site_load_button.pack(side="left")
        self.post_site_preview_button=ttk.Button(sitehead,text="Preview Site Address",command=self.post_site_preview,state="disabled")
        self.post_site_preview_button.pack(side="left",padx=6)
        self.post_site_apply_button=ttk.Button(sitehead,text="APPLY + VERIFY",style="Danger.TButton",command=self.post_site_apply,state="disabled")
        self.post_site_apply_button.pack(side="left",padx=4)
        self.post_site_status_var=tk.StringVar(value="Load the selected network to review or set its physical site address.")
        ttk.Label(sitehead,textvariable=self.post_site_status_var,style="Panel.TLabel").pack(side="left",padx=10)

        sf=ttk.Frame(site,style="Panel.TFrame"); sf.pack(fill="x",padx=12,pady=6)
        self.post_site_street=tk.StringVar(); self.post_site_line2=tk.StringVar(); self.post_site_city=tk.StringVar()
        self.post_site_state=tk.StringVar(); self.post_site_postal=tk.StringVar(); self.post_site_country=tk.StringVar(value="USA")
        ttk.Label(sf,text="Street",style="Panel.TLabel").grid(row=0,column=0,sticky="w")
        ttk.Entry(sf,textvariable=self.post_site_street,width=30).grid(row=0,column=1,sticky="w",padx=(4,12))
        ttk.Label(sf,text="Address 2",style="Panel.TLabel").grid(row=0,column=2,sticky="w")
        ttk.Entry(sf,textvariable=self.post_site_line2,width=24).grid(row=0,column=3,sticky="w",padx=(4,12))
        ttk.Label(sf,text="City",style="Panel.TLabel").grid(row=0,column=4,sticky="w")
        ttk.Entry(sf,textvariable=self.post_site_city,width=20).grid(row=0,column=5,sticky="w",padx=(4,12))
        ttk.Label(sf,text="State",style="Panel.TLabel").grid(row=1,column=0,sticky="w",pady=(6,0))
        ttk.Entry(sf,textvariable=self.post_site_state,width=10).grid(row=1,column=1,sticky="w",padx=(4,12),pady=(6,0))
        ttk.Label(sf,text="ZIP / Postal",style="Panel.TLabel").grid(row=1,column=2,sticky="w",pady=(6,0))
        ttk.Entry(sf,textvariable=self.post_site_postal,width=14).grid(row=1,column=3,sticky="w",padx=(4,12),pady=(6,0))
        ttk.Label(sf,text="Country",style="Panel.TLabel").grid(row=1,column=4,sticky="w",pady=(6,0))
        ttk.Entry(sf,textvariable=self.post_site_country,width=16).grid(row=1,column=5,sticky="w",padx=(4,12),pady=(6,0))
        self.post_site_move_marker_var=tk.BooleanVar(value=True)
        ttk.Checkbutton(sf,text="Move Dashboard map marker from address",variable=self.post_site_move_marker_var,style="Panel.TCheckbutton").grid(row=1,column=6,sticky="w",padx=(4,0),pady=(6,0))

        swrap=ttk.Frame(site,style="Panel.TFrame"); swrap.pack(fill="both",expand=True,padx=12,pady=4)
        self.post_site_tree=ttk.Treeview(swrap,columns=("name","model","serial","address"),show="headings",height=8)
        for col,label,width in [("name","Name",220),("model","Model",110),("serial","Serial",145),("address","Current device address",520)]:
            self.post_site_tree.heading(col,text=label); self.post_site_tree.column(col,width=width,anchor="w")
        self.post_site_tree.pack(side="left",fill="both",expand=True)
        ssite=ttk.Scrollbar(swrap,orient="vertical",command=self.post_site_tree.yview); ssite.pack(side="right",fill="y")
        self.post_site_tree.configure(yscrollcommand=ssite.set)
        self.post_site_text=tk.Text(site,height=9,bg="#0b1016",fg="#d7e1ea",insertbackground="white",font=("Cascadia Mono",9),relief="flat")
        self.post_site_text.pack(fill="x",padx=12,pady=(2,12))
        self.post_site_devices=[]
        self.post_site_current_network=None
        self.last_post_site_signature=None

        # Wireless -------------------------------------------------------
        wireless=ttk.Frame(self.post_nb,style="Panel.TFrame")
        self.post_nb.add(wireless,text="Wireless")
        wh=ttk.Frame(wireless,style="Panel.TFrame"); wh.pack(fill="x",padx=12,pady=(12,6))
        self.post_wireless_refresh_button=ttk.Button(wh,text="Refresh SSIDs",command=self.post_wireless_refresh)
        self.post_wireless_refresh_button.pack(side="left")
        self.post_wireless_status_var=tk.StringVar(value="Refresh to load SSIDs for the selected network.")
        ttk.Label(wh,textvariable=self.post_wireless_status_var,style="Panel.TLabel").pack(side="left",padx=10)

        wtreewrap=ttk.Frame(wireless,style="Panel.TFrame"); wtreewrap.pack(fill="both",expand=True,padx=12,pady=4)
        self.post_wireless_tree=ttk.Treeview(wtreewrap,columns=("num","enabled","name","auth","wpa","pmf","vlan","band"),show="headings",height=8)
        for col,label,width in [
            ("num","SSID",55),("enabled","Enabled",70),("name","Name",210),("auth","Auth",125),
            ("wpa","WPA",170),("pmf","PMF",90),("vlan","VLAN",70),("band","Band",210)]:
            self.post_wireless_tree.heading(col,text=label); self.post_wireless_tree.column(col,width=width,anchor="w")
        self.post_wireless_tree.pack(side="left",fill="both",expand=True)
        wscroll=ttk.Scrollbar(wtreewrap,orient="vertical",command=self.post_wireless_tree.yview); wscroll.pack(side="right",fill="y")
        self.post_wireless_tree.configure(yscrollcommand=wscroll.set)
        self.post_wireless_tree.bind("<<TreeviewSelect>>",lambda e:self._post_wireless_on_select())

        wed=ttk.Frame(wireless,style="Panel.TFrame"); wed.pack(fill="x",padx=12,pady=6)
        self.post_wireless_number_var=tk.StringVar(value="-")
        self.post_wireless_enabled_var=tk.BooleanVar(value=False)
        self.post_wireless_name_var=tk.StringVar()
        self.post_wireless_auth_var=tk.StringVar(value="Preserve current")
        self.post_wireless_wpa_var=tk.StringVar(value="Preserve current")
        self.post_wireless_pmf_var=tk.StringVar(value="Preserve current")
        self.post_wireless_psk_var=tk.StringVar()
        self.post_wireless_addressing_var=tk.StringVar(value="Preserve current")
        self.post_wireless_vlan_var=tk.StringVar()
        self.post_wireless_band_var=tk.StringVar(value="Preserve current")
        self.post_wireless_visible_var=tk.BooleanVar(value=True)
        self.post_wireless_isolation_var=tk.BooleanVar(value=False)

        ttk.Label(wed,text="SSID #",style="Panel.TLabel").grid(row=0,column=0,sticky="w",padx=(0,4),pady=3)
        ttk.Label(wed,textvariable=self.post_wireless_number_var,style="Panel.TLabel").grid(row=0,column=1,sticky="w",padx=(0,14))
        ttk.Checkbutton(wed,text="Enabled",variable=self.post_wireless_enabled_var,style="Panel.TCheckbutton").grid(row=0,column=2,sticky="w",padx=(0,14))
        ttk.Label(wed,text="Name",style="Panel.TLabel").grid(row=0,column=3,sticky="w")
        ttk.Entry(wed,textvariable=self.post_wireless_name_var,width=28).grid(row=0,column=4,sticky="w",padx=(4,14))
        ttk.Label(wed,text="Auth",style="Panel.TLabel").grid(row=0,column=5,sticky="w")
        ttk.Combobox(wed,textvariable=self.post_wireless_auth_var,state="readonly",width=18,values=["Preserve current","psk","open"]).grid(row=0,column=6,sticky="w",padx=(4,14))
        ttk.Label(wed,text="WPA",style="Panel.TLabel").grid(row=0,column=7,sticky="w")
        ttk.Combobox(wed,textvariable=self.post_wireless_wpa_var,state="readonly",width=22,values=["Preserve current","WPA2 only","WPA3 Transition Mode","WPA3 only"]).grid(row=0,column=8,sticky="w",padx=(4,0))

        ttk.Label(wed,text="New PSK",style="Panel.TLabel").grid(row=1,column=0,sticky="w",pady=3)
        ttk.Entry(wed,textvariable=self.post_wireless_psk_var,width=22,show="•").grid(row=1,column=1,columnspan=2,sticky="w",padx=(4,14))
        ttk.Label(wed,text="blank = preserve",style="Panel.TLabel").grid(row=1,column=3,sticky="w",padx=(0,14))
        ttk.Label(wed,text="Client addressing",style="Panel.TLabel").grid(row=1,column=4,sticky="w")
        ttk.Combobox(wed,textvariable=self.post_wireless_addressing_var,state="readonly",width=18,values=["Preserve current","Bridge mode","NAT mode"]).grid(row=1,column=5,sticky="w",padx=(4,14))
        ttk.Label(wed,text="VLAN ID",style="Panel.TLabel").grid(row=1,column=6,sticky="w")
        ttk.Entry(wed,textvariable=self.post_wireless_vlan_var,width=8).grid(row=1,column=7,sticky="w",padx=(4,14))
        ttk.Label(wed,text="Band",style="Panel.TLabel").grid(row=1,column=8,sticky="w")
        ttk.Combobox(wed,textvariable=self.post_wireless_band_var,state="readonly",width=34,values=["Preserve current","Dual band operation","5 GHz band only","Dual band operation with Band Steering"]).grid(row=1,column=9,sticky="w",padx=(4,0))

        ttk.Checkbutton(wed,text="Broadcast SSID",variable=self.post_wireless_visible_var,style="Panel.TCheckbutton").grid(row=2,column=0,columnspan=2,sticky="w",pady=4)
        ttk.Checkbutton(wed,text="LAN client isolation",variable=self.post_wireless_isolation_var,style="Panel.TCheckbutton").grid(row=2,column=2,columnspan=2,sticky="w",pady=4)
        ttk.Label(wed,text="PMF / 802.11w",style="Panel.TLabel").grid(row=2,column=4,sticky="w")
        ttk.Combobox(wed,textvariable=self.post_wireless_pmf_var,state="readonly",width=18,values=["Preserve current","Disabled","Enabled","Required"]).grid(row=2,column=5,sticky="w",padx=(4,14))
        self.post_wireless_preview_button=ttk.Button(wed,text="Preview SSID Change",command=self.post_wireless_preview,state="disabled")
        self.post_wireless_preview_button.grid(row=2,column=6,sticky="w",padx=4)
        self.post_wireless_apply_button=ttk.Button(wed,text="APPLY + VERIFY",style="Danger.TButton",command=self.post_wireless_apply,state="disabled")
        self.post_wireless_apply_button.grid(row=2,column=7,sticky="w",padx=4)
        ttk.Label(wed,text="WPA3 automatically requires compatible PMF. PSKs are never written to reports.",style="Panel.TLabel").grid(row=2,column=8,columnspan=2,sticky="w",padx=(12,0))

        self.post_wireless_text=tk.Text(wireless,height=8,bg="#0b1016",fg="#d7e1ea",insertbackground="white",font=("Cascadia Mono",9),relief="flat")
        self.post_wireless_text.pack(fill="x",padx=12,pady=(2,12))
        self.post_wireless_ssids=[]
        self.post_wireless_current=None
        self.last_post_wireless_signature=None

        # Switches -------------------------------------------------------
        switches=ttk.Frame(self.post_nb,style="Panel.TFrame")
        self.post_nb.add(switches,text="Switches")
        sh=ttk.Frame(switches,style="Panel.TFrame"); sh.pack(fill="x",padx=12,pady=(12,6))
        self.post_switch_refresh_button=ttk.Button(sh,text="Refresh Switches",command=self.post_switch_refresh)
        self.post_switch_refresh_button.pack(side="left")
        self.post_switch_status_var=tk.StringVar(value="Move switch hardware into the network, then refresh here.")
        ttk.Label(sh,textvariable=self.post_switch_status_var,style="Panel.TLabel").pack(side="left",padx=10)

        streewrap=ttk.Frame(switches,style="Panel.TFrame"); streewrap.pack(fill="both",expand=True,padx=12,pady=4)
        self.post_switch_tree=ttk.Treeview(streewrap,columns=("name","model","serial","lanip","mac"),show="headings",height=8)
        for col,label,width in [("name","Name",220),("model","Model",120),("serial","Serial",145),("lanip","Current IP",145),("mac","MAC",155)]:
            self.post_switch_tree.heading(col,text=label); self.post_switch_tree.column(col,width=width,anchor="w")
        self.post_switch_tree.pack(side="left",fill="both",expand=True)
        sscroll=ttk.Scrollbar(streewrap,orient="vertical",command=self.post_switch_tree.yview); sscroll.pack(side="right",fill="y")
        self.post_switch_tree.configure(yscrollcommand=sscroll.set)
        self.post_switch_tree.bind("<<TreeviewSelect>>",lambda e:self._post_switch_on_select())

        sed=ttk.Frame(switches,style="Panel.TFrame"); sed.pack(fill="x",padx=12,pady=6)
        self.post_switch_serial_var=tk.StringVar(value="-")
        self.post_switch_name_var=tk.StringVar()
        self.post_switch_ipmode_var=tk.StringVar(value="DHCP")
        self.post_switch_ip_var=tk.StringVar()
        self.post_switch_mask_var=tk.StringVar()
        self.post_switch_gateway_var=tk.StringVar()
        self.post_switch_dns_var=tk.StringVar()
        self.post_switch_vlan_var=tk.StringVar()
        ttk.Label(sed,text="Serial",style="Panel.TLabel").grid(row=0,column=0,sticky="w",pady=3)
        ttk.Label(sed,textvariable=self.post_switch_serial_var,style="Panel.TLabel").grid(row=0,column=1,sticky="w",padx=(4,14))
        ttk.Label(sed,text="Name",style="Panel.TLabel").grid(row=0,column=2,sticky="w")
        ttk.Entry(sed,textvariable=self.post_switch_name_var,width=26).grid(row=0,column=3,sticky="w",padx=(4,14))
        ttk.Label(sed,text="Management IP",style="Panel.TLabel").grid(row=0,column=4,sticky="w")
        ttk.Combobox(sed,textvariable=self.post_switch_ipmode_var,state="readonly",width=10,values=["DHCP","Static"]).grid(row=0,column=5,sticky="w",padx=(4,14))
        ttk.Label(sed,text="IP",style="Panel.TLabel").grid(row=0,column=6,sticky="w")
        ttk.Entry(sed,textvariable=self.post_switch_ip_var,width=15).grid(row=0,column=7,sticky="w",padx=(4,14))
        ttk.Label(sed,text="Mask",style="Panel.TLabel").grid(row=0,column=8,sticky="w")
        ttk.Entry(sed,textvariable=self.post_switch_mask_var,width=15).grid(row=0,column=9,sticky="w",padx=(4,0))

        ttk.Label(sed,text="Gateway",style="Panel.TLabel").grid(row=1,column=0,sticky="w",pady=3)
        ttk.Entry(sed,textvariable=self.post_switch_gateway_var,width=15).grid(row=1,column=1,sticky="w",padx=(4,14))
        ttk.Label(sed,text="DNS (max 2)",style="Panel.TLabel").grid(row=1,column=2,sticky="w")
        ttk.Entry(sed,textvariable=self.post_switch_dns_var,width=28).grid(row=1,column=3,sticky="w",padx=(4,14))
        ttk.Label(sed,text="Management VLAN",style="Panel.TLabel").grid(row=1,column=4,sticky="w")
        ttk.Entry(sed,textvariable=self.post_switch_vlan_var,width=8).grid(row=1,column=5,sticky="w",padx=(4,14))
        self.post_switch_preview_button=ttk.Button(sed,text="Preview Switch Change",command=self.post_switch_preview,state="disabled")
        self.post_switch_preview_button.grid(row=1,column=6,columnspan=2,sticky="w",padx=4)
        self.post_switch_apply_button=ttk.Button(sed,text="APPLY + VERIFY",style="Danger.TButton",command=self.post_switch_apply,state="disabled")
        self.post_switch_apply_button.grid(row=1,column=8,columnspan=2,sticky="w",padx=4)
        ttk.Label(sed,text="Per-device management IP is available only after the switch is assigned to this network. Every write is re-read and verified.",style="Panel.TLabel").grid(row=2,column=0,columnspan=10,sticky="w",pady=(4,0))

        self.post_switch_text=tk.Text(switches,height=8,bg="#0b1016",fg="#d7e1ea",insertbackground="white",font=("Cascadia Mono",9),relief="flat")
        self.post_switch_text.pack(fill="x",padx=12,pady=(2,12))
        self.post_switch_devices=[]
        self.post_switch_current_device=None
        self.post_switch_current_mgmt=None
        self.last_post_switch_signature=None

        # Appliance ------------------------------------------------------
        appliance=ttk.Frame(self.post_nb,style="Panel.TFrame")
        self.post_nb.add(appliance,text="Appliance")
        ah=ttk.Frame(appliance,style="Panel.TFrame"); ah.pack(fill="x",padx=12,pady=(12,6))
        self.post_appliance_refresh_button=ttk.Button(ah,text="Refresh / Inspect Appliance",command=self.post_appliance_refresh)
        self.post_appliance_refresh_button.pack(side="left")
        self.post_appliance_status_var=tk.StringVar(value="Move the MX/Z into the network, then inspect WAN settings or set the appliance name here.")
        ttk.Label(ah,textvariable=self.post_appliance_status_var,style="Panel.TLabel").pack(side="left",padx=10)

        atreewrap=ttk.Frame(appliance,style="Panel.TFrame"); atreewrap.pack(fill="x",padx=12,pady=4)
        self.post_appliance_tree=ttk.Treeview(atreewrap,columns=("name","model","serial","lanip","address"),show="headings",height=4)
        for col,label,width in [("name","Name",220),("model","Model",110),("serial","Serial",145),("lanip","LAN IP",135),("address","Device address",430)]:
            self.post_appliance_tree.heading(col,text=label); self.post_appliance_tree.column(col,width=width,anchor="w")
        self.post_appliance_tree.pack(side="left",fill="x",expand=True)
        ascroll=ttk.Scrollbar(atreewrap,orient="vertical",command=self.post_appliance_tree.yview); ascroll.pack(side="right",fill="y")
        self.post_appliance_tree.configure(yscrollcommand=ascroll.set)
        self.post_appliance_tree.bind("<<TreeviewSelect>>",lambda e:self._post_appliance_on_select())

        aedit=ttk.Frame(appliance,style="Panel.TFrame"); aedit.pack(fill="x",padx=12,pady=6)
        self.post_appliance_serial_var=tk.StringVar(value="-")
        self.post_appliance_name_var=tk.StringVar()
        ttk.Label(aedit,text="Serial",style="Panel.TLabel").grid(row=0,column=0,sticky="w",pady=3)
        ttk.Label(aedit,textvariable=self.post_appliance_serial_var,style="Panel.TLabel").grid(row=0,column=1,sticky="w",padx=(4,14))
        ttk.Label(aedit,text="Appliance name",style="Panel.TLabel").grid(row=0,column=2,sticky="w")
        ttk.Entry(aedit,textvariable=self.post_appliance_name_var,width=30).grid(row=0,column=3,sticky="w",padx=(4,14))
        self.post_appliance_preview_button=ttk.Button(aedit,text="Preview Appliance Name",command=self.post_appliance_preview,state="disabled")
        self.post_appliance_preview_button.grid(row=0,column=4,sticky="w",padx=4)
        self.post_appliance_apply_button=ttk.Button(aedit,text="APPLY + VERIFY",style="Danger.TButton",command=self.post_appliance_apply,state="disabled")
        self.post_appliance_apply_button.grid(row=0,column=5,sticky="w",padx=4)
        ttk.Label(aedit,text="WAN settings remain read-only; appliance naming uses the guarded device update path and is re-read from this network.",style="Panel.TLabel").grid(row=1,column=0,columnspan=6,sticky="w",pady=(4,0))

        self.post_appliance_text=tk.Text(appliance,bg="#0b1016",fg="#d7e1ea",insertbackground="white",font=("Cascadia Mono",9),relief="flat")
        self.post_appliance_text.pack(fill="both",expand=True,padx=12,pady=(4,12))
        self.post_appliance_text.insert("end","Refresh to inspect WAN1/WAN2 in readable form. Select an MX/Z above to preview and verify a device-name change. WAN addressing remains read-only here.\n")
        self.post_appliance_devices=[]
        self.post_appliance_current_device=None
        self.last_post_appliance_signature=None

        # Compliance -----------------------------------------------------
        compliance=ttk.Frame(self.post_nb,style="Panel.TFrame")
        self.post_nb.add(compliance,text="Compliance")
        ch=ttk.Frame(compliance,style="Panel.TFrame"); ch.pack(fill="x",padx=12,pady=(14,8))
        ttk.Label(ch,text="Audit scope",style="Panel.TLabel").pack(side="left")
        self.post_compliance_scope_var=tk.StringVar(value="This Network")
        self.post_compliance_scope_combo=ttk.Combobox(ch,textvariable=self.post_compliance_scope_var,width=18,state="readonly",values=["This Network","This Organization"])
        self.post_compliance_scope_combo.pack(side="left",padx=8)
        self.post_compliance_button=ttk.Button(ch,text="Run Compliance Audit",style="Accent.TButton",command=self.postbuild_full_compliance)
        self.post_compliance_button.pack(side="left",padx=4)
        self.post_compliance_open_button=ttk.Button(ch,text="Open Last Report",command=self.open_last_post_compliance_report,state="disabled")
        self.post_compliance_open_button.pack(side="left",padx=4)
        self.post_compliance_status_var=tk.StringVar(value="This Network is the default Post-Build audit scope.")
        ttk.Label(ch,textvariable=self.post_compliance_status_var,style="Panel.TLabel").pack(side="left",padx=10)
        self.post_compliance_last_report=None
        self.post_compliance_text=tk.Text(compliance,bg="#0b1016",fg="#d7e1ea",insertbackground="white",font=("Cascadia Mono",9),relief="flat",height=16)
        self.post_compliance_text.pack(fill="both",expand=True,padx=12,pady=(4,12))
        self.post_compliance_text.insert("end","POST-BUILD COMPLIANCE\n"+"="*72+"\n\n")
        self.post_compliance_text.insert("end","This Network audits only the selected Post-Build site.\nThis Organization audits every network inside the selected customer organization.\n\n")
        self.post_compliance_text.insert("end","The audit runs in the background inside the Toolkit; no PowerShell window is opened.\n")
        self.post_compliance_text.insert("end","The fleet-wide Multi-Org Compliance tool remains under More Tools and is not used from this workflow.\n")
        self.post_compliance_text.configure(state="disabled")
    def _build_network_cleanup(self):
        f=self._panel(
            "Delete Network",
            "Choose what happens to assigned hardware first, preview the exact device list and destination, then delete only after hardware disposition is verified."
        )
        self.nb.add(f,text="Delete Network")

        scope=ttk.Frame(f,style="Panel.TFrame")
        scope.pack(fill="x",padx=18,pady=(4,8))
        self.delete_scope_var=tk.StringVar(value="Select one organization at the top of the window.")
        ttk.Label(scope,textvariable=self.delete_scope_var,style="Panel.TLabel").pack(anchor="w")

        row=ttk.Frame(f,style="Panel.TFrame")
        row.pack(fill="x",padx=18,pady=6)
        ttk.Label(row,text="Network",style="Panel.TLabel").pack(side="left")
        self.delete_net_var=tk.StringVar()
        self.delete_net_combo=ttk.Combobox(row,textvariable=self.delete_net_var,width=62,state="readonly")
        self.delete_net_combo.pack(side="left",padx=8)
        self.delete_net_combo.bind("<<ComboboxSelected>>",lambda e:self._delete_selection_changed())
        self.delete_preview_button=ttk.Button(row,text="Preview Delete",command=self.delete_network_preview)
        self.delete_preview_button.pack(side="left")
        self.delete_apply_button=ttk.Button(row,text="DELETE Network",style="Danger.TButton",command=self.delete_network_apply,state="disabled")
        self.delete_apply_button.pack(side="left",padx=8)
        self.delete_status_var=tk.StringVar(value="Preview required")
        ttk.Label(row,textvariable=self.delete_status_var,style="Panel.TLabel").pack(side="left",padx=8)

        drow=ttk.Frame(f,style="Panel.TFrame")
        drow.pack(fill="x",padx=18,pady=(0,6))
        ttk.Label(drow,text="Hardware disposition",style="Panel.TLabel").pack(side="left")
        self.delete_disposition_var=tk.StringVar(value="2 - Keep in Customer Organization Inventory")
        self.delete_disposition_combo=ttk.Combobox(
            drow,
            textvariable=self.delete_disposition_var,
            state="readonly",
            width=43,
            values=[
                "1 - Return to Hardware Holding",
                "2 - Keep in Customer Organization Inventory",
                "3 - Unclaim from Customer Organization",
            ],
        )
        self.delete_disposition_combo.pack(side="left",padx=8)
        self.delete_disposition_combo.bind("<<ComboboxSelected>>",lambda e:self._delete_disposition_changed())
        self.delete_disposition_help_var=tk.StringVar()
        ttk.Label(drow,textvariable=self.delete_disposition_help_var,style="Panel.TLabel").pack(side="left",padx=8)
        self._delete_disposition_changed()

        self.delete_text=tk.Text(f,bg="#0b1016",fg="#d7e1ea",insertbackground="white",font=("Cascadia Mono",9),relief="flat")
        self.delete_text.pack(fill="both",expand=True,padx=18,pady=10)
        self.last_delete_preview=None
        self.last_delete_signature=None

    def _delete_selection_changed(self):
        self.last_delete_preview=None
        self.last_delete_signature=None
        if hasattr(self,"delete_apply_button"):
            self.delete_apply_button.configure(state="disabled")
        if hasattr(self,"delete_status_var"):
            self.delete_status_var.set("Preview required")

    def _delete_disposition_changed(self):
        if hasattr(self,"last_delete_preview"):
            self._delete_selection_changed()
        if not hasattr(self,"delete_disposition_help_var"):
            return
        code=self._delete_disposition_code(allow_missing=True)
        help_text={
            "holding":"MSP-owned hardware: transfer every assigned device to Hardware Holding before deletion.",
            "keep":"Customer-owned hardware: remove devices from this network but keep them claimed in this organization inventory.",
            "unclaim":"Release hardware completely from this customer organization after removing it from the network.",
        }.get(code,"Choose how assigned hardware should be handled before deletion.")
        self.delete_disposition_help_var.set(help_text)

    def _delete_disposition_code(self, allow_missing=False):
        value=(getattr(self,"delete_disposition_var",tk.StringVar(value="")).get() or "").strip()
        if value.startswith("1 -"):
            return "holding"
        if value.startswith("2 -"):
            return "keep"
        if value.startswith("3 -"):
            return "unclaim"
        if allow_missing:
            return None
        raise RuntimeError("Choose a hardware disposition before previewing deletion.")

    def _build_admin_access(self):
        f = self._panel(
            "Admin Access",
            "Add or change Dashboard administrators, grant access to selected networks, remove an admin, or offboard a departed employee across every accessible organization. This NEVER deletes networks or hardware."
        )
        self.nb.add(f, text="Admin Access")

        top = ttk.Frame(f, style="Panel.TFrame"); top.pack(fill="x", padx=18, pady=(4,6))
        ttk.Label(top, text="Workflow", style="Panel.TLabel").pack(side="left")
        self.admin_workflow_var=tk.StringVar(value="Add / Change Admin")
        self.admin_workflow_combo=ttk.Combobox(top,textvariable=self.admin_workflow_var,state="readonly",width=36,values=("Add / Change Admin","Remove Admin","Employee Offboarding - All Organizations"))
        self.admin_workflow_combo.pack(side="left",padx=(8,18)); self.admin_workflow_combo.bind("<<ComboboxSelected>>",lambda e:self._admin_workflow_changed())
        ttk.Label(top,text="Scope",style="Panel.TLabel").pack(side="left")
        self.admin_scope_var=tk.StringVar(value="Selected Organization")
        self.admin_scope_combo=ttk.Combobox(top,textvariable=self.admin_scope_var,state="readonly",width=28,values=("Selected Organization","All Accessible Organizations"))
        self.admin_scope_combo.pack(side="left",padx=8); self.admin_scope_combo.bind("<<ComboboxSelected>>",lambda e:self._admin_scope_changed())
        self.admin_identity_var=tk.StringVar(value="Authenticated identity: unknown")
        ttk.Label(top,textvariable=self.admin_identity_var,style="Panel.TLabel").pack(side="right")

        details=ttk.Frame(f,style="Panel.TFrame"); details.pack(fill="x",padx=18,pady=6)
        ttk.Label(details,text="Email",style="Panel.TLabel").grid(row=0,column=0,sticky="w")
        self.admin_email_var=tk.StringVar(); self.admin_email_entry=ttk.Entry(details,textvariable=self.admin_email_var,width=38); self.admin_email_entry.grid(row=0,column=1,padx=(8,18),sticky="w")
        ttk.Label(details,text="Name",style="Panel.TLabel").grid(row=0,column=2,sticky="w")
        self.admin_name_var=tk.StringVar(); self.admin_name_entry=ttk.Entry(details,textvariable=self.admin_name_var,width=30); self.admin_name_entry.grid(row=0,column=3,padx=(8,18),sticky="w")
        ttk.Label(details,text="Access",style="Panel.TLabel").grid(row=0,column=4,sticky="w")
        self.admin_access_var=tk.StringVar(value="Full")
        self.admin_access_combo=ttk.Combobox(details,textvariable=self.admin_access_var,state="readonly",width=14,values=("Full","Read-only")); self.admin_access_combo.grid(row=0,column=5,padx=(8,18),sticky="w")
        ttk.Label(details,text="Grant",style="Panel.TLabel").grid(row=0,column=6,sticky="w")
        self.admin_grant_var=tk.StringVar(value="Organization-wide")
        self.admin_grant_combo=ttk.Combobox(details,textvariable=self.admin_grant_var,state="readonly",width=22,values=("Organization-wide","Selected Networks")); self.admin_grant_combo.grid(row=0,column=7,padx=8,sticky="w")
        self.admin_grant_combo.bind("<<ComboboxSelected>>",lambda e:self._admin_form_changed())
        for v in (self.admin_email_var,self.admin_name_var,self.admin_access_var,self.admin_grant_var): v.trace_add("write",lambda *_:self._admin_form_changed())

        actions=ttk.Frame(f,style="Panel.TFrame"); actions.pack(fill="x",padx=18,pady=6)
        self.admin_select_all_button=ttk.Button(actions,text="Select All Networks",command=self._admin_select_all_networks); self.admin_select_all_button.pack(side="left")
        self.admin_clear_networks_button=ttk.Button(actions,text="Clear Network Selection",command=lambda:self.admin_network_tree.selection_remove(self.admin_network_tree.selection())); self.admin_clear_networks_button.pack(side="left",padx=8)
        self.admin_dry_button=ttk.Button(actions,text="Dry Run",style="Accent.TButton",command=self.admin_access_dry_run); self.admin_dry_button.pack(side="left",padx=(18,8))
        self.admin_apply_button=ttk.Button(actions,text="APPLY + VERIFY",style="Danger.TButton",command=self.admin_access_apply,state="disabled"); self.admin_apply_button.pack(side="left")
        self.admin_status_var=tk.StringVar(value="Dry run required"); ttk.Label(actions,textvariable=self.admin_status_var,style="Panel.TLabel").pack(side="left",padx=12)

        split=ttk.Panedwindow(f,orient="horizontal"); split.pack(fill="both",expand=True,padx=18,pady=8)
        left=ttk.Frame(split,style="Panel.TFrame"); right=ttk.Frame(split,style="Panel.TFrame"); split.add(left,weight=2); split.add(right,weight=3)
        ttk.Label(left,text="Networks in selected organization",style="Panel.TLabel").pack(anchor="w",pady=(0,6))
        self.admin_network_tree=ttk.Treeview(left,columns=("name","id"),show="headings",selectmode="extended",height=12)
        self.admin_network_tree.heading("name",text="Network"); self.admin_network_tree.heading("id",text="Network ID")
        self.admin_network_tree.column("name",width=220,anchor="w"); self.admin_network_tree.column("id",width=245,anchor="w")
        self.admin_network_tree.pack(fill="both",expand=True); self.admin_network_tree.bind("<<TreeviewSelect>>",lambda e:self._admin_form_changed())
        ttk.Label(right,text="Dry Run / Verification",style="Panel.TLabel").pack(anchor="w",pady=(0,6))
        self.admin_plan_tree=ttk.Treeview(right,columns=("org","current","planned","status"),show="headings",height=12)
        for c,t,w in (("org","Organization",220),("current","Current Access",190),("planned","Planned",230),("status","Preflight / Result",250)):
            self.admin_plan_tree.heading(c,text=t); self.admin_plan_tree.column(c,width=w,anchor="w")
        self.admin_plan_tree.pack(fill="both",expand=True)

        self.admin_text=tk.Text(f,height=12,bg="#0b1016",fg="#d7e1ea",insertbackground="white",relief="flat",font=("Cascadia Mono",9),wrap="word")
        self.admin_text.pack(fill="x",padx=18,pady=(0,12))
        self.last_admin_plan=None
        self._admin_identity_refresh(); self._admin_workflow_changed()

    def _build_org_cleanup(self):
        f = self._panel(
            "Organization Cleanup",
            "Audit one organization, remove extra administrators only when it is a safe cleanup candidate, and permanently delete the organization only after every blocker is cleared."
        )
        self.nb.add(f, text="Org Cleanup")

        scope = ttk.Frame(f, style="Panel.TFrame")
        scope.pack(fill="x", padx=18, pady=(4, 6))
        self.cleanup_scope_var = tk.StringVar(value="Select one organization at the top of the window.")
        ttk.Label(scope, textvariable=self.cleanup_scope_var, style="Panel.TLabel").pack(side="left")

        actions = ttk.Frame(f, style="Panel.TFrame")
        actions.pack(fill="x", padx=18, pady=6)
        self.cleanup_audit_button = ttk.Button(actions, text="Audit Organization", style="Accent.TButton", command=self.org_cleanup_audit)
        self.cleanup_audit_button.pack(side="left")
        self.cleanup_preview_admin_button = ttk.Button(actions, text="Preview Admin Cleanup", command=self.org_cleanup_preview_admin, state="disabled")
        self.cleanup_preview_admin_button.pack(side="left", padx=8)
        self.cleanup_apply_admin_button = ttk.Button(actions, text="REMOVE Extra Admins", style="Danger.TButton", command=self.org_cleanup_apply_admin, state="disabled")
        self.cleanup_apply_admin_button.pack(side="left")
        self.cleanup_delete_org_button = ttk.Button(actions, text="DELETE Organization", style="Danger.TButton", command=self.org_cleanup_delete_org, state="disabled")
        self.cleanup_delete_org_button.pack(side="left", padx=8)
        self.cleanup_go_networks_button = ttk.Button(actions, text="Go to Delete Network", command=self.org_cleanup_go_delete_network)
        self.cleanup_go_networks_button.pack(side="left")
        self.cleanup_status_var = tk.StringVar(value="Audit required")
        ttk.Label(actions, textvariable=self.cleanup_status_var, style="Panel.TLabel").pack(side="left", padx=12)

        split = ttk.Panedwindow(f, orient="horizontal")
        split.pack(fill="both", expand=True, padx=18, pady=8)

        left = ttk.Frame(split, style="Panel.TFrame")
        right = ttk.Frame(split, style="Panel.TFrame")
        split.add(left, weight=3)
        split.add(right, weight=2)

        ttk.Label(left, text="Cleanup audit", style="Section.TLabel").pack(anchor="w", pady=(2, 6))
        self.cleanup_text = tk.Text(left, bg="#0b1016", fg="#d7e1ea", insertbackground="white", font=("Cascadia Mono", 9), relief="flat", wrap="word")
        self.cleanup_text.pack(fill="both", expand=True)

        ttk.Label(right, text="Administrators", style="Section.TLabel").pack(anchor="w", pady=(2, 4))
        ttk.Label(right, text="Select the ONE full-access administrator to KEEP, then preview admin cleanup.", style="Panel.TLabel").pack(anchor="w", pady=(0, 6))
        cols = ("name", "email", "access")
        self.cleanup_admin_tree = ttk.Treeview(right, columns=cols, show="headings", height=12, selectmode="browse")
        for c, w in zip(cols, (150, 230, 100)):
            self.cleanup_admin_tree.heading(c, text=c.title())
            self.cleanup_admin_tree.column(c, width=w, anchor="w")
        self.cleanup_admin_tree.pack(fill="both", expand=True)
        self.cleanup_admin_tree.bind("<<TreeviewSelect>>", lambda e: self._cleanup_admin_selection_changed())

        note = (
            "Safety: admin removal is enabled only for an audited SAFE AFTER ADMIN CLEANUP candidate. "
            "If the API key belongs to an admin you remove, the session may immediately lose access. "
            "For network cleanup, use the separate Delete Network tab."
        )
        ttk.Label(right, text=note, style="Panel.TLabel", wraplength=470, justify="left").pack(anchor="w", pady=(8, 2))

        self.last_cleanup_audit = None
        self.last_cleanup_admin_plan = None

    def _cleanup_admin_selection_changed(self):
        self.last_cleanup_admin_plan = None
        if hasattr(self, "cleanup_apply_admin_button"):
            self.cleanup_apply_admin_button.configure(state="disabled")
        if hasattr(self, "cleanup_status_var") and self.last_cleanup_audit:
            self.cleanup_status_var.set("Admin selection changed · preview required")

    def _build_holding(self):
        f=self._panel(
            "Hardware / Inventory",
            "Move hardware from Hardware Holding to a customer, return customer hardware to Holding, claim brand-new serials, or offboard a departing client by unclaiming selected/all hardware. Every write path uses a dry run, typed confirmation, and final verification."
        )
        self.nb.add(f,text="Hardware / Inventory")

        mode_row=ttk.Frame(f,style="Panel.TFrame"); mode_row.pack(fill="x",padx=18,pady=(6,2))
        ttk.Label(mode_row,text="Workflow",style="Panel.TLabel").pack(side="left")
        self.hold_direction=tk.StringVar(value="Move from Holding")
        self.hold_direction_combo=ttk.Combobox(
            mode_row,textvariable=self.hold_direction,
            values=["Move from Holding","Return to Holding","Claim New Hardware","Client Offboarding - Unclaim"],state="readonly",width=30
        )
        self.hold_direction_combo.pack(side="left",padx=8)
        self.hold_direction.trace_add("write",lambda *_: self._holding_direction_changed())
        self.hold_direction_help_var=tk.StringVar(value="Source: Hardware Holding → destination: selected organization/network")
        ttk.Label(mode_row,textvariable=self.hold_direction_help_var,style="Panel.TLabel").pack(side="left",padx=8)

        self.hold_single_serial_frame=ttk.Frame(f,style="Panel.TFrame")
        self.hold_single_serial_frame.pack(fill="x",padx=18,pady=(6,2))
        ttk.Label(self.hold_single_serial_frame,text="Serial",style="Panel.TLabel").pack(side="left")
        self.hold_serial=tk.StringVar()
        self.hold_serial_entry=ttk.Entry(self.hold_single_serial_frame,textvariable=self.hold_serial,width=30)
        self.hold_serial_entry.pack(side="left",padx=8)
        ttk.Label(self.hold_single_serial_frame,text="Select a row below or enter one serial.",style="Panel.TLabel").pack(side="left",padx=8)

        self.hold_claim_serial_frame=ttk.Frame(f,style="Panel.TFrame")
        ttk.Label(self.hold_claim_serial_frame,text="New serials",style="Panel.TLabel").pack(side="left",anchor="n",pady=4)
        self.hold_claim_text=tk.Text(
            self.hold_claim_serial_frame,height=4,width=56,bg="#0b1016",fg="#d7e1ea",
            insertbackground="white",font=("Cascadia Mono",9),relief="flat",wrap="word"
        )
        self.hold_claim_text.pack(side="left",padx=8,fill="x",expand=True)
        ttk.Label(
            self.hold_claim_serial_frame,
            text="Paste or scan one or many serials. Separate them with spaces, commas, semicolons, or new lines.",
            style="Panel.TLabel",wraplength=520,justify="left"
        ).pack(side="left",padx=8)

        row=ttk.Frame(f,style="Panel.TFrame"); row.pack(fill="x",padx=18,pady=6)
        self.hold_net_label_var=tk.StringVar(value="Target network")
        ttk.Label(row,textvariable=self.hold_net_label_var,style="Panel.TLabel").pack(side="left")
        self.hold_net=tk.StringVar(); self.hold_net_combo=ttk.Combobox(row,textvariable=self.hold_net,width=52,state="readonly")
        self.hold_net_combo.pack(side="left",padx=6)
        self.hold_net.trace_add("write",lambda *_: self._holding_target_changed())
        self.hold_dry_button = ttk.Button(row,text="Dry Run",command=self.holding_preview)
        self.hold_dry_button.pack(side="left",padx=6)
        self.hold_move_button = ttk.Button(row,text="MOVE Hardware",style="Danger.TButton",command=self.holding_apply)
        self.hold_move_button.pack(side="left")
        self.hold_status_var = tk.StringVar(value="Ready")
        ttk.Label(row,textvariable=self.hold_status_var,style="Panel.TLabel").pack(side="left",padx=12)

        self.hold_inventory_button_row=ttk.Frame(f,style="Panel.TFrame")
        self.hold_inventory_button_row.pack(fill="x",padx=18,pady=4)
        self.hold_list_button = ttk.Button(self.hold_inventory_button_row,text="List Holding Inventory",command=self.holding_list)
        self.hold_list_button.pack(side="left")
        self.offboard_select_all_button=ttk.Button(self.hold_inventory_button_row,text="Select All Devices",command=self._offboarding_select_all)
        self.offboard_clear_selection_button=ttk.Button(self.hold_inventory_button_row,text="Clear Selection",command=self._offboarding_clear_selection)
        cols=("serial","model","name","network")
        self.hold_tree=ttk.Treeview(f,columns=cols,show="headings",height=14,selectmode="extended")
        for c,w in zip(cols,(165,115,220,430)):
            self.hold_tree.heading(c,text=c.title()); self.hold_tree.column(c,width=w,anchor="w")
        self.hold_tree.pack(fill="both",expand=True,padx=18,pady=10)
        self.hold_tree.bind("<<TreeviewSelect>>",self._holding_pick)
        self.last_new_claim_preview=None
        self.last_holding_preview_signature=None
        self.last_offboarding_preview=None
        self._holding_direction_changed()

    def _build_launchers(self):
        f=self._panel("Safe Wrappers", "These proven scripts are bundled unchanged and can still be launched from the toolkit while we migrate their internals into native panels.")
        self.nb.add(f,text="More Tools")
        box=ttk.Frame(f,style="Panel.TFrame"); box.pack(fill="x",padx=18,pady=10)
        self.compliance_button = ttk.Button(box,text="Run Multi-Org Compliance Audit",style="Accent.TButton",command=self.launch_compliance)
        self.compliance_button.pack(anchor="w",pady=5)
        self.clone_wrapper_button = ttk.Button(box,text="Launch Legacy Clone Safe Wrapper",command=self.launch_clone_wrapper)
        self.clone_wrapper_button.pack(anchor="w",pady=5)
        self.more_status_var = tk.StringVar(value="Ready")
        ttk.Label(box,textvariable=self.more_status_var,style="Panel.TLabel").pack(anchor="w",pady=(8,0))
        ttk.Label(box,text="Compliance is read-only. Organization Cleanup now has its own native tab. Legacy clone keeps its original safety gates.",style="Panel.TLabel").pack(anchor="w",pady=(8,0))

    def write_log(self, msg):
        stamp=dt.datetime.now().strftime("%H:%M:%S")
        self.log.insert("end",f"[{stamp}] {msg}\n"); self.log.see("end")

    def _emit(self, kind, value): self.work_q.put((kind,value))
    def _drain_queue(self):
        try:
            while True:
                kind,val=self.work_q.get_nowait()
                if kind=="log": self.write_log(val)
                elif kind=="status": self.status_var.set(val)
                elif kind=="call": val()
                elif kind=="error": messagebox.showerror("Meraki MSP Toolkit",val)
        except queue.Empty: pass
        self.after(100,self._drain_queue)

    def worker(self, fn, on_finish=None):
        threading.Thread(target=self._worker_wrap,args=(fn,on_finish),daemon=True).start()
    def _worker_wrap(self,fn,on_finish=None):
        error = None
        try:
            fn()
        except Exception as exc:
            error = exc
            self._emit("log",f"ERROR: {exc}")
            self._emit("error",str(exc))
        finally:
            if on_finish:
                self._emit("call", lambda e=error: on_finish(e))

    @staticmethod
    def _set_buttons(buttons, state):
        for button in buttons:
            button.configure(state=state)

    def _finish_buttons(self, buttons, status_var, error=None):
        self._set_buttons(buttons, "normal")
        if error is not None:
            status_var.set("Failed")

    def require_api(self):
        if not self.api: raise RuntimeError("Connect to Meraki first.")
        return self.api

    def connect(self):
        key=self.key_entry.get().strip()
        if not key: messagebox.showwarning("API key","Enter your Meraki API key."); return
        if self.connect_button.instate(["disabled"]): return
        self.connect_button.configure(text="Connecting...", state="disabled")
        self.status_var.set("Connecting...")
        def work():
            api=MerakiAPI(key)
            orgs=api.get_all("/organizations")
            orgs=sorted(orgs,key=lambda x:(x.get("name") or "").lower())
            try:
                identity=api.get("/administered/identities/me") or {}
            except Exception:
                identity={}
            holding=next((o for o in orgs if (o.get("name") or "").casefold()=="hardware holding".casefold()),None)
            holding_networks=[]
            if holding:
                try:
                    holding_networks=api.get_all(f"/organizations/{urllib.parse.quote(str(holding['id']))}/networks")
                    holding_networks=sorted(holding_networks,key=lambda x:(x.get("name") or "").lower())
                except Exception:
                    holding_networks=[]
            def done():
                self.api=api; self.orgs=orgs
                self.current_identity=identity if isinstance(identity,dict) else {}
                self.holding_org=holding
                self.holding_networks=holding_networks
                vals=["ALL ORGANIZATIONS"]+[self._org_label(o) for o in orgs]
                self.org_combo["values"]=vals; self.selected_org_var.set("ALL ORGANIZATIONS")
                self.status_var.set(f"Connected · {len(orgs)} organizations")
                self.write_log(f"Connected. {len(orgs)} organizations available. API key retained in memory only.")
                if self.holding_org: self.write_log("Hardware Holding organization detected.")
                if self.current_identity.get("email"):
                    self.write_log(f"Authenticated Meraki identity: {self.current_identity.get('email')}")
                self._admin_identity_refresh() if hasattr(self,"admin_identity_var") else None
                self.on_org_change()
            self._emit("call",done)
        def finished(error):
            self.connect_button.configure(text="Connect / Refresh", state="normal")
            if error is not None: self.status_var.set("Connection failed")
        self.worker(work, finished)

    def _org_label(self,o):
        return f"{o.get('name','')}  [{o.get('id','')}]"
    def selected_orgs(self):
        if self.selected_org_var.get()=="ALL ORGANIZATIONS": return list(self.orgs)
        label=self.selected_org_var.get()
        return [o for o in self.orgs if self._org_label(o)==label]
    def selected_org(self):
        xs=self.selected_orgs()
        if len(xs)!=1: raise RuntimeError("Select one organization for this operation.")
        return xs[0]

    def on_org_change(self):
        self.networks=[]
        if hasattr(self, "last_build_signature"):
            self.last_build_signature=None
        if hasattr(self, "last_delete_signature"):
            self.last_delete_signature=None
        if not self.api: return
        try: org=self.selected_org()
        except Exception:
            self.alert_net_combo["values"]=[]; self.build_source_combo["values"]=[]
            if hasattr(self,"post_net_combo"):
                self.post_net_combo["values"]=[]; self.post_net_var.set("")
                self.post_apply_button.configure(state="disabled")
                self.last_postbuild_signature=None
                self._postbuild_target_changed(clear_alert_text=True)
                self.post_status_var.set("Select one organization at the top of the window.")
            if hasattr(self,"delete_net_combo"):
                self.delete_net_combo["values"]=[]; self.delete_net_var.set("")
                self.delete_scope_var.set("Select one organization at the top of the window.")
                self.delete_apply_button.configure(state="disabled")
                self.last_delete_preview=None
            if hasattr(self, "cleanup_scope_var"):
                self.cleanup_scope_var.set("Select one organization at the top of the window.")
                self._org_cleanup_reset(clear_text=True)
            if hasattr(self, "admin_network_tree"):
                self._admin_reset(clear_text=True)
                self._admin_refresh_network_tree([])
            self._refresh_holding_controls()
            return
        self._emit("status",f"Loading networks for {org.get('name')}...")
        def work():
            nets=self.require_api().get_all(f"/organizations/{urllib.parse.quote(str(org['id']))}/networks")
            nets=sorted(nets,key=lambda x:(x.get("name") or "").lower())
            def done():
                self.networks=nets
                vals=[self._net_label(n) for n in nets]
                self.alert_net_combo["values"]=vals; self.build_source_combo["values"]=vals
                if hasattr(self,"post_net_combo"):
                    self.post_net_combo["values"]=vals
                    preferred=getattr(self,"postbuild_preferred_network_name",None)
                    preferred_label=next((self._net_label(n) for n in nets if preferred and (n.get("name") or "")==preferred),None)
                    self.post_net_var.set(preferred_label or (vals[0] if vals else ""))
                    self.postbuild_preferred_network_name=None
                    self.post_status_var.set("Preview required" if vals else "No networks in selected organization")
                    self.post_apply_button.configure(state="disabled")
                    self.last_postbuild_signature=None
                    self._postbuild_target_changed(clear_alert_text=True)
                if hasattr(self,"delete_net_combo"):
                    self.delete_net_combo["values"]=vals
                    self.delete_scope_var.set(f"Organization locked for delete: {org.get('name')} [{org.get('id')}]")
                    self.delete_apply_button.configure(state="disabled")
                    self.last_delete_preview=None
                if hasattr(self, "cleanup_scope_var"):
                    self.cleanup_scope_var.set(f"Organization locked for cleanup: {org.get('name')} [{org.get('id')}]")
                    self._org_cleanup_reset(clear_text=True)
                if hasattr(self, "admin_network_tree"):
                    self._admin_reset(clear_text=True)
                    self._admin_refresh_network_tree(nets)
                if vals:
                    self.alert_net_var.set(vals[0]); self.build_source.set(vals[0])
                    if hasattr(self,"delete_net_var"):
                        self.delete_net_var.set(vals[0])
                else:
                    if hasattr(self,"delete_net_var"):
                        self.delete_net_var.set("")
                self._refresh_holding_controls()
                self.status_var.set(f"Connected · {len(self.orgs)} organizations · Selected org: {len(nets)} network{'s' if len(nets) != 1 else ''}")
            self._emit("call",done)
        self.worker(work)

    def _net_label(self,n): return f"{n.get('name','')}  [{n.get('id','')}]"
    def net_from_label(self,label):
        return next((n for n in self.networks if self._net_label(n)==label),None)

    # ---------------- Device Search ----------------
    def search_devices(self):
        if self.search_busy:
            self.search_status_var.set("Search already running...")
            return

        term = self.search_var.get().strip()
        if not term:
            messagebox.showwarning("Search", "Enter a MAC address or serial.")
            return

        # Snapshot the UI choices before the worker starts.
        try:
            org_scope = list(self.selected_orgs())
        except Exception as exc:
            messagebox.showerror("Search", str(exc))
            return
        include_clients = bool(self.search_clients_var.get())

        self.search_busy = True
        self.search_button.configure(text="Searching...", state="disabled")
        self.search_status_var.set("Working...")
        for item in self.search_tree.get_children():
            self.search_tree.delete(item)

        mac = norm_mac(term)
        serial = norm_serial(term)
        is_mac = len(mac) == 12
        self.write_log(f"Device search started for {term} across {len(org_scope)} organization(s).")

        def restore_ui(message):
            self.search_busy = False
            self.search_button.configure(text="Search", state="normal")
            self.search_status_var.set(message)

        def work():
            try:
                api = self.require_api()
                results = []
                total_orgs = len(org_scope)

                for index, org in enumerate(org_scope, start=1):
                    oid = org["id"]
                    oname = org.get("name", "")
                    self._emit("call", lambda i=index, n=oname, t=total_orgs: self.search_status_var.set(f"Searching {i}/{t}: {n}"))

                    try:
                        nets = api.get_all(f"/organizations/{oid}/networks")
                    except Exception:
                        nets = []
                    nmap = {n.get("id"): n.get("name", "") for n in nets}

                    try:
                        devices = api.get_all(f"/organizations/{oid}/devices")
                    except Exception:
                        devices = []
                    for d in devices:
                        hit = ((is_mac and norm_mac(str(d.get("mac", ""))) == mac) or
                               ((not is_mac) and norm_serial(str(d.get("serial", ""))) == serial))
                        if hit:
                            results.append((
                                "Device", oname, nmap.get(d.get("networkId"), ""),
                                d.get("name", "") or "", d.get("model", "") or "",
                                d.get("serial", "") or "", d.get("mac", "") or "",
                                d.get("lanIp", "") or ""
                            ))

                    try:
                        inv = api.get_all(f"/organizations/{oid}/inventory/devices")
                    except Exception:
                        inv = []
                    for d in inv:
                        hit = ((is_mac and norm_mac(str(d.get("mac", ""))) == mac) or
                               ((not is_mac) and norm_serial(str(d.get("serial", ""))) == serial))
                        if hit:
                            results.append((
                                "Inventory", oname, nmap.get(d.get("networkId"), "Unassigned"),
                                d.get("name", "") or "", d.get("model", "") or "",
                                d.get("serial", "") or "", d.get("mac", "") or "",
                                d.get("lanIp", "") or ""
                            ))

                    if is_mac and include_clients:
                        for n in nets:
                            try:
                                clients = api.get_all(f"/networks/{n['id']}/clients?timespan=2678400")
                            except Exception:
                                continue
                            for c in clients:
                                if norm_mac(str(c.get("mac", ""))) == mac:
                                    results.append((
                                        "Client", oname, n.get("name", "") or "",
                                        c.get("description", "") or c.get("dhcpHostname", "") or "",
                                        c.get("manufacturer", "") or "", "",
                                        c.get("mac", "") or "", c.get("ip", "") or ""
                                    ))

                # One search may find the same physical device through more than one API
                # endpoint. Collapse exact/near-identical device rows before displaying.
                unique = []
                seen = set()
                for row in results:
                    # For Device/Inventory, serial+org is the physical-device identity.
                    # For clients, MAC+org+network is the useful identity.
                    if row[0] in {"Device", "Inventory"} and row[5]:
                        key = ("hardware", row[1].casefold(), norm_serial(str(row[5])))
                    elif row[6]:
                        key = (row[0].casefold(), row[1].casefold(), row[2].casefold(), norm_mac(str(row[6])))
                    else:
                        key = tuple(str(v).casefold() for v in row)
                    if key in seen:
                        continue
                    seen.add(key)
                    unique.append(row)

                def done():
                    # Replace, never append, the visible result set.
                    for item in self.search_tree.get_children():
                        self.search_tree.delete(item)
                    for row in unique:
                        self.search_tree.insert("", "end", values=row)
                    count = len(unique)
                    label = "No matches found" if count == 0 else f"{count} match{'es' if count != 1 else ''} found"
                    restore_ui(label)
                    self.write_log(f"Device search complete: {count} match(es).")

                self._emit("call", done)

            except Exception as exc:
                def failed():
                    restore_ui("Search failed")
                self._emit("call", failed)
                self._emit("log", f"ERROR: device search failed: {exc}")
                self._emit("error", str(exc))

        self.worker(work)

    # ---------------- License ----------------
    def run_license_audit(self):
        if self.license_button.instate(["disabled"]):
            self.license_status_var.set("Audit already running...")
            return
        org_scope = list(self.selected_orgs())
        self.license_button.configure(text="Auditing...", state="disabled")
        self.license_status_var.set("Working...")
        for item in self.lic_tree.get_children(): self.lic_tree.delete(item)
        self.write_log(f"License audit started across {len(org_scope)} organization(s).")
        def parse_date(v):
            if not v:return None
            text=str(v).strip().replace("Z","+00:00")
            for fmt in ("%b %d, %Y UTC","%B %d, %Y UTC","%Y-%m-%d"):
                try:return dt.datetime.strptime(str(v),fmt).replace(tzinfo=dt.timezone.utc)
                except ValueError:pass
            try:
                d=dt.datetime.fromisoformat(text); return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
            except Exception:return None
        def work():
            api=self.require_api(); rows=[]; total=len(org_scope)
            for index,org in enumerate(org_scope,1):
                oname=org.get("name","")
                self._emit("call",lambda i=index,n=oname,t=total:self.license_status_var.set(f"Checking {i}/{t}: {n}"))
                try: ov=api.get(f"/organizations/{org['id']}/licenses/overview") or {}
                except Exception as e:
                    rows.append([oname,f"ERROR: {e}","","","","",""]); continue
                status=ov.get("status") or "Per-device / subscription"
                exp=ov.get("expirationDate") or ""
                parsed=parse_date(exp); days=(parsed.date()-dt.datetime.now(dt.timezone.utc).date()).days if parsed else ""
                states=ov.get("states") or {}
                cnt=lambda n:(states.get(n) or {}).get("count","") if isinstance(states.get(n),dict) else ""
                rows.append([oname,status,exp,days,cnt("active"),cnt("expiring"),cnt("expired")])
            path=REPORTS/f"license_audit_{nowstamp()}.csv"
            with path.open("w",newline="",encoding="utf-8-sig") as fh:
                w=csv.writer(fh); w.writerow(["Org","Status","Expiration","Days Remaining","Active","Expiring","Expired"]); w.writerows(rows)
            def done():
                for r in rows:self.lic_tree.insert("","end",values=r)
                self.license_status_var.set(f"Complete · {len(rows)} organization(s)")
                self.write_log(f"License audit complete. CSV: {path}")
            self._emit("call",done)
        def finished(error):
            self.license_button.configure(text="Run License Audit", state="normal")
            if error is not None:self.license_status_var.set("Audit failed")
        self.worker(work,finished)

    # ---------------- SSID ----------------
    @staticmethod
    def ssid_risk(s):
        if not s.get("enabled"): return "Disabled"
        auth=str(s.get("authMode") or "").lower(); enc=str(s.get("encryptionMode") or "").lower(); wpa=str(s.get("wpaEncryptionMode") or "").lower()
        if auth in {"open","open-with-radius","open-with-nac"} or "wep" in enc: return "High"
        if "wpa1" in wpa or auth in {"psk","psk-with-radius"}: return "Medium"
        if auth in {"8021x-meraki","8021x-radius","ipsk-with-radius","ipsk-without-radius"}: return "Low"
        return "Review"
    def run_ssid_audit(self):
        if self.ssid_button.instate(["disabled"]):
            self.ssid_status_var.set("Audit already running...")
            return
        org_scope=list(self.selected_orgs())
        self.ssid_button.configure(text="Auditing...", state="disabled")
        self.ssid_status_var.set("Working...")
        for item in self.ssid_tree.get_children(): self.ssid_tree.delete(item)
        self.write_log(f"SSID security audit started across {len(org_scope)} organization(s).")
        def work():
            api=self.require_api(); rows=[]; total=len(org_scope)
            for index,org in enumerate(org_scope,1):
                oname=org.get("name","")
                self._emit("call",lambda i=index,n=oname,t=total:self.ssid_status_var.set(f"Scanning {i}/{t}: {n}"))
                try:nets=api.get_all(f"/organizations/{org['id']}/networks")
                except Exception:continue
                for net in nets:
                    if "wireless" not in (net.get("productTypes") or []):continue
                    try:ssids=api.get(f"/networks/{net['id']}/wireless/ssids") or []
                    except Exception:continue
                    for ssid in ssids:
                        rows.append([self.ssid_risk(ssid),oname,net.get("name"),ssid.get("name"),ssid.get("enabled"),ssid.get("authMode"),ssid.get("encryptionMode"),ssid.get("wpaEncryptionMode")])
            path=REPORTS/f"ssid_security_{nowstamp()}.csv"
            with path.open("w",newline="",encoding="utf-8-sig") as fh:
                w=csv.writer(fh);w.writerow(["Risk","Org","Network","SSID","Enabled","Auth","Encryption","WPA"]);w.writerows(rows)
            def done():
                for r in rows:self.ssid_tree.insert("","end",values=r)
                self.ssid_status_var.set(f"Complete · {len(rows)} SSID(s)")
                self.write_log(f"SSID audit complete: {len(rows)} SSIDs. CSV: {path}")
            self._emit("call",done)
        def finished(error):
            self.ssid_button.configure(text="Run SSID Audit", state="normal")
            if error is not None:self.ssid_status_var.set("Audit failed")
        self.worker(work,finished)

    # ---------------- Alerts ----------------
    @staticmethod
    def _alert_plan_options(settings, timeout=5, require_changed=False):
        alerts=settings.get("alerts") or []; changes=[]; new=[]
        for a in alerts:
            b=json.loads(json.dumps(a)); typ=str(b.get("type") or "")
            if typ in REQUIRED_ALERTS and b.get("enabled") is not True:
                changes.append(f"{typ}: disabled -> enabled ({REQUIRED_ALERTS[typ]})"); b["enabled"]=True
            if typ in OFFLINE_ALERT_TYPES and b.get("enabled") is True:
                filters=b.get("filters") or {}; old=filters.get("timeout")
                if old is not None:
                    try: mismatch=int(old)!=int(timeout)
                    except Exception: mismatch=str(old)!=str(timeout)
                    if mismatch:
                        changes.append(f"{typ} timeout: {old} -> {timeout} minutes"); filters["timeout"]=int(timeout); b["filters"]=filters
            if typ=="settingsChanged" and require_changed and b.get("enabled") is not True:
                changes.append("settingsChanged: disabled -> enabled"); b["enabled"]=True
            new.append(b)
        payload={"defaultDestinations":json.loads(json.dumps(settings.get("defaultDestinations") or {})),"alerts":new}
        return changes,payload

    def _alert_plan(self, settings):
        timeout=int(self.timeout_var.get() or "5"); require_changed=self.settings_changed_var.get()
        return self._alert_plan_options(settings, timeout, require_changed)
    def alert_dry_run(self):
        net=self.net_from_label(self.alert_net_var.get())
        if not net: messagebox.showwarning("Network","Select a network.");return
        if self.alert_dry_button.instate(["disabled"]): return
        self._set_buttons([self.alert_dry_button,self.alert_apply_button],"disabled")
        self.alert_dry_button.configure(text="Checking...")
        self.alert_status_var.set("Reading alert settings...")
        self.alert_text.delete("1.0","end")
        def work():
            settings=self.require_api().get(f"/networks/{net['id']}/alerts/settings") or {}
            changes,_=self._alert_plan(settings)
            text=f"DRY RUN - {net.get('name')}\n"+"="*65+"\n"+("\n".join(f"- {x}" for x in changes) if changes else "No baseline changes required.")
            def done():
                self.alert_text.insert("end",text)
                self.alert_status_var.set(f"Dry run complete · {len(changes)} change(s)")
            self._emit("call",done)
            self._emit("log",f"Alert dry run complete for {net.get('name')}: {len(changes)} proposed change(s).")
        def finished(error):
            self.alert_dry_button.configure(text="Dry Run")
            self._finish_buttons([self.alert_dry_button,self.alert_apply_button],self.alert_status_var,error)
            if error is not None:self.alert_status_var.set("Dry run failed")
        self.worker(work,finished)
    def alert_apply(self):
        net=self.net_from_label(self.alert_net_var.get())
        if not net:return
        if self.alert_apply_button.instate(["disabled"]): return
        confirm=simpledialog.askstring("Confirm alert changes",f"Type APPLY to update alert settings for:\n{net.get('name')}")
        if confirm!="APPLY": return
        self._set_buttons([self.alert_dry_button,self.alert_apply_button],"disabled")
        self.alert_apply_button.configure(text="Applying...")
        self.alert_status_var.set("Applying approved changes...")
        def work():
            api=self.require_api(); settings=api.get(f"/networks/{net['id']}/alerts/settings") or {}; changes,payload=self._alert_plan(settings)
            if changes:
                api.put(f"/networks/{net['id']}/alerts/settings",payload)
                self._emit("log",f"Applied {len(changes)} approved alert baseline change(s) to {net.get('name')}.")
            else:
                self._emit("log","No alert changes required.")
            self._emit("call",lambda:self.alert_status_var.set("Verifying..."))
            verify=api.get(f"/networks/{net['id']}/alerts/settings") or {}
            remaining,_=self._alert_plan(verify)
            text=f"VERIFY - {net.get('name')}\n"+"="*65+"\n"+("\n".join(f"- Remaining: {x}" for x in remaining) if remaining else "Baseline verified. No approved changes remain.")
            def done():
                self.alert_text.delete("1.0","end"); self.alert_text.insert("end",text)
                self.alert_status_var.set(f"Apply complete · {len(changes)} change(s) · verified")
            self._emit("call",done)
        def finished(error):
            self.alert_apply_button.configure(text="Apply")
            self._finish_buttons([self.alert_dry_button,self.alert_apply_button],self.alert_status_var,error)
            if error is not None:self.alert_status_var.set("Apply failed")
        self.worker(work,finished)

    # ---------------- Post-build ----------------
    def _postbuild_target(self):
        org=self.selected_org()
        net=self.net_from_label(self.post_net_var.get())
        if not net:
            raise RuntimeError("Select a network for Post-Build Setup.")
        if str(net.get("organizationId") or org.get("id")) != str(org.get("id")):
            raise RuntimeError("Selected network does not belong to the selected organization.")
        return org,net

    def _postbuild_target_changed(self, clear_alert_text=False):
        self.last_postbuild_signature=None
        if hasattr(self,"post_apply_button"):
            self.post_apply_button.configure(state="disabled")
        if hasattr(self,"post_status_var"):
            self.post_status_var.set("Preview required")
        if clear_alert_text and hasattr(self,"post_text"):
            self.post_text.delete("1.0","end")
        if hasattr(self,"post_site_tree"):
            for iid in self.post_site_tree.get_children(): self.post_site_tree.delete(iid)
            self.post_site_devices=[]; self.post_site_current_network=None; self.last_post_site_signature=None
            self.post_site_street.set(""); self.post_site_line2.set(""); self.post_site_city.set("")
            self.post_site_state.set(""); self.post_site_postal.set(""); self.post_site_country.set("USA")
            self.post_site_preview_button.configure(state="disabled"); self.post_site_apply_button.configure(state="disabled")
            self.post_site_status_var.set("Load the selected network to review or set its physical site address.")
            self.post_site_text.delete("1.0","end")
        if hasattr(self,"post_wireless_tree"):
            for iid in self.post_wireless_tree.get_children(): self.post_wireless_tree.delete(iid)
            self.post_wireless_ssids=[]; self.post_wireless_current=None; self.last_post_wireless_signature=None
            self.post_wireless_number_var.set("-"); self.post_wireless_name_var.set(""); self.post_wireless_psk_var.set(""); self.post_wireless_pmf_var.set("Preserve current")
            self.post_wireless_preview_button.configure(state="disabled"); self.post_wireless_apply_button.configure(state="disabled")
            self.post_wireless_status_var.set("Refresh to load SSIDs for the selected network.")
            self.post_wireless_text.delete("1.0","end")
        if hasattr(self,"post_switch_tree"):
            for iid in self.post_switch_tree.get_children(): self.post_switch_tree.delete(iid)
            self.post_switch_devices=[]; self.post_switch_current_device=None; self.post_switch_current_mgmt=None; self.last_post_switch_signature=None
            self.post_switch_serial_var.set("-"); self.post_switch_name_var.set("")
            self.post_switch_preview_button.configure(state="disabled"); self.post_switch_apply_button.configure(state="disabled")
            self.post_switch_status_var.set("Move switch hardware into the network, then refresh here.")
            self.post_switch_text.delete("1.0","end")
        if hasattr(self,"post_appliance_tree"):
            for iid in self.post_appliance_tree.get_children(): self.post_appliance_tree.delete(iid)
            self.post_appliance_devices=[]; self.post_appliance_current_device=None; self.last_post_appliance_signature=None
            self.post_appliance_serial_var.set("-"); self.post_appliance_name_var.set("")
            self.post_appliance_preview_button.configure(state="disabled"); self.post_appliance_apply_button.configure(state="disabled")
            self.post_appliance_status_var.set("Move the MX/Z into the network, then inspect WAN settings or set the appliance name here.")
            self.post_appliance_text.delete("1.0","end")

    def _post_site_form_data(self):
        return normalize_site_address({
            "street": self.post_site_street.get(),
            "line2": self.post_site_line2.get(),
            "city": self.post_site_city.get(),
            "state": self.post_site_state.get(),
            "postal": self.post_site_postal.get(),
            "country": self.post_site_country.get(),
        })

    @staticmethod
    def _post_site_signature(org, net, site, move_marker, serials):
        return json.dumps({
            "orgId": str(org.get("id")),
            "networkId": str(net.get("id")),
            "site": normalize_site_address(site),
            "moveMapMarker": bool(move_marker),
            "serials": sorted(norm_serial(str(x)) for x in serials),
        }, sort_keys=True, separators=(",", ":"))

    def _apply_site_address_to_devices(self, api, network_id, serials, move_marker=True):
        """Apply a stored site address and verify it from the destination network device list.

        The network-stored site address is authoritative. Device address/map-marker updates use
        Meraki's generic PUT /devices/{serial} endpoint when available. Some legacy/EOL devices
        can remain visible in a network while that generic device write path returns HTTP 404.
        In that case the site metadata stays safely stored on the network and the per-device
        result is WARN rather than turning an otherwise verified hardware move into a failure.
        """
        qnid=urllib.parse.quote(str(network_id))
        network=api.get(f"/networks/{qnid}") or {}
        site=site_address_from_notes(network.get("notes") or "")
        full=format_site_address(site)
        if not full:
            return {"configured":False,"verified":True,"warnings":0,"failures":0,"address":"","results":[]}

        def network_devices():
            return list(api.get_all(f"/networks/{qnid}/devices") or [])

        def find_member(devices, serial):
            key=norm_serial(serial)
            return next((d for d in devices if norm_serial(str(d.get("serial") or ""))==key),None)

        results=[]
        for serial in serials:
            serial=str(serial).strip()
            if not serial:
                continue
            qserial=urllib.parse.quote(serial, safe="")
            path=f"/devices/{qserial}"
            try:
                members=network_devices()
                member=find_member(members,serial)
                if not member:
                    raise RuntimeError(f"Device {serial} is not present in destination network {network_id}; address write was not attempted.")

                payload={"address":full,"moveMapMarker":bool(move_marker)}
                last_exc=None
                updated=False
                marker_fallback=False
                # A newly moved device can briefly return 404 on the global device write path.
                for attempt in range(8):
                    try:
                        api.put(path,payload)
                        updated=True
                        break
                    except Exception as exc:
                        last_exc=exc
                        if "HTTP 404" in str(exc) and attempt < 7:
                            if not find_member(network_devices(),serial):
                                raise RuntimeError(f"Device {serial} disappeared from destination network {network_id} during address propagation wait.") from exc
                            time.sleep(1.5)
                            continue
                        break

                # If Meraki rejects the geocoding/map-marker variant with 404, try storing just
                # the physical address. This preserves useful device metadata even when marker
                # relocation is not available for that model/backend path.
                if not updated and move_marker and last_exc and "HTTP 404" in str(last_exc):
                    for attempt in range(4):
                        try:
                            api.put(path,{"address":full})
                            updated=True
                            marker_fallback=True
                            break
                        except Exception as exc:
                            last_exc=exc
                            if "HTTP 404" in str(exc) and attempt < 3:
                                time.sleep(1.5)
                                continue
                            break

                if not updated:
                    if last_exc and "HTTP 404" in str(last_exc):
                        results.append({
                            "serial":serial,"status":"WARN","ok":False,"blocking":False,
                            "detail":"Meraki's generic device update endpoint returned HTTP 404 for this assigned device. The site address remains stored on the network, but the device address/map marker could not be written through the public API."
                        })
                        continue
                    raise RuntimeError(f"Device address update failed: {last_exc}")

                check=None
                for attempt in range(8):
                    members=network_devices()
                    check=find_member(members,serial)
                    if check and str(check.get("address") or "").strip()==full:
                        break
                    if attempt < 7:
                        time.sleep(1.0)
                ok=bool(check) and str(check.get("address") or "").strip()==full
                if ok:
                    detail="Address verified from destination network inventory"
                    if marker_fallback:
                        detail += "; address saved, but map-marker relocation was not confirmed because Meraki rejected the geocoding variant"
                    results.append({"serial":serial,"status":"PASS","ok":True,"blocking":False,"detail":detail})
                else:
                    results.append({
                        "serial":serial,"status":"FAIL","ok":False,"blocking":True,
                        "detail":f"Device update returned successfully, but network read-back address did not match: {((check or {}).get('address') or '(blank)')}"
                    })
            except Exception as exc:
                results.append({"serial":serial,"status":"FAIL","ok":False,"blocking":True,"detail":str(exc)})

        failures=sum(1 for r in results if r.get("status")=="FAIL")
        warnings=sum(1 for r in results if r.get("status")=="WARN")
        verified=(failures==0 and warnings==0)
        return {
            "configured":True,
            "verified":verified,
            "nonblocking":failures==0,
            "warnings":warnings,
            "failures":failures,
            "address":full,
            "results":results,
        }


    def post_site_refresh(self):
        if self.post_site_load_button.instate(["disabled"]):
            return
        try:
            org,net=self._postbuild_target()
        except Exception as exc:
            messagebox.showerror("Post-Build Site / Location",str(exc)); return
        self.post_site_load_button.configure(state="disabled",text="Loading...")
        self.post_site_status_var.set("Reading network site address and assigned devices...")
        def work():
            api=self.require_api(); qnid=urllib.parse.quote(str(net["id"]))
            live=api.get(f"/networks/{qnid}") or {}
            devices=api.get_all(f"/networks/{qnid}/devices")
            site=site_address_from_notes(live.get("notes") or "")
            if not format_site_address(site):
                first=next((str(d.get("address") or "").strip() for d in devices if str(d.get("address") or "").strip()),"")
                if first:
                    site=normalize_site_address({"street":first})
            def done():
                self.post_site_current_network=live; self.post_site_devices=list(devices); self.last_post_site_signature=None
                self.post_site_street.set(site.get("street","") or ""); self.post_site_line2.set(site.get("line2","") or "")
                self.post_site_city.set(site.get("city","") or ""); self.post_site_state.set(site.get("state","") or "")
                self.post_site_postal.set(site.get("postal","") or ""); self.post_site_country.set(site.get("country","") or ("USA" if not format_site_address(site) else ""))
                for iid in self.post_site_tree.get_children(): self.post_site_tree.delete(iid)
                for d in devices:
                    self.post_site_tree.insert("","end",values=(d.get("name") or "(blank)",d.get("model") or "",d.get("serial") or "",d.get("address") or ""))
                full=format_site_address(site)
                self.post_site_text.delete("1.0","end")
                self.post_site_text.insert("end","MERAKI POST-BUILD SITE / LOCATION\n"+"="*72+"\n\n")
                self.post_site_text.insert("end",f"Organization : {org.get('name')} [{org.get('id')}]\nNetwork      : {net.get('name')} [{net.get('id')}]\n")
                self.post_site_text.insert("end",f"Stored site : {full or '(not set)'}\nDevices     : {len(devices)} assigned\n\n")
                self.post_site_text.insert("end","Set or edit the physical address above, then Preview. The address is stored in network notes and can be applied to every assigned device.\n")
                self.post_site_preview_button.configure(state="normal"); self.post_site_apply_button.configure(state="disabled")
                self.post_site_status_var.set(f"Loaded · {len(devices)} device(s) · {'address found' if full else 'address not set'}")
            self._emit("call",done)
        def finished(error):
            self.post_site_load_button.configure(state="normal",text="Load Current Site")
            if error is not None:
                self.post_site_status_var.set("Load failed")
                messagebox.showerror("Post-Build Site / Location",str(error))
        self.worker(work,finished)

    def post_site_preview(self):
        try:
            org,net=self._postbuild_target(); site=self._post_site_form_data(); full=format_site_address(site)
            if not full:
                raise RuntimeError("Enter a physical site address before Preview.")
        except Exception as exc:
            messagebox.showerror("Post-Build Site / Location",str(exc)); return
        self.post_site_status_var.set("Building site-address dry run...")
        def work():
            api=self.require_api(); qnid=urllib.parse.quote(str(net["id"]))
            live=api.get(f"/networks/{qnid}") or {}; devices=api.get_all(f"/networks/{qnid}/devices")
            current_site=site_address_from_notes(live.get("notes") or ""); current_full=format_site_address(current_site)
            serials=[str(d.get("serial") or "") for d in devices if d.get("serial")]
            signature=self._post_site_signature(org,net,site,self.post_site_move_marker_var.get(),serials)
            lines=[
                "MERAKI POST-BUILD SITE / LOCATION","="*72,"DRY RUN - NO CHANGES WILL BE MADE","",
                f"Organization : {org.get('name')} [{org.get('id')}]",f"Network      : {net.get('name')} [{net.get('id')}]","",
                "SITE ADDRESS","------------",f"Current      : {current_full or '(not set)'}",f"Proposed     : {full}",
                f"Move map marker: {'YES' if self.post_site_move_marker_var.get() else 'NO'}","",
                "ASSIGNED DEVICES","----------------",
            ]
            if devices:
                for d in devices:
                    cur=str(d.get("address") or "").strip() or "(blank)"
                    action="no address change" if cur==full else f"{cur} -> {full}"
                    lines.append(f"- {d.get('model') or '?'} {d.get('serial') or '?'} | {action}")
            else:
                lines.append("- None assigned. The site address will still be stored on the network; future Hardware / Inventory assignments will inherit it automatically.")
            lines += ["","WHAT APPLY + VERIFY WILL DO","---------------------------",
                      "1. Store the structured physical site address in the network notes while preserving unrelated notes.",
                      "2. Apply the formatted address to every currently assigned Meraki device.",
                      ("3. Ask Meraki to move each device map marker from the address." if self.post_site_move_marker_var.get() else "3. Preserve existing device map-marker coordinates."),
                      "4. Re-read the network and every device and report PASS/FAIL.",
                      "","Typed confirmation required: APPLY SITE"]
            text="\n".join(lines)
            report_dir=REPORTS/"PostBuild"/"SiteLocation"; report_dir.mkdir(parents=True,exist_ok=True)
            path=report_dir/f"Site-Location-Preview_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_{nowstamp()}.txt"
            path.write_text(text+"\n",encoding="utf-8")
            def done():
                self.post_site_current_network=live; self.post_site_devices=list(devices); self.last_post_site_signature=signature
                self.post_site_text.delete("1.0","end"); self.post_site_text.insert("end",text)
                self.post_site_apply_button.configure(state="normal"); self.post_site_status_var.set("Preview ready · no changes made")
            self._emit("call",done)
        def finished(error):
            if error is not None:
                self.post_site_apply_button.configure(state="disabled"); self.post_site_status_var.set("Preview failed")
                messagebox.showerror("Post-Build Site / Location",str(error))
        self.worker(work,finished)

    def post_site_apply(self):
        try:
            org,net=self._postbuild_target(); site=self._post_site_form_data(); full=format_site_address(site)
            if not full:
                raise RuntimeError("Enter a physical site address before Apply.")
        except Exception as exc:
            messagebox.showerror("Post-Build Site / Location",str(exc)); return
        if not self.last_post_site_signature:
            messagebox.showwarning("Preview required","Run Preview Site Address after your last change before applying."); return
        confirm=simpledialog.askstring("Apply Site Address",f"Type APPLY SITE to update the physical address for:\n{org.get('name')} / {net.get('name')}\n\n{full}")
        if confirm!="APPLY SITE": return
        self._set_buttons([self.post_site_load_button,self.post_site_preview_button,self.post_site_apply_button],"disabled")
        self.post_site_apply_button.configure(text="Applying..."); self.post_site_status_var.set("Re-validating target and device list...")
        def set_status(text): self._emit("call",lambda t=text:self.post_site_status_var.set(t))
        def work():
            api=self.require_api(); qnid=urllib.parse.quote(str(net["id"]))
            live=api.get(f"/networks/{qnid}") or {}; devices=api.get_all(f"/networks/{qnid}/devices")
            serials=[str(d.get("serial") or "") for d in devices if d.get("serial")]
            signature=self._post_site_signature(org,net,site,self.post_site_move_marker_var.get(),serials)
            if signature!=self.last_post_site_signature:
                raise RuntimeError("Site address, target network, map-marker choice, or assigned device list changed after Dry Run. Run Preview again.")
            set_status("Step 1/3 · Storing site address on network...")
            updated_notes=notes_with_site_address(live.get("notes") or "",site)
            api.put(f"/networks/{qnid}",{"notes":updated_notes})
            check_net=api.get(f"/networks/{qnid}") or {}
            stored_full=format_site_address(site_address_from_notes(check_net.get("notes") or ""))
            network_ok=(stored_full==full)
            if not network_ok:
                raise RuntimeError(f"Network notes write completed, but site-address read-back did not match. Read back: {stored_full or '(blank)'}")
            set_status(f"Step 2/3 · Applying address to {len(serials)} device(s)...")
            device_result=self._apply_site_address_to_devices(api,net["id"],serials,self.post_site_move_marker_var.get())
            set_status("Step 3/3 · Building verification report...")
            results=device_result.get("results") or []
            passed=sum(1 for r in results if r.get("status")=="PASS")
            warned=sum(1 for r in results if r.get("status")=="WARN")
            failed=sum(1 for r in results if r.get("status")=="FAIL")
            verified=network_ok and failed==0 and warned==0
            nonblocking=network_ok and failed==0
            overall="PASS" if verified else ("PASS WITH WARNINGS" if nonblocking else "FAIL")
            lines=["MERAKI POST-BUILD SITE / LOCATION","="*72,"APPLY + VERIFY RESULT","",
                   f"Organization : {org.get('name')} [{org.get('id')}]",f"Network      : {net.get('name')} [{net.get('id')}]",
                   f"Site address : {full}",f"Network notes: {'PASS' if network_ok else 'FAIL'}",
                   f"Devices      : {len(serials)}",f"Device PASS  : {passed}",f"Device WARN  : {warned}",f"Device FAIL  : {failed}","",
                   "VERIFICATION","------------",f"Overall      : {overall}"]
            if not serials:
                lines.append("- No devices are currently assigned. The network-stored address will auto-apply when hardware is moved/claimed into this network.")
            else:
                for r in results: lines.append(f"{r.get('status') or ('PASS' if r.get('ok') else 'FAIL')} - {r.get('serial')}: {r.get('detail')}")
            report_dir=REPORTS/"PostBuild"/"SiteLocation"; report_dir.mkdir(parents=True,exist_ok=True)
            path=report_dir/f"Site-Location-Verification_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_{nowstamp()}.txt"
            path.write_text("\n".join(lines)+"\n",encoding="utf-8")
            final_devices=api.get_all(f"/networks/{qnid}/devices")
            def done():
                for iid in self.post_site_tree.get_children(): self.post_site_tree.delete(iid)
                for d in final_devices: self.post_site_tree.insert("","end",values=(d.get("name") or "(blank)",d.get("model") or "",d.get("serial") or "",d.get("address") or ""))
                self.post_site_text.delete("1.0","end"); self.post_site_text.insert("end","\n".join(lines))
                self.post_site_status_var.set(f"Apply complete · {overall}")
                self.write_log(f"Post-Build Site / Location: {overall} | {org.get('name')} / {net.get('name')} | {path}")
            self._emit("call",done)
            if failed:
                raise RuntimeError("One or more device site-address verification checks failed. Review the Site / Location report.")
            if warned:
                self._emit("call",lambda: messagebox.showwarning(
                    "Site address stored · Device update warning",
                    "The network site address was stored successfully, but one or more assigned devices returned HTTP 404 on Meraki's generic device update endpoint. Review the Site / Location report."
                ))
        def finished(error):
            self.post_site_apply_button.configure(text="APPLY + VERIFY")
            self._finish_buttons([self.post_site_load_button,self.post_site_preview_button,self.post_site_apply_button],self.post_site_status_var,error)
            self.last_post_site_signature=None
            if error is not None: self.post_site_status_var.set("Site address apply failed or partially completed")
        self.worker(work,finished)

    @staticmethod
    def _ssid_display_vlan(ssid):
        if ssid.get("ipAssignmentMode") in {"Bridge mode","Layer 3 roaming"} and ssid.get("useVlanTagging"):
            return str(ssid.get("defaultVlanId") if ssid.get("defaultVlanId") is not None else "tagged")
        return "-"

    @staticmethod
    def _ssid_display_pmf(ssid):
        dot11w=ssid.get("dot11w") or {}
        if not dot11w.get("enabled"):
            return "Disabled"
        return "Required" if dot11w.get("required") else "Enabled"

    def post_wireless_refresh(self):
        if self.post_wireless_refresh_button.instate(["disabled"]): return
        try:
            org,net=self._postbuild_target()
        except Exception as exc:
            messagebox.showerror("Post-Build Wireless",str(exc)); return
        if "wireless" not in (net.get("productTypes") or []):
            messagebox.showinfo("Post-Build Wireless","The selected network does not have the wireless product type."); return
        self.post_wireless_refresh_button.configure(state="disabled",text="Loading...")
        self.post_wireless_status_var.set("Reading SSIDs...")
        def work():
            api=self.require_api()
            ssids=api.get(f"/networks/{urllib.parse.quote(str(net['id']))}/wireless/ssids") or []
            def done():
                self.post_wireless_ssids=list(ssids)
                for iid in self.post_wireless_tree.get_children(): self.post_wireless_tree.delete(iid)
                for ssid in self.post_wireless_ssids:
                    num=ssid.get("number")
                    self.post_wireless_tree.insert("", "end", iid=str(num), values=(
                        num,"YES" if ssid.get("enabled") else "NO",ssid.get("name") or "",
                        ssid.get("authMode") or "",ssid.get("wpaEncryptionMode") or "",
                        self._ssid_display_pmf(ssid),self._ssid_display_vlan(ssid),ssid.get("bandSelection") or ""
                    ))
                self.post_wireless_status_var.set(f"Loaded {len(self.post_wireless_ssids)} SSID slot(s). Select one to edit.")
                self.post_wireless_text.delete("1.0","end")
                self.post_wireless_text.insert("end",f"WIRELESS INVENTORY - {org.get('name')} / {net.get('name')}\n"+"="*72+"\n")
                enabled=[x for x in self.post_wireless_ssids if x.get("enabled")]
                self.post_wireless_text.insert("end",f"Enabled SSIDs: {len(enabled)} of {len(self.post_wireless_ssids)}\n")
                self.post_wireless_current=None; self.last_post_wireless_signature=None
                self.post_wireless_preview_button.configure(state="disabled"); self.post_wireless_apply_button.configure(state="disabled")
            self._emit("call",done)
        def finished(error):
            self.post_wireless_refresh_button.configure(state="normal",text="Refresh SSIDs")
            if error is not None: self.post_wireless_status_var.set("SSID refresh failed")
        self.worker(work,finished)

    def _post_wireless_on_select(self):
        sel=self.post_wireless_tree.selection()
        if not sel: return
        try: num=int(sel[0])
        except Exception: return
        ssid=next((x for x in self.post_wireless_ssids if int(x.get("number",-1))==num),None)
        if not ssid: return
        self.post_wireless_current=json.loads(json.dumps(ssid))
        self.post_wireless_number_var.set(str(num))
        self.post_wireless_enabled_var.set(bool(ssid.get("enabled")))
        self.post_wireless_name_var.set(ssid.get("name") or "")
        self.post_wireless_auth_var.set("Preserve current")
        self.post_wireless_wpa_var.set("Preserve current")
        self.post_wireless_pmf_var.set("Preserve current")
        self.post_wireless_psk_var.set("")
        self.post_wireless_addressing_var.set("Preserve current")
        self.post_wireless_vlan_var.set(str(ssid.get("defaultVlanId")) if ssid.get("useVlanTagging") and ssid.get("defaultVlanId") is not None else "")
        self.post_wireless_band_var.set("Preserve current")
        self.post_wireless_visible_var.set(bool(ssid.get("visible",True)))
        self.post_wireless_isolation_var.set(bool(ssid.get("lanIsolationEnabled",False)))
        self.last_post_wireless_signature=None
        self.post_wireless_preview_button.configure(state="normal"); self.post_wireless_apply_button.configure(state="disabled")
        self.post_wireless_status_var.set(f"Editing SSID {num}: {ssid.get('name') or '(unnamed)'}")

    @staticmethod
    def _validate_psk(psk):
        if not psk: return
        if len(psk)==64 and re.fullmatch(r"[0-9A-Fa-f]{64}",psk): return
        if 8 <= len(psk) <= 63: return
        raise RuntimeError("PSK must be 8-63 characters, or exactly 64 hexadecimal characters.")

    def _post_wireless_plan(self):
        org,net=self._postbuild_target()
        current=self.post_wireless_current
        if not current:
            raise RuntimeError("Select an SSID first.")
        payload={}
        payload["enabled"]=bool(self.post_wireless_enabled_var.get())
        name=self.post_wireless_name_var.get().strip()
        if not name: raise RuntimeError("SSID name cannot be blank.")
        payload["name"]=name
        auth=self.post_wireless_auth_var.get()
        if auth!="Preserve current": payload["authMode"]=auth
        effective_auth=payload.get("authMode",current.get("authMode"))
        if effective_auth=="psk":
            payload["encryptionMode"]="wpa"
            wpa=self.post_wireless_wpa_var.get()
            if wpa!="Preserve current": payload["wpaEncryptionMode"]=wpa
            psk=self.post_wireless_psk_var.get()
            self._validate_psk(psk)
            if current.get("authMode")!="psk" and payload.get("authMode")=="psk" and not psk:
                raise RuntimeError("Changing an SSID to PSK authentication requires a new PSK.")
            if psk: payload["psk"]=psk
        elif auth=="open":
            payload["encryptionMode"]="open"

        # Protected Management Frames (802.11w / PMF). Meraki requires
        # compatible PMF settings when WPA3 is selected. If the operator
        # leaves PMF on Preserve current while deliberately changing WPA,
        # choose the safe compatible PMF state automatically.
        pmf_choice=self.post_wireless_pmf_var.get()
        pmf_map={
            "Disabled":{"enabled":False,"required":False},
            "Enabled":{"enabled":True,"required":False},
            "Required":{"enabled":True,"required":True},
        }
        if pmf_choice!="Preserve current":
            payload["dot11w"]=pmf_map[pmf_choice]

        requested_wpa=self.post_wireless_wpa_var.get() if effective_auth=="psk" else "Preserve current"
        if requested_wpa=="WPA3 only":
            if pmf_choice in {"Disabled","Enabled"}:
                raise RuntimeError("WPA3 only requires PMF / 802.11w = Required. Choose Required or Preserve current so the toolkit can set it automatically.")
            if pmf_choice=="Preserve current":
                payload["dot11w"]={"enabled":True,"required":True}
        elif requested_wpa=="WPA3 Transition Mode":
            if pmf_choice=="Disabled":
                raise RuntimeError("WPA3 Transition Mode requires PMF / 802.11w to be enabled. Choose Enabled, Required, or Preserve current.")
            if pmf_choice=="Preserve current":
                payload["dot11w"]={"enabled":True,"required":False}

        addressing=self.post_wireless_addressing_var.get()
        if addressing!="Preserve current": payload["ipAssignmentMode"]=addressing
        effective_addressing=payload.get("ipAssignmentMode",current.get("ipAssignmentMode"))
        vlan_raw=self.post_wireless_vlan_var.get().strip()
        if vlan_raw:
            try: vlan=int(vlan_raw)
            except Exception: raise RuntimeError("SSID VLAN ID must be a whole number.")
            if not 1 <= vlan <= 4094: raise RuntimeError("SSID VLAN ID must be between 1 and 4094.")
            if effective_addressing!="Bridge mode":
                raise RuntimeError("A VLAN ID requires Client addressing = Bridge mode.")
            payload["useVlanTagging"]=True; payload["defaultVlanId"]=vlan
        elif effective_addressing=="Bridge mode" and current.get("useVlanTagging"):
            # Blank VLAN intentionally removes the current fixed VLAN assignment.
            payload["useVlanTagging"]=False

        band=self.post_wireless_band_var.get()
        if band!="Preserve current": payload["bandSelection"]=band
        payload["visible"]=bool(self.post_wireless_visible_var.get())
        if effective_addressing=="Bridge mode": payload["lanIsolationEnabled"]=bool(self.post_wireless_isolation_var.get())

        number=int(current.get("number"))
        safe_payload=json.loads(json.dumps(payload)); safe_payload.pop("psk",None)
        signature=json.dumps({
            "orgId":str(org.get("id")),"networkId":str(net.get("id")),"number":number,
            "payload":safe_payload,
            "pskSha256":hashlib.sha256((payload.get("psk") or "").encode()).hexdigest() if payload.get("psk") else ""
        },sort_keys=True,separators=(",",":"))
        return org,net,current,number,payload,signature

    @staticmethod
    def _diff_pairs(current,payload):
        out=[]
        for k,v in payload.items():
            if k=="psk":
                out.append(("PSK","(preserved)","CHANGE REQUESTED")); continue
            old=current.get(k)
            if old!=v: out.append((k,old,v))
        return out

    def post_wireless_preview(self):
        try:
            org,net,current,number,payload,signature=self._post_wireless_plan()
        except Exception as exc:
            messagebox.showerror("Post-Build Wireless",str(exc)); return
        changes=self._diff_pairs(current,payload)
        lines=["MERAKI POST-BUILD WIRELESS","="*72,"DRY RUN - NO CHANGES WILL BE MADE","",
               f"Organization : {org.get('name')} [{org.get('id')}]",f"Network      : {net.get('name')} [{net.get('id')}]",
               f"SSID         : {number} | {current.get('name') or '(unnamed)'}","","PROPOSED CHANGES","----------------"]
        if changes:
            for field,old,new in changes: lines.append(f"- {field}: {old!s} -> {new!s}")
        else: lines.append("PASS - no changes detected.")
        lines += ["","SAFETY","------","- Only this SSID number will be updated.","- The PSK value is never printed or written to a report.","- WPA3 selections include the compatible Protected Management Frames (802.11w / PMF) state in the same API update.","- The SSID will be re-read after Apply and every non-secret field will be verified."]
        text="\n".join(lines)
        self.post_wireless_text.delete("1.0","end"); self.post_wireless_text.insert("end",text)
        self.last_post_wireless_signature=signature
        self.post_wireless_apply_button.configure(state="normal" if changes else "disabled")
        self.post_wireless_status_var.set("Preview complete" if changes else "No changes to apply")
        report_dir=REPORTS/"PostBuild"/"Wireless"; report_dir.mkdir(parents=True,exist_ok=True)
        path=report_dir/f"Wireless-Preview_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_SSID{number}_{nowstamp()}.txt"
        path.write_text(text+"\n",encoding="utf-8")

    def post_wireless_apply(self):
        try:
            org,net,current,number,payload,signature=self._post_wireless_plan()
        except Exception as exc:
            messagebox.showerror("Post-Build Wireless",str(exc)); return
        if not self.last_post_wireless_signature or signature!=self.last_post_wireless_signature:
            messagebox.showwarning("Preview required","Preview this exact SSID change before applying it."); return
        confirm=simpledialog.askstring("Apply SSID Change",f"Type APPLY SSID to update SSID {number} on:\n{org.get('name')} / {net.get('name')}")
        if confirm!="APPLY SSID": return
        self._set_buttons([self.post_wireless_refresh_button,self.post_wireless_preview_button,self.post_wireless_apply_button],"disabled")
        self.post_wireless_status_var.set("Applying SSID change...")
        def work():
            api=self.require_api()
            api.put(f"/networks/{urllib.parse.quote(str(net['id']))}/wireless/ssids/{number}",payload)
            ssids=api.get(f"/networks/{urllib.parse.quote(str(net['id']))}/wireless/ssids") or []
            after=next((x for x in ssids if int(x.get("number",-1))==number),None)
            if not after: raise RuntimeError("SSID update returned but the SSID could not be re-read for verification.")
            verify=[]
            for k,v in payload.items():
                if k=="psk": continue
                if after.get(k)!=v: verify.append(f"{k}: expected {v!s}, got {after.get(k)!s}")
            lines=["MERAKI POST-BUILD WIRELESS","="*72,"APPLY + VERIFY RESULT","",
                   f"Organization : {org.get('name')} [{org.get('id')}]",f"Network      : {net.get('name')} [{net.get('id')}]",f"SSID         : {number}",""]
            lines.append("Verification : "+("PASS" if not verify else "FAIL"))
            if payload.get("psk"): lines.append("PSK          : API accepted change; secret value was not re-displayed or logged.")
            for item in verify: lines.append("- "+item)
            text="\n".join(lines)
            report_dir=REPORTS/"PostBuild"/"Wireless"; report_dir.mkdir(parents=True,exist_ok=True)
            path=report_dir/f"Wireless-Verification_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_SSID{number}_{nowstamp()}.txt"
            path.write_text(text+"\n",encoding="utf-8")
            def done():
                self.post_wireless_text.delete("1.0","end"); self.post_wireless_text.insert("end",text)
                self.last_post_wireless_signature=None; self.post_wireless_apply_button.configure(state="disabled")
                self.post_wireless_status_var.set("SSID VERIFIED" if not verify else "SSID verification failed")
                self.write_log(f"Post-build SSID {number} update verified for {org.get('name')} / {net.get('name')}. TXT: {path}")
            self._emit("call",done)
        def finished(error):
            self.post_wireless_refresh_button.configure(state="normal")
            self.post_wireless_preview_button.configure(state="normal" if self.post_wireless_current else "disabled")
            self.post_wireless_apply_button.configure(state="disabled")
            if error is not None: self.post_wireless_status_var.set("SSID apply / verify failed")
        self.worker(work,finished)

    def post_switch_refresh(self):
        if self.post_switch_refresh_button.instate(["disabled"]): return
        try:
            org,net=self._postbuild_target()
        except Exception as exc:
            messagebox.showerror("Post-Build Switches",str(exc)); return
        if "switch" not in (net.get("productTypes") or []):
            messagebox.showinfo("Post-Build Switches","The selected network does not have the switch product type."); return
        self.post_switch_refresh_button.configure(state="disabled",text="Loading...")
        self.post_switch_status_var.set("Reading assigned switches...")
        def work():
            devices=self.require_api().get(f"/networks/{urllib.parse.quote(str(net['id']))}/devices") or []
            switches=[d for d in devices if d.get("productType")=="switch" or str(d.get("model") or "").upper().startswith(("MS","C9"))]
            def done():
                self.post_switch_devices=switches
                for iid in self.post_switch_tree.get_children(): self.post_switch_tree.delete(iid)
                for d in switches:
                    serial=str(d.get("serial") or "")
                    self.post_switch_tree.insert("","end",iid=serial,values=(d.get("name") or "(blank)",d.get("model") or "",serial,d.get("lanIp") or "",d.get("mac") or ""))
                self.post_switch_status_var.set(f"Loaded {len(switches)} switch(es)." if switches else "No switches are assigned yet. Move hardware first, then refresh.")
                self.post_switch_current_device=None; self.post_switch_current_mgmt=None; self.last_post_switch_signature=None
                self.post_switch_preview_button.configure(state="disabled"); self.post_switch_apply_button.configure(state="disabled")
                self.post_switch_text.delete("1.0","end")
            self._emit("call",done)
        def finished(error):
            self.post_switch_refresh_button.configure(state="normal",text="Refresh Switches")
            if error is not None: self.post_switch_status_var.set("Switch refresh failed")
        self.worker(work,finished)

    def _post_switch_on_select(self):
        sel=self.post_switch_tree.selection()
        if not sel: return
        serial=sel[0]
        device=next((d for d in self.post_switch_devices if str(d.get("serial"))==serial),None)
        if not device: return
        self.post_switch_status_var.set(f"Reading management interface for {serial}...")
        self.post_switch_preview_button.configure(state="disabled"); self.post_switch_apply_button.configure(state="disabled")
        def work():
            mgmt=self.require_api().get(f"/devices/{urllib.parse.quote(serial)}/managementInterface") or {}
            def done():
                self.post_switch_current_device=json.loads(json.dumps(device)); self.post_switch_current_mgmt=json.loads(json.dumps(mgmt))
                wan1=mgmt.get("wan1") or {}
                self.post_switch_serial_var.set(serial); self.post_switch_name_var.set(device.get("name") or "")
                self.post_switch_ipmode_var.set("Static" if wan1.get("usingStaticIp") else "DHCP")
                self.post_switch_ip_var.set(wan1.get("staticIp") or ""); self.post_switch_mask_var.set(wan1.get("staticSubnetMask") or "")
                self.post_switch_gateway_var.set(wan1.get("staticGatewayIp") or ""); self.post_switch_dns_var.set(", ".join(wan1.get("staticDns") or []))
                self.post_switch_vlan_var.set("" if wan1.get("vlan") is None else str(wan1.get("vlan")))
                self.last_post_switch_signature=None; self.post_switch_preview_button.configure(state="normal"); self.post_switch_apply_button.configure(state="disabled")
                self.post_switch_status_var.set(f"Editing {device.get('name') or serial} · {device.get('model') or ''}")
                self.post_switch_text.delete("1.0","end")
                lines=["MERAKI POST-BUILD SWITCH MANAGEMENT","="*72,"CURRENT SETTINGS","",
                       f"Name            : {device.get('name') or '(blank)'}",
                       f"Model           : {device.get('model') or ''}",
                       f"Serial          : {serial}",
                       f"Dashboard LAN IP: {device.get('lanIp') or '(not reported)'}",
                       f"IP assignment   : {'Static' if wan1.get('usingStaticIp') else 'DHCP'}",
                       f"Management VLAN : {wan1.get('vlan') if wan1.get('vlan') is not None else '(none)'}"]
                if wan1.get("usingStaticIp"):
                    lines += [f"Static IP       : {wan1.get('staticIp') or '(blank)'}",
                              f"Subnet mask     : {wan1.get('staticSubnetMask') or '(blank)'}",
                              f"Gateway         : {wan1.get('staticGatewayIp') or '(blank)'}",
                              f"DNS             : {', '.join(wan1.get('staticDns') or []) or '(blank)'}"]
                self.post_switch_text.insert("end","\n".join(lines))
            self._emit("call",done)
        def finished(error):
            if error is not None: self.post_switch_status_var.set("Could not read switch management interface")
        self.worker(work,finished)

    @staticmethod
    def _parse_dns_ips(value):
        out=[]
        for raw in re.split(r"[;,\s]+",value or ""):
            raw=raw.strip()
            if not raw: continue
            try: ipaddress.ip_address(raw)
            except Exception: raise RuntimeError(f"Invalid DNS IP: {raw}")
            if raw not in out: out.append(raw)
        if len(out)>2: raise RuntimeError("Meraki management interface supports up to two static DNS addresses.")
        return out

    def _post_switch_plan(self):
        org,net=self._postbuild_target()
        device=self.post_switch_current_device; mgmt=self.post_switch_current_mgmt
        if not device or mgmt is None: raise RuntimeError("Select a switch and wait for its management interface to load.")
        serial=str(device.get("serial") or "")
        new_name=self.post_switch_name_var.get().strip()
        name_payload={}
        if new_name != (device.get("name") or ""): name_payload["name"]=new_name or None
        wan1={}
        mode=self.post_switch_ipmode_var.get()
        vlan_raw=self.post_switch_vlan_var.get().strip()
        vlan=None
        if vlan_raw:
            try: vlan=int(vlan_raw)
            except Exception: raise RuntimeError("Management VLAN must be a whole number.")
            if not 1 <= vlan <= 4094: raise RuntimeError("Management VLAN must be between 1 and 4094.")
        wan1["usingStaticIp"]=(mode=="Static")
        wan1["vlan"]=vlan
        if mode=="Static":
            ip=self.post_switch_ip_var.get().strip(); mask=self.post_switch_mask_var.get().strip(); gw=self.post_switch_gateway_var.get().strip()
            if not ip or not mask or not gw: raise RuntimeError("Static management IP requires IP, subnet mask, and gateway.")
            try:
                ip_obj=ipaddress.ip_address(ip); gw_obj=ipaddress.ip_address(gw)
                net_obj=ipaddress.ip_network(f"{ip}/{mask}",strict=False)
            except Exception as exc: raise RuntimeError(f"Invalid static management IP settings: {exc}")
            if ip_obj not in net_obj or ip_obj in {net_obj.network_address,net_obj.broadcast_address}: raise RuntimeError("Switch static IP must be a usable address inside the subnet.")
            if gw_obj not in net_obj: raise RuntimeError("Switch gateway must be inside the same management subnet.")
            wan1.update({"staticIp":ip,"staticSubnetMask":str(net_obj.netmask),"staticGatewayIp":gw,"staticDns":self._parse_dns_ips(self.post_switch_dns_var.get())})
        mgmt_payload={"wan1":wan1}
        signature=json.dumps({"orgId":str(org.get("id")),"networkId":str(net.get("id")),"serial":serial,"name":name_payload,"mgmt":mgmt_payload},sort_keys=True,separators=(",",":"))
        return org,net,device,mgmt,serial,name_payload,mgmt_payload,signature

    def post_switch_preview(self):
        try:
            org,net,device,mgmt,serial,name_payload,mgmt_payload,signature=self._post_switch_plan()
        except Exception as exc:
            messagebox.showerror("Post-Build Switches",str(exc)); return
        current_wan1=mgmt.get("wan1") or {}
        changes=[]
        if name_payload: changes.append(f"Name: {device.get('name') or '(blank)'} -> {name_payload.get('name') or '(blank)'}")
        field_labels={
            "usingStaticIp":"IP assignment",
            "vlan":"Management VLAN",
            "staticIp":"Static IP",
            "staticSubnetMask":"Subnet mask",
            "staticGatewayIp":"Gateway",
            "staticDns":"DNS",
        }
        for field,new in mgmt_payload["wan1"].items():
            old=current_wan1.get(field)
            if old==new: continue
            label=field_labels.get(field,field)
            if field=="usingStaticIp":
                old_text="Static" if old else "DHCP"
                new_text="Static" if new else "DHCP"
            elif field=="staticDns":
                old_text=", ".join(old or []) or "(blank)"
                new_text=", ".join(new or []) or "(blank)"
            else:
                old_text="(none)" if old is None else str(old)
                new_text="(none)" if new is None else str(new)
            changes.append(f"{label}: {old_text} -> {new_text}")
        lines=["MERAKI POST-BUILD SWITCH MANAGEMENT","="*72,"DRY RUN - NO CHANGES WILL BE MADE","",
               f"Organization : {org.get('name')} [{org.get('id')}]",f"Network      : {net.get('name')} [{net.get('id')}]",
               f"Switch       : {device.get('model') or ''} | {serial}","","PROPOSED CHANGES","----------------"]
        lines += ["- "+x for x in changes] if changes else ["PASS - no changes detected."]
        lines += ["","SAFETY","------","- Only the selected switch serial will be changed.","- Device name and management-interface settings are written separately.","- Both are re-read after Apply and verified. A partial API failure is reported; no automatic rollback is attempted."]
        text="\n".join(lines)
        self.post_switch_text.delete("1.0","end"); self.post_switch_text.insert("end",text)
        self.last_post_switch_signature=signature; self.post_switch_apply_button.configure(state="normal" if changes else "disabled")
        self.post_switch_status_var.set("Preview complete" if changes else "No changes to apply")
        report_dir=REPORTS/"PostBuild"/"Switches"; report_dir.mkdir(parents=True,exist_ok=True)
        path=report_dir/f"Switch-Preview_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_{safe_filename(serial)}_{nowstamp()}.txt"
        path.write_text(text+"\n",encoding="utf-8")

    @staticmethod
    def _switch_dns_list(value):
        """Normalize Meraki DNS read-back into a predictable list of strings."""
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return [str(x) for x in value if str(x).strip()]
        if isinstance(value, str):
            return [x.strip() for x in re.split(r"[;,\s]+", value) if x.strip()]
        return [str(value)]

    def post_switch_apply(self):
        try:
            org,net,device,mgmt,serial,name_payload,mgmt_payload,signature=self._post_switch_plan()
        except Exception as exc:
            messagebox.showerror("Post-Build Switches",str(exc)); return
        if not self.last_post_switch_signature or signature!=self.last_post_switch_signature:
            messagebox.showwarning("Preview required","Preview this exact switch change before applying it."); return
        confirm=simpledialog.askstring("Apply Switch Change",f"Type APPLY SWITCH to update:\n{device.get('name') or serial} [{serial}]")
        if confirm!="APPLY SWITCH": return

        current_wan1=(mgmt.get("wan1") or {}) if isinstance(mgmt,dict) else {}
        planned_wan1=mgmt_payload.get("wan1") or {}
        mgmt_fields=("usingStaticIp","vlan","staticIp","staticSubnetMask","staticGatewayIp","staticDns")
        mgmt_changed=False
        for field in mgmt_fields:
            if field not in planned_wan1:
                continue
            old=current_wan1.get(field)
            new=planned_wan1.get(field)
            if field=="staticDns":
                old=self._switch_dns_list(old); new=self._switch_dns_list(new)
            if old!=new:
                mgmt_changed=True; break

        self._set_buttons([self.post_switch_refresh_button,self.post_switch_preview_button,self.post_switch_apply_button],"disabled")
        self.post_switch_status_var.set("Applying switch changes...")

        def work():
            api=self.require_api()
            write_results=[]
            verify_failures=[]
            after_dev={}
            after_mgmt={}

            # Write only what the dry run actually showed as changed.
            if name_payload:
                try:
                    api.put(f"/devices/{urllib.parse.quote(serial)}",name_payload)
                    write_results.append(("Device name","APPLIED",""))
                except Exception as exc:
                    write_results.append(("Device name","FAILED",str(exc)))
                    verify_failures.append(f"Device name write failed: {exc}")
            else:
                write_results.append(("Device name","SKIPPED","no change"))

            if mgmt_changed:
                try:
                    api.put(f"/devices/{urllib.parse.quote(serial)}/managementInterface",mgmt_payload)
                    write_results.append(("Management interface","APPLIED",""))
                except Exception as exc:
                    write_results.append(("Management interface","FAILED",str(exc)))
                    verify_failures.append(f"Management interface write failed: {exc}")
            else:
                write_results.append(("Management interface","SKIPPED","no change"))

            # Read back independently so one odd response cannot suppress the entire result report.
            try:
                raw=api.get(f"/devices/{urllib.parse.quote(serial)}")
                after_dev=raw if isinstance(raw,dict) else {}
                if not isinstance(raw,dict):
                    verify_failures.append(f"Device read-back returned unexpected type: {type(raw).__name__}")
            except Exception as exc:
                verify_failures.append(f"Device read-back failed: {exc}")

            try:
                raw=api.get(f"/devices/{urllib.parse.quote(serial)}/managementInterface")
                after_mgmt=raw if isinstance(raw,dict) else {}
                if not isinstance(raw,dict):
                    verify_failures.append(f"Management interface read-back returned unexpected type: {type(raw).__name__}")
            except Exception as exc:
                verify_failures.append(f"Management interface read-back failed: {exc}")

            if name_payload:
                actual_name=after_dev.get("name") if isinstance(after_dev,dict) else None
                if actual_name!=name_payload.get("name"):
                    verify_failures.append(f"Name expected {name_payload.get('name')!s}, got {actual_name!s}")

            after_wan1=(after_mgmt.get("wan1") or {}) if isinstance(after_mgmt,dict) else {}
            if not isinstance(after_wan1,dict):
                verify_failures.append(f"WAN1 read-back returned unexpected type: {type(after_wan1).__name__}")
                after_wan1={}

            if mgmt_changed:
                field_labels={
                    "usingStaticIp":"IP assignment",
                    "vlan":"Management VLAN",
                    "staticIp":"Static IP",
                    "staticSubnetMask":"Subnet mask",
                    "staticGatewayIp":"Gateway",
                    "staticDns":"DNS",
                }
                for field,new in planned_wan1.items():
                    actual=after_wan1.get(field)
                    if field=="staticDns":
                        actual=self._switch_dns_list(actual); new=self._switch_dns_list(new)
                    if actual!=new:
                        verify_failures.append(f"{field_labels.get(field,field)} expected {new!s}, got {actual!s}")

            verification="PASS" if not verify_failures else "FAIL"
            lines=["MERAKI POST-BUILD SWITCH MANAGEMENT","="*72,"APPLY + VERIFY RESULT","",
                   f"Organization : {org.get('name')} [{org.get('id')}]",f"Network      : {net.get('name')} [{net.get('id')}]",
                   f"Switch       : {after_dev.get('model') or device.get('model') or ''} | {serial}","",
                   "WRITE RESULT","------------"]
            for label,state,detail in write_results:
                suffix=f" - {detail}" if detail else ""
                lines.append(f"{label:<20}: {state}{suffix}")
            lines += ["",f"Verification : {verification}","","FINAL STATE","-----------",
                      f"Name            : {after_dev.get('name') or device.get('name') or '(blank)'}",
                      f"IP assignment   : {'Static' if after_wan1.get('usingStaticIp') else 'DHCP'}",
                      f"Management VLAN : {after_wan1.get('vlan') if after_wan1.get('vlan') is not None else '(none)'}"]
            if after_wan1.get("usingStaticIp"):
                dns_text=", ".join(self._switch_dns_list(after_wan1.get("staticDns"))) or "(blank)"
                lines += [f"Static IP       : {after_wan1.get('staticIp') or '(blank)'}",
                          f"Subnet mask     : {after_wan1.get('staticSubnetMask') or '(blank)'}",
                          f"Gateway         : {after_wan1.get('staticGatewayIp') or '(blank)'}",
                          f"DNS             : {dns_text}"]
            if verify_failures:
                lines += ["","VERIFICATION FAILURES","---------------------"]
                lines += ["- "+item for item in verify_failures]
            text="\n".join(lines)

            report_dir=REPORTS/"PostBuild"/"Switches"; report_dir.mkdir(parents=True,exist_ok=True)
            path=None; report_error=None
            try:
                path=report_dir/f"Switch-Verification_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_{safe_filename(serial)}_{nowstamp()}.txt"
                path.write_text(text+"\n",encoding="utf-8")
            except Exception as exc:
                report_error=str(exc)
                text += f"\n\nREPORT SAVE WARNING\n-------------------\n- Verification completed, but the TXT report could not be saved: {exc}"

            def done():
                self.post_switch_text.delete("1.0","end"); self.post_switch_text.insert("end",text)
                self.post_switch_text.see("1.0")
                # Keep the successful read-back as the new baseline.
                if isinstance(after_dev,dict) and after_dev:
                    self.post_switch_current_device=json.loads(json.dumps(after_dev))
                    self.post_switch_name_var.set(after_dev.get("name") or "")
                if isinstance(after_mgmt,dict) and after_mgmt:
                    self.post_switch_current_mgmt=json.loads(json.dumps(after_mgmt))
                self.last_post_switch_signature=None
                self.post_switch_apply_button.configure(state="disabled")
                self.post_switch_status_var.set("SWITCH VERIFIED" if verification=="PASS" else "Switch verification failed")
                if path:
                    self.write_log(f"Post-build switch update {verification} for {serial}. TXT: {path}")
                else:
                    self.write_log(f"Post-build switch update {verification} for {serial}. Report save warning: {report_error}")
            self._emit("call",done)

        def finished(error):
            self.post_switch_refresh_button.configure(state="normal")
            self.post_switch_preview_button.configure(state="normal" if self.post_switch_current_device else "disabled")
            self.post_switch_apply_button.configure(state="disabled")
            if error is not None:
                self.post_switch_status_var.set("Switch apply / verify failed")
        self.worker(work,finished)

    def post_appliance_refresh(self):
        if self.post_appliance_refresh_button.instate(["disabled"]): return
        try:
            org,net=self._postbuild_target()
        except Exception as exc:
            messagebox.showerror("Post-Build Appliance",str(exc)); return
        if "appliance" not in (net.get("productTypes") or []):
            messagebox.showinfo("Post-Build Appliance","The selected network does not have the appliance product type."); return
        self.post_appliance_refresh_button.configure(state="disabled",text="Inspecting...")
        self.post_appliance_status_var.set("Reading assigned appliance and WAN settings...")
        self.post_appliance_preview_button.configure(state="disabled"); self.post_appliance_apply_button.configure(state="disabled")
        def work():
            api=self.require_api(); qnid=urllib.parse.quote(str(net['id']))
            devices=api.get_all(f"/networks/{qnid}/devices") or []
            appliances=[d for d in devices if d.get("productType")=="appliance" or str(d.get("model") or "").upper().startswith(("MX","Z"))]
            blocks=[]
            for d in appliances:
                serial=str(d.get("serial") or "")
                try: mgmt=api.get(f"/devices/{urllib.parse.quote(serial, safe='')}/managementInterface") or {}
                except Exception as exc: mgmt={"readError":str(exc)}
                blocks.append({"device":json.loads(json.dumps(d)),"managementInterface":mgmt})
            def done():
                self.post_appliance_devices=[b["device"] for b in blocks]
                self.post_appliance_current_device=None; self.last_post_appliance_signature=None
                self.post_appliance_serial_var.set("-"); self.post_appliance_name_var.set("")
                for iid in self.post_appliance_tree.get_children(): self.post_appliance_tree.delete(iid)
                for d in self.post_appliance_devices:
                    serial=str(d.get("serial") or "")
                    self.post_appliance_tree.insert("","end",iid=serial,values=(d.get("name") or "(blank)",d.get("model") or "",serial,d.get("lanIp") or "",d.get("address") or ""))
                self.post_appliance_text.delete("1.0","end")
                self.post_appliance_text.insert("end","MERAKI POST-BUILD APPLIANCE INSPECTION\n"+"="*72+"\n")
                self.post_appliance_text.insert("end",f"Organization : {org.get('name')} [{org.get('id')}]\nNetwork      : {net.get('name')} [{net.get('id')}]\n\n")
                if not blocks:
                    self.post_appliance_text.insert("end","No MX/Z appliance is assigned yet. Move hardware first, then inspect again.\n")
                    self.post_appliance_status_var.set("No appliance assigned yet")
                else:
                    out=[]
                    for index,block in enumerate(blocks,1):
                        dev=block.get("device") or {}; mgmt=block.get("managementInterface") or {}
                        if index>1: out += ["", "-"*72, ""]
                        out += [
                            "APPLIANCE","---------",
                            f"Name    : {dev.get('name') or '(blank)'}",
                            f"Model   : {dev.get('model') or ''}",
                            f"Serial  : {dev.get('serial') or ''}",
                            f"LAN IP  : {dev.get('lanIp') or '(not reported)'}",
                            f"Address : {dev.get('address') or '(blank)'}",
                        ]
                        if mgmt.get("readError"):
                            out += ["",f"Management interface read failed: {mgmt.get('readError')}"]
                            continue
                        for label,key in (("WAN1","wan1"),("WAN2","wan2")):
                            iface=mgmt.get(key) or {}
                            enabled=str(iface.get("wanEnabled") or "").lower()
                            enabled_text="Disabled" if enabled=="disabled" else ("Enabled" if enabled=="enabled" else "Unknown")
                            using_static=bool(iface.get("usingStaticIp")); mode="Static" if using_static else "DHCP"
                            out += ["",label,"----",f"Status     : {enabled_text}"]
                            if enabled_text=="Disabled":
                                out += ["Addressing : Not in use"]
                            else:
                                out += [f"Addressing : {mode}",f"VLAN       : {iface.get('vlan') if iface.get('vlan') is not None else '(none / untagged)'}"]
                                if using_static:
                                    out += [f"IP address : {iface.get('staticIp') or '(blank)'}",f"Subnet mask: {iface.get('staticSubnetMask') or '(blank)'}",f"Gateway    : {iface.get('staticGatewayIp') or '(blank)'}",f"DNS        : {', '.join(iface.get('staticDns') or []) or '(blank)'}"]
                    self.post_appliance_text.insert("end","\n".join(out))
                    self.post_appliance_status_var.set(f"Inspected {len(blocks)} appliance(s) · WAN read-only · name editable")
                    if len(self.post_appliance_devices)==1:
                        serial=str(self.post_appliance_devices[0].get("serial") or "")
                        if serial:
                            self.post_appliance_tree.selection_set(serial)
                            self.post_appliance_tree.focus(serial)
                            self._post_appliance_on_select()
            self._emit("call",done)
        def finished(error):
            self.post_appliance_refresh_button.configure(state="normal",text="Refresh / Inspect Appliance")
            if error is not None: self.post_appliance_status_var.set("Appliance inspection failed")
        self.worker(work,finished)

    def _post_appliance_on_select(self):
        sel=self.post_appliance_tree.selection()
        if not sel: return
        serial=sel[0]
        device=next((d for d in self.post_appliance_devices if str(d.get("serial") or "")==serial),None)
        if not device: return
        self.post_appliance_current_device=json.loads(json.dumps(device))
        self.post_appliance_serial_var.set(serial)
        self.post_appliance_name_var.set(device.get("name") or "")
        self.last_post_appliance_signature=None
        self.post_appliance_preview_button.configure(state="normal"); self.post_appliance_apply_button.configure(state="disabled")
        suggested=f"{self.post_net_var.get().split(' [',1)[0]}-MX1" if not device.get("name") else ""
        suffix=f" · suggested name: {suggested}" if suggested else ""
        self.post_appliance_status_var.set(f"Selected {device.get('model') or 'appliance'} {serial}{suffix}")

    def _post_appliance_plan(self):
        org,net=self._postbuild_target(); device=self.post_appliance_current_device
        if not device: raise RuntimeError("Select an MX/Z appliance first.")
        serial=str(device.get("serial") or "").strip()
        if not serial: raise RuntimeError("Selected appliance has no serial number.")
        new_name=self.post_appliance_name_var.get().strip()
        old_name=str(device.get("name") or "")
        payload={}
        if new_name!=old_name: payload["name"]=new_name or None
        signature=json.dumps({"orgId":str(org.get("id")),"networkId":str(net.get("id")),"serial":serial,"payload":payload},sort_keys=True,separators=(",",":"))
        return org,net,device,serial,payload,signature

    def post_appliance_preview(self):
        try:
            org,net,device,serial,payload,signature=self._post_appliance_plan()
        except Exception as exc:
            messagebox.showerror("Post-Build Appliance",str(exc)); return
        lines=["MERAKI POST-BUILD APPLIANCE MANAGEMENT","="*72,"DRY RUN - NO CHANGES WILL BE MADE","",
               f"Organization : {org.get('name')} [{org.get('id')}]",f"Network      : {net.get('name')} [{net.get('id')}]",
               f"Appliance    : {device.get('model') or ''} | {serial}","","PROPOSED CHANGES","----------------"]
        if payload:
            lines.append(f"- Name: {device.get('name') or '(blank)'} -> {payload.get('name') or '(blank)'}")
        else:
            lines.append("PASS - no changes detected.")
        lines += ["","SAFETY","------","- Only the selected appliance serial will be changed.","- WAN1/WAN2 addressing remains read-only in this section.","- The appliance name is re-read from the selected network after Apply and verified."]
        text="\n".join(lines)
        self.post_appliance_text.delete("1.0","end"); self.post_appliance_text.insert("end",text)
        self.last_post_appliance_signature=signature
        self.post_appliance_apply_button.configure(state="normal" if payload else "disabled")
        self.post_appliance_status_var.set("Preview complete" if payload else "No changes to apply")
        report_dir=REPORTS/"PostBuild"/"Appliance"; report_dir.mkdir(parents=True,exist_ok=True)
        path=report_dir/f"Appliance-Preview_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_{safe_filename(serial)}_{nowstamp()}.txt"
        path.write_text(text+"\n",encoding="utf-8")

    def post_appliance_apply(self):
        try:
            org,net,device,serial,payload,signature=self._post_appliance_plan()
        except Exception as exc:
            messagebox.showerror("Post-Build Appliance",str(exc)); return
        if not payload:
            messagebox.showinfo("Post-Build Appliance","No appliance-name change is currently planned."); return
        if not self.last_post_appliance_signature or signature!=self.last_post_appliance_signature:
            messagebox.showwarning("Preview required","Preview this exact appliance-name change before applying it."); return
        confirm=simpledialog.askstring("Apply Appliance Name",f"Type APPLY APPLIANCE to update:\n{device.get('model') or 'MX/Z'} {serial}\n\nNew name: {payload.get('name') or '(blank)'}")
        if confirm!="APPLY APPLIANCE": return
        self._set_buttons([self.post_appliance_refresh_button,self.post_appliance_preview_button,self.post_appliance_apply_button],"disabled")
        self.post_appliance_apply_button.configure(text="Applying..."); self.post_appliance_status_var.set("Applying appliance name...")
        def work():
            api=self.require_api(); qnid=urllib.parse.quote(str(net['id'])); qserial=urllib.parse.quote(serial,safe="")
            write_state="APPLIED"; write_detail=""
            try:
                api.put(f"/devices/{qserial}",payload)
            except Exception as exc:
                write_state="FAILED"; write_detail=str(exc)
            after=None
            try:
                devices=api.get_all(f"/networks/{qnid}/devices") or []
                after=next((d for d in devices if norm_serial(str(d.get("serial") or ""))==norm_serial(serial)),None)
            except Exception as exc:
                if not write_detail: write_detail=f"Network read-back failed: {exc}"
            expected=payload.get("name")
            actual=(after or {}).get("name")
            verified=(write_state=="APPLIED" and after is not None and actual==expected)
            lines=["MERAKI POST-BUILD APPLIANCE MANAGEMENT","="*72,"APPLY + VERIFY RESULT","",
                   f"Organization : {org.get('name')} [{org.get('id')}]",f"Network      : {net.get('name')} [{net.get('id')}]",f"Appliance    : {(after or device).get('model') or ''} | {serial}","",
                   "WRITE RESULT","------------",f"Device name : {write_state}" + (f" - {write_detail}" if write_detail else ""),"",
                   f"Verification : {'PASS' if verified else 'FAIL'}","","FINAL STATE","-----------",f"Name         : {actual or '(blank)'}"]
            if not verified:
                if write_state=="FAILED" and "HTTP 404" in write_detail:
                    lines += ["","NOTE","----","Meraki returned HTTP 404 from the documented generic device-update endpoint for this serial. The appliance remains assigned and unchanged."]
                elif after is None:
                    lines += ["","VERIFICATION FAILURE","--------------------","- Appliance could not be re-read from the target network."]
                else:
                    lines += ["","VERIFICATION FAILURE","--------------------",f"- Expected name {expected!s}, got {actual!s}."]
            text="\n".join(lines)
            report_dir=REPORTS/"PostBuild"/"Appliance"; report_dir.mkdir(parents=True,exist_ok=True)
            path=report_dir/f"Appliance-Verification_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_{safe_filename(serial)}_{nowstamp()}.txt"
            path.write_text(text+"\n",encoding="utf-8")
            def done():
                self.post_appliance_text.delete("1.0","end"); self.post_appliance_text.insert("end",text)
                self.last_post_appliance_signature=None; self.post_appliance_apply_button.configure(state="disabled")
                if after is not None:
                    self.post_appliance_current_device=json.loads(json.dumps(after)); self.post_appliance_name_var.set(after.get("name") or "")
                    if self.post_appliance_tree.exists(serial):
                        self.post_appliance_tree.item(serial,values=(after.get("name") or "(blank)",after.get("model") or "",serial,after.get("lanIp") or "",after.get("address") or ""))
                self.post_appliance_status_var.set("APPLIANCE VERIFIED" if verified else "Appliance name verification failed")
                self.write_log(f"Post-build appliance name {'PASS' if verified else 'FAIL'} for {serial}. TXT: {path}")
            self._emit("call",done)
        def finished(error):
            self.post_appliance_refresh_button.configure(state="normal",text="Refresh / Inspect Appliance")
            self.post_appliance_preview_button.configure(state="normal" if self.post_appliance_current_device else "disabled")
            self.post_appliance_apply_button.configure(state="disabled",text="APPLY + VERIFY")
            if error is not None: self.post_appliance_status_var.set("Appliance name apply failed")
        self.worker(work,finished)

    @staticmethod
    def _parse_email_list(value):
        items=[]
        for raw in re.split(r"[;,\n]+", value or ""):
            email=raw.strip()
            if not email:
                continue
            if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
                raise RuntimeError(f"Invalid email address: {email}")
            if email.casefold() not in {x.casefold() for x in items}:
                items.append(email)
        return items

    def _postbuild_selected(self):
        org,net=self._postbuild_target()
        try:
            timeout=int(self.post_timeout_var.get() or "5")
        except Exception:
            raise RuntimeError("Offline timeout must be a whole number of minutes.")
        if timeout < 1:
            raise RuntimeError("Offline timeout must be at least 1 minute.")
        requested=self._parse_email_list(self.post_emails_var.get())
        return org,net,timeout,requested

    def _postbuild_signature(self, org, net, timeout, requested):
        return json.dumps({
            "orgId":str(org.get("id")),"networkId":str(net.get("id")),
            "timeout":int(timeout),"requireSettingsChanged":bool(self.post_settings_changed_var.get()),
            "applyBaseline":bool(self.post_apply_baseline_var.get()),
            "requestedEmails":[x.casefold() for x in requested],
        },sort_keys=True,separators=(",",":"))

    def _postbuild_assess(self, api, org, net, timeout, requested):
        settings=api.get(f"/networks/{urllib.parse.quote(str(net['id']))}/alerts/settings") or {}
        baseline_changes,baseline_payload=self._alert_plan_options(
            settings, timeout, self.post_settings_changed_var.get()
        )
        current_dest=json.loads(json.dumps(settings.get("defaultDestinations") or {}))
        existing_emails=list(current_dest.get("emails") or [])
        merged=[]
        for email in existing_emails + requested:
            if email and email.casefold() not in {x.casefold() for x in merged}:
                merged.append(email)
        proposed_dest=json.loads(json.dumps(current_dest))
        proposed_dest["emails"]=merged
        proposed_payload=json.loads(json.dumps(baseline_payload))
        proposed_payload["defaultDestinations"]=proposed_dest

        devices=[]
        try:
            devices=api.get(f"/networks/{urllib.parse.quote(str(net['id']))}/devices") or []
        except Exception:
            devices=[]

        ssid_findings=[]
        if "wireless" in (net.get("productTypes") or []):
            try:
                ssids=api.get(f"/networks/{urllib.parse.quote(str(net['id']))}/wireless/ssids") or []
                for ssid in ssids:
                    if not ssid.get("enabled"):
                        continue
                    risk=self.ssid_risk(ssid)
                    if risk in {"High","Medium","Review"}:
                        ssid_findings.append({
                            "name":ssid.get("name") or f"SSID {ssid.get('number')}",
                            "risk":risk,"auth":ssid.get("authMode"),"wpa":ssid.get("wpaEncryptionMode")
                        })
            except Exception as exc:
                ssid_findings.append({"name":"(unable to read SSIDs)","risk":"Review","auth":str(exc),"wpa":""})

        return {
            "settings":settings,"baselineChanges":baseline_changes,"payload":proposed_payload,
            "existingEmails":existing_emails,"proposedEmails":merged,
            "allAdmins":bool(current_dest.get("allAdmins")),"deviceCount":len(devices) if isinstance(devices,list) else 0,
            "ssidFindings":ssid_findings,
        }

    def _postbuild_report_text(self, org, net, assessment, mode="DRY RUN"):
        lines=[
            "MERAKI POST-BUILD SETUP", "="*72,
            f"{mode}", "",
            "TARGET", "------",
            f"Organization : {org.get('name')} [{org.get('id')}]",
            f"Network      : {net.get('name')} [{net.get('id')}]",
            f"Products     : {', '.join(net.get('productTypes') or []) or '(none)'}", "",
            "ALERT DESTINATIONS", "------------------",
            "Current default email(s) : " + (", ".join(assessment['existingEmails']) or "NONE"),
            "Proposed default email(s): " + (", ".join(assessment['proposedEmails']) or "NONE"),
            f"All admins destination    : {'YES' if assessment['allAdmins'] else 'NO'}", "",
            "APPROVED ALERT BASELINE", "-----------------------",
        ]
        if self.post_apply_baseline_var.get():
            if assessment['baselineChanges']:
                lines += [f"- {x}" for x in assessment['baselineChanges']]
            else:
                lines.append("PASS - no approved baseline changes are required.")
        else:
            lines.append("SKIPPED - Apply approved alert baseline is not selected.")
        lines += ["", "SELECTED-NETWORK COMPLIANCE CHECK", "---------------------------------"]
        lines.append(f"Assigned Meraki devices : {assessment['deviceCount']}")
        if assessment['proposedEmails']:
            lines.append("Alert email destination : PASS")
        else:
            lines.append("Alert email destination : REVIEW - no default email destination is configured; email-based ticketing will not receive network alerts.")
        if assessment['ssidFindings']:
            lines.append(f"Wireless security       : REVIEW - {len(assessment['ssidFindings'])} enabled SSID(s) need review")
            for item in assessment['ssidFindings'][:12]:
                lines.append(f"  - [{item['risk']}] {item['name']} | auth={item['auth']} | wpa={item['wpa']}")
            if len(assessment['ssidFindings'])>12:
                lines.append(f"  - ... {len(assessment['ssidFindings'])-12} additional SSID finding(s)")
        elif "wireless" in (net.get("productTypes") or []):
            lines.append("Wireless security       : PASS - no enabled high/medium/review SSIDs found")
        else:
            lines.append("Wireless security       : N/A - network has no wireless product type")
        applied_mode=str(mode).upper().startswith("APPLY + VERIFY")
        if applied_mode:
            lines += ["", "ACTIONS PERFORMED", "-----------------"]
            if assessment['proposedEmails'] != assessment['existingEmails']:
                lines.append("- Alert destination email state was evaluated and requested destinations were preserved/merged.")
            else:
                lines.append("- Alert destination emails already matched the requested state.")
            if self.post_apply_baseline_var.get():
                lines.append("- Approved alert baseline was applied where changes were required.")
            lines.append("- Alert settings were re-read for verification.")
            lines.append("- A post-build verification TXT report was saved.")
        else:
            lines += ["", "WHAT APPLY + VERIFY WILL DO", "---------------------------"]
            if assessment['proposedEmails'] != assessment['existingEmails']:
                lines.append("- Add the requested email address(es) to network-wide default alert destinations; existing email destinations are preserved.")
            else:
                lines.append("- Alert destination emails already match the requested state.")
            if self.post_apply_baseline_var.get():
                lines.append("- Apply only the approved alert enable/timeout changes shown above.")
            lines.append("- Re-read alert settings after the update and verify baseline + destination emails.")
            lines.append("- Save a post-build verification TXT report.")
        lines.append("- No firmware, admin, VLAN, firewall, VPN, or routing settings are modified by the Alerts section.")
        return "\n".join(lines)

    def postbuild_preview(self):
        try:
            org,net,timeout,requested=self._postbuild_selected()
        except Exception as exc:
            messagebox.showerror("Post-Build Setup",str(exc)); return
        if self.post_preview_button.instate(["disabled"]): return
        self._set_buttons([self.post_preview_button,self.post_apply_button,self.post_compliance_button],"disabled")
        self.post_preview_button.configure(text="Checking...")
        self.post_status_var.set("Reading network configuration...")
        self.post_text.delete("1.0","end")
        signature=self._postbuild_signature(org,net,timeout,requested)
        def work():
            assessment=self._postbuild_assess(self.require_api(),org,net,timeout,requested)
            text=self._postbuild_report_text(org,net,assessment,"DRY RUN - NO CHANGES WILL BE MADE")
            report_dir=REPORTS/"PostBuild"; report_dir.mkdir(parents=True,exist_ok=True)
            path=report_dir/f"Post-Build-Preview_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_{nowstamp()}.txt"
            path.write_text(text+"\n",encoding="utf-8")
            def done():
                self.last_postbuild_signature=signature
                self.post_text.insert("end",text)
                self.post_apply_button.configure(state="normal")
                review=[]
                if not assessment['proposedEmails']: review.append("no alert email")
                if assessment['ssidFindings']: review.append("SSID review")
                suffix=(" · REVIEW: "+", ".join(review)) if review else " · ready"
                self.post_status_var.set(f"Preview complete{suffix}")
                self.write_log(f"Post-build preview complete for {org.get('name')} / {net.get('name')}. TXT: {path}")
            self._emit("call",done)
        def finished(error):
            self.post_preview_button.configure(text="Preview / Dry Run")
            self.post_preview_button.configure(state="normal")
            self.post_compliance_button.configure(state="normal")
            if error is not None:
                self.post_apply_button.configure(state="disabled"); self.post_status_var.set("Preview failed")
        self.worker(work,finished)

    def postbuild_apply(self):
        try:
            org,net,timeout,requested=self._postbuild_selected()
        except Exception as exc:
            messagebox.showerror("Post-Build Setup",str(exc)); return
        signature=self._postbuild_signature(org,net,timeout,requested)
        if not self.last_postbuild_signature or signature!=self.last_postbuild_signature:
            messagebox.showwarning("Preview required","Run Preview / Dry Run after your last change before applying Post-Build Setup."); return
        confirm=simpledialog.askstring("Apply Post-Build Setup",f"Type APPLY to update alert settings for:\n{org.get('name')} / {net.get('name')}")
        if confirm!="APPLY": return
        self._set_buttons([self.post_preview_button,self.post_apply_button,self.post_compliance_button],"disabled")
        self.post_apply_button.configure(text="Applying...")
        self.post_status_var.set("Applying alert setup...")
        def work():
            api=self.require_api()
            before=self._postbuild_assess(api,org,net,timeout,requested)
            payload=before['payload']
            # If baseline application is unchecked, preserve the original alert objects exactly.
            if not self.post_apply_baseline_var.get():
                payload['alerts']=json.loads(json.dumps(before['settings'].get('alerts') or []))
            needs_destination=(before['proposedEmails']!=before['existingEmails'])
            needs_baseline=bool(before['baselineChanges']) and self.post_apply_baseline_var.get()
            if needs_destination or needs_baseline:
                api.put(f"/networks/{urllib.parse.quote(str(net['id']))}/alerts/settings",payload)
                self._emit("log",f"Post-build alert settings updated for {org.get('name')} / {net.get('name')}.")
            else:
                self._emit("log",f"Post-build alert settings already matched for {org.get('name')} / {net.get('name')}.")
            self._emit("call",lambda:self.post_status_var.set("Verifying..."))
            verify_settings=api.get(f"/networks/{urllib.parse.quote(str(net['id']))}/alerts/settings") or {}
            remaining,_=self._alert_plan_options(verify_settings,timeout,self.post_settings_changed_var.get())
            final_emails=list((verify_settings.get('defaultDestinations') or {}).get('emails') or [])
            missing=[e for e in requested if e.casefold() not in {x.casefold() for x in final_emails}]
            after=self._postbuild_assess(api,org,net,timeout,requested)
            lines=self._postbuild_report_text(org,net,after,"APPLY + VERIFY RESULT")
            lines += "\n\nVERIFICATION\n------------\n"
            if self.post_apply_baseline_var.get():
                lines += "Alert baseline : " + ("PASS" if not remaining else f"FAIL - {len(remaining)} approved change(s) still remain") + "\n"
            else:
                lines += "Alert baseline : NOT APPLIED (user selected)\n"
            lines += "Requested email(s): " + ("PASS" if not missing else "FAIL - missing " + ", ".join(missing)) + "\n"
            lines += "Final default email(s): " + (", ".join(final_emails) or "NONE") + "\n"
            report_dir=REPORTS/"PostBuild"; report_dir.mkdir(parents=True,exist_ok=True)
            path=report_dir/f"Post-Build-Verification_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_{nowstamp()}.txt"
            path.write_text(lines+"\n",encoding="utf-8")
            def done():
                self.post_text.delete("1.0","end"); self.post_text.insert("end",lines)
                self.last_postbuild_signature=None
                if (not remaining or not self.post_apply_baseline_var.get()) and not missing and final_emails:
                    self.post_status_var.set("POST-BUILD VERIFIED · alert email + baseline ready")
                elif (not remaining or not self.post_apply_baseline_var.get()) and not missing:
                    self.post_status_var.set("Verified with REVIEW · no default alert email configured")
                else:
                    self.post_status_var.set("Verification failed · review report")
                self.write_log(f"Post-build verification complete. TXT: {path}")
            self._emit("call",done)
        def finished(error):
            self.post_apply_button.configure(text="APPLY + VERIFY")
            self.post_preview_button.configure(state="normal")
            self.post_compliance_button.configure(state="normal")
            self.post_apply_button.configure(state="disabled")
            if error is not None:self.post_status_var.set("Apply / verify failed")
        self.worker(work,finished)

    def _tool_python_executable(self):
        """Return a console-capable Python executable for bundled CLI tools.

        The GUI is normally launched with pythonw.exe so there is no console window.
        Bundled CLI scripts can still run headlessly with stdout/stderr captured by using
        the sibling python.exe when available.
        """
        exe=Path(sys.executable)
        if os.name=="nt":
            low=exe.name.lower()
            if low=="pythonw.exe":
                candidate=exe.with_name("python.exe")
                if candidate.exists(): return str(candidate)
            if low=="pyw.exe":
                candidate=exe.with_name("py.exe")
                if candidate.exists(): return str(candidate)
        return str(exe)

    def _set_post_compliance_text(self, text):
        if not hasattr(self,"post_compliance_text"): return
        self.post_compliance_text.configure(state="normal")
        self.post_compliance_text.delete("1.0","end")
        self.post_compliance_text.insert("end",text.rstrip()+"\n")
        self.post_compliance_text.configure(state="disabled")
        self.post_compliance_text.see("1.0")

    def open_last_post_compliance_report(self):
        report=getattr(self,"post_compliance_last_report",None)
        if not report:
            messagebox.showinfo("Post-Build Compliance","No completed Post-Build compliance report is available yet.")
            return
        path=Path(report)
        if not path.exists():
            messagebox.showerror("Post-Build Compliance",f"Report file was not found:\n{path}")
            return
        try:
            webbrowser.open(path.resolve().as_uri())
        except Exception as exc:
            messagebox.showerror("Open report failed",str(exc))

    def postbuild_full_compliance(self):
        if self.post_compliance_button.instate(["disabled"]): return
        try:
            org,net,timeout,requested=self._postbuild_selected()
        except Exception as exc:
            messagebox.showerror("Post-Build Compliance",str(exc)); return

        scope=(self.post_compliance_scope_var.get() or "This Network").strip()
        output_root=REPORTS/"Compliance"
        args=[
            "--output-root",str(output_root),
            "--organization-id",str(org.get("id") or ""),
            "--offline-timeout-minutes",str(timeout),
        ]
        if scope == "This Network":
            args += ["--network-id",str(net.get("id") or "")]
        if self.post_settings_changed_var.get():
            args.append("--require-settings-changed")
        for email in requested:
            args += ["--required-email",email]
        if self.public_var.get():
            args.append("--public-display")

        target = f"{org.get('name')} / {net.get('name')}" if scope == "This Network" else str(org.get('name') or org.get('id'))
        self.post_compliance_last_report=None
        self.post_compliance_button.configure(text="Running...",state="disabled")
        self.post_compliance_open_button.configure(state="disabled")
        self.post_status_var.set(f"Running compliance audit: {scope.lower()}...")
        self.post_compliance_status_var.set(f"Running · {scope} · {target}")
        self._set_post_compliance_text(
            "POST-BUILD COMPLIANCE\n"+"="*72+"\n\n"
            f"Scope  : {scope}\nTarget : {target}\n\n"
            "Running read-only audit in the background...\n"
            "No PowerShell or command window will be opened."
        )

        def work():
            script=TOOLS/"Meraki-Multi-Org-Compliance-Report-v2.1.py"
            if not script.exists():
                raise RuntimeError(f"Missing compliance tool: {script}")
            key=self.key_entry.get().strip()
            if not key:
                raise RuntimeError("Meraki API key is not available in memory.")
            env=os.environ.copy(); env["MERAKI_DASHBOARD_API_KEY"]=key
            cmd=[self._tool_python_executable(),str(script),*args]
            kwargs={
                "cwd":str(ROOT),
                "env":env,
                "stdout":subprocess.PIPE,
                "stderr":subprocess.PIPE,
                "text":True,
                "errors":"replace",
            }
            if os.name=="nt":
                kwargs["creationflags"]=getattr(subprocess,"CREATE_NO_WINDOW",0)
            proc=subprocess.run(cmd,**kwargs)
            stdout=(proc.stdout or "").strip()
            stderr=(proc.stderr or "").strip()
            if proc.returncode!=0:
                details=stderr or stdout or f"Compliance tool exited with code {proc.returncode}."
                raise RuntimeError(details)

            report_path=None
            match=re.search(r"^HTML report:\s*(.+)$",stdout,re.MULTILINE|re.IGNORECASE)
            if match:
                candidate=Path(match.group(1).strip())
                if candidate.exists(): report_path=candidate
            if report_path is None:
                candidates=sorted(output_root.glob("Meraki-Compliance-*/report.html"),key=lambda p:p.stat().st_mtime if p.exists() else 0,reverse=True)
                if candidates: report_path=candidates[0]

            display=[
                "POST-BUILD COMPLIANCE RESULT",
                "="*72,
                "",
                f"Scope  : {scope}",
                f"Target : {target}",
                "",
            ]
            display.extend(stdout.splitlines() if stdout else ["Compliance audit completed successfully."])
            if stderr:
                display += ["","TOOL WARNINGS / STDERR","-"*72,*stderr.splitlines()]
            if report_path:
                display += ["",f"Open Last Report : {report_path}"]
            text="\n".join(display)

            def apply_result():
                self._set_post_compliance_text(text)
                self.post_compliance_last_report=report_path
                if report_path:
                    self.post_compliance_open_button.configure(state="normal")
                self.post_status_var.set(f"Compliance complete · {scope} · {target}")
                self.post_compliance_status_var.set(f"Complete · {scope} · {target}")
                self.write_log(f"Post-build compliance audit completed for {scope}: {target}.")
            self._emit("call",apply_result)

        def finished(error):
            self.post_compliance_button.configure(text="Run Compliance Audit",state="normal")
            if error is not None:
                self.post_status_var.set("Compliance audit failed")
                self.post_compliance_status_var.set("Compliance audit failed")
                self._set_post_compliance_text(
                    "POST-BUILD COMPLIANCE FAILED\n"+"="*72+"\n\n"+str(error)
                )
        self.worker(work,finished)

    # ---------------- Builder ----------------
    def _builder_set_controls_locked(self, locked):
        """Lock/unlock all Network Builder inputs after a successful build.

        The top-level organization selector remains available because Post-Build and other
        toolkit tabs use it. Only inputs that can alter the prepared Builder transaction
        are locked here.
        """
        if locked:
            for widget in (
                self.build_destination_combo,
                self.build_new_org_entry,
                self.build_admin_name_entry,
                self.build_admin_email_entry,
                self.build_admin_access_combo,
                self.build_admin_add_button,
                self.build_admin_remove_button,
                self.build_mode_combo,
                self.build_name_entry,
                self.build_tz_entry,
                self.build_site_street_entry,
                self.build_site_line2_entry,
                self.build_site_city_entry,
                self.build_site_state_entry,
                self.build_site_postal_entry,
                self.build_site_country_entry,
                self.build_source_combo,
                self.build_addressing_combo,
                self.build_addressing_button,
                self.build_note_entry,
            ):
                try: widget.configure(state="disabled")
                except Exception: pass
            for widget in getattr(self,"product_checkbuttons",{}).values():
                try: widget.configure(state="disabled")
                except Exception: pass
            return

        # Generic fields are editable again; contextual widgets are restored below.
        self.build_destination_combo.configure(state="readonly")
        self.build_name_entry.configure(state="normal")
        self.build_tz_entry.configure(state="normal")
        for widget in (self.build_site_street_entry,self.build_site_line2_entry,self.build_site_city_entry,self.build_site_state_entry,self.build_site_postal_entry,self.build_site_country_entry):
            widget.configure(state="normal")
        self.build_note_entry.configure(state="normal")
        for widget in getattr(self,"product_checkbuttons",{}).values():
            widget.configure(state="normal")
        self._builder_destination_changed()

    def _builder_destination_changed(self):
        if getattr(self,"builder_completed",False):
            self._builder_set_controls_locked(True)
            return
        new_org = self.build_destination.get() == "New Organization"
        self.build_new_org_entry.configure(state="normal" if new_org else "disabled")
        self.build_admin_name_entry.configure(state="normal" if new_org else "disabled")
        self.build_admin_email_entry.configure(state="normal" if new_org else "disabled")
        self.build_admin_access_combo.configure(state="readonly" if new_org else "disabled")
        self.build_admin_add_button.configure(state="normal" if new_org else "disabled")
        self.build_admin_remove_button.configure(state="normal" if new_org else "disabled")
        if new_org:
            # A brand-new org starts with a blank network. Cross-org cloning is not assumed.
            self.build_mode.set("No Clone")
            self.build_mode_combo.configure(values=["No Clone"], state="readonly")
            self.builder_destination_help_var.set("The toolkit will create the organization first, then create the network.")
        else:
            self.build_mode_combo.configure(values=["No Clone","Clone Existing"], state="readonly")
            self.builder_destination_help_var.set("Uses the organization selected at the top of the window.")
        self.last_build_signature=None
        self._builder_mode_changed()

    def _builder_mode_changed(self):
        if getattr(self,"builder_completed",False):
            self._builder_set_controls_locked(True)
            return
        clone_ok = (
            self.build_destination.get() == "Existing Organization"
            and self.build_mode.get() == "Clone Existing"
        )
        self.build_source_combo.configure(state="readonly" if clone_ok else "disabled")
        for widget in getattr(self,"product_checkbuttons",{}).values():
            widget.configure(state="disabled" if clone_ok else "normal")
        self.last_build_signature=None
        if clone_ok:
            self._builder_source_changed()
        elif hasattr(self,"build_addressing_combo"):
            self._builder_addressing_state()

    def _builder_source_changed(self):
        if getattr(self,"builder_completed",False):
            self._builder_set_controls_locked(True)
            return
        clone_ok = (
            self.build_destination.get() == "Existing Organization"
            and self.build_mode.get() == "Clone Existing"
        )
        if clone_ok:
            src=self.net_from_label(self.build_source.get())
            source_products=set(src.get("productTypes") or []) if src else set()
            for product,var in self.product_vars.items():
                var.set(product in source_products)
        self.last_build_signature=None
        self._builder_addressing_state()

    def _builder_products_changed(self):
        if getattr(self,"builder_completed",False):
            self._builder_set_controls_locked(True)
            return
        self.last_build_signature=None
        self._builder_addressing_state()

    def _builder_addressing_state(self):
        if getattr(self,"builder_completed",False):
            self.build_addressing_combo.configure(state="disabled")
            self.build_addressing_button.configure(state="disabled")
            return
        clone_mode=(
            self.build_destination.get()=="Existing Organization"
            and self.build_mode.get()=="Clone Existing"
        )
        current=self.build_addressing_mode.get()
        if clone_mode:
            src=self.net_from_label(self.build_source.get())
            if not src:
                self.build_addressing_combo.configure(values=["Select clone source first"],state="disabled")
                self.build_addressing_mode.set("Select clone source first")
            elif "appliance" not in set(src.get("productTypes") or []):
                self.build_addressing_combo.configure(values=["Not applicable"],state="disabled")
                self.build_addressing_mode.set("Not applicable")
            else:
                allowed=["Choose...","VLANs","Single LAN","Keep source addressing"]
                self.build_addressing_combo.configure(values=allowed,state="readonly")
                if current not in allowed:
                    self.build_addressing_mode.set("Choose...")
        else:
            appliance_selected=bool(self.product_vars.get("appliance") and self.product_vars["appliance"].get())
            if not appliance_selected:
                self.build_addressing_combo.configure(values=["Not applicable"],state="disabled")
                self.build_addressing_mode.set("Not applicable")
            else:
                allowed=["Choose...","VLANs","Single LAN","Skip for now"]
                self.build_addressing_combo.configure(values=allowed,state="readonly")
                if current not in allowed:
                    self.build_addressing_mode.set("Choose...")
        self._builder_update_addressing_summary()

    def _builder_addressing_changed(self):
        if getattr(self,"builder_completed",False):
            self._builder_set_controls_locked(True)
            return
        self.last_build_signature=None
        self._builder_update_addressing_summary()

    def _builder_update_addressing_summary(self):
        mode=self.build_addressing_mode.get()
        clone_mode=(self.build_destination.get()=="Existing Organization" and self.build_mode.get()=="Clone Existing")
        if mode=="VLANs":
            count=len(self.builder_vlans)
            prefix="Clone settings, then replace addressing: " if clone_mode else ""
            text=prefix+(f"{count} VLAN{'s' if count!=1 else ''} configured" if count else "Configure at least one VLAN before Preview.")
            button_state="normal"
        elif mode=="Single LAN":
            subnet=self.builder_single_lan.get("subnet","")
            appliance=self.builder_single_lan.get("applianceIp","")
            prefix="Clone settings, then replace addressing: " if clone_mode else ""
            text=prefix+(f"{subnet} · appliance {appliance}" if subnet and appliance else "Configure the LAN subnet and appliance IP before Preview.")
            button_state="normal"
        elif mode=="Skip for now":
            text="Addressing will remain at the Meraki defaults for later review."
            button_state="disabled"
        elif mode=="Keep source addressing":
            text="WARNING: the clone will keep the source LAN/VLAN addressing and therefore duplicate its IP scheme."
            button_state="disabled"
        elif mode=="Not applicable":
            text="No appliance product selected; LAN/VLAN addressing is not applicable."
            button_state="disabled"
        elif mode=="Select clone source first":
            text="Select the clone source before choosing how its addressing should be handled."
            button_state="disabled"
        else:
            text=("Choose VLANs, Single LAN, or explicitly keep the source addressing." if clone_mode
                  else "Choose VLANs, Single LAN, or explicitly skip addressing.")
            button_state="disabled"
        self.build_addressing_summary_var.set(text)
        self.build_addressing_button.configure(state="disabled" if getattr(self,"builder_completed",False) else button_state)

    @staticmethod
    def _ipv4_network(value, label="Subnet"):
        value=(value or "").strip()
        if not value:
            raise RuntimeError(f"Enter {label.lower()}.")
        try:
            net=ipaddress.ip_network(value,strict=False)
        except ValueError as exc:
            raise RuntimeError(f"{label} '{value}' is not a valid IPv4 CIDR subnet.") from exc
        if net.version!=4:
            raise RuntimeError(f"{label} must be IPv4 in this build.")
        return net

    @staticmethod
    def _lan_network_from_input(value, appliance_ip, label="LAN subnet / mask"):
        """Accept a CIDR/network, prefix length, or dotted netmask and return IPv4Network.

        Examples accepted:
          192.168.10.0/24
          192.168.10.1/24   (normalized to 192.168.10.0/24)
          /24 or 24          (derived from appliance_ip)
          255.255.255.0      (derived from appliance_ip)
        """
        raw=(value or "").strip()
        if not raw:
            raise RuntimeError(f"Enter {label.lower()}.")

        # CIDR entered directly, including host/prefix form.
        if "/" in raw and not raw.startswith("/"):
            try:
                net=ipaddress.ip_network(raw,strict=False)
            except ValueError as exc:
                raise RuntimeError(
                    f"{label} '{raw}' is invalid. Use CIDR such as 192.168.10.0/24 "
                    "or a subnet mask such as 255.255.255.0."
                ) from exc
            if net.version!=4:
                raise RuntimeError(f"{label} must be IPv4 in this build.")
            return net

        # Prefix-only input such as 24 or /24.
        prefix_text=raw[1:] if raw.startswith("/") else raw
        if prefix_text.isdigit():
            prefix=int(prefix_text)
            if not 0 <= prefix <= 32:
                raise RuntimeError(f"{label} prefix /{prefix} is invalid. Use /0 through /32.")
            try:
                return ipaddress.ip_network(f"{appliance_ip}/{prefix}",strict=False)
            except ValueError as exc:
                raise RuntimeError(f"Could not derive {label.lower()} from appliance IP {appliance_ip} and /{prefix}.") from exc

        # Dotted-decimal netmask such as 255.255.255.0. Validate the mask first.
        try:
            ipaddress.ip_network(f"0.0.0.0/{raw}",strict=False)
            return ipaddress.ip_network(f"{appliance_ip}/{raw}",strict=False)
        except ValueError as exc:
            raise RuntimeError(
                f"{label} '{raw}' is invalid. Enter CIDR such as 192.168.10.0/24, "
                "a prefix such as /24, or a subnet mask such as 255.255.255.0."
            ) from exc

    @staticmethod
    def _validate_lan_host_range(net, appliance, label):
        if net.prefixlen >= 31:
            mask=str(net.netmask)
            raise RuntimeError(
                f"{label} {net.with_prefixlen} ({mask}) does not provide a normal usable LAN host range. "
                "If this is an ISP/WAN address or mask, do not enter it in the LAN/VLAN plan."
            )
        if appliance not in net or appliance in {net.network_address,net.broadcast_address}:
            raise RuntimeError(f"{label} appliance IP {appliance} must be a usable address inside {net.with_prefixlen}.")

    @staticmethod
    def _is_rfc1918_network(net):
        private_ranges=(
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        return any(net.subnet_of(private_net) for private_net in private_ranges)

    @classmethod
    def _validate_rfc1918_lan(cls, net, label, allow_non_rfc1918=False):
        if cls._is_rfc1918_network(net):
            return
        if allow_non_rfc1918:
            return
        raise RuntimeError(
            f"{label} subnet {net.with_prefixlen} is not RFC1918 private LAN space. "
            "Normal customer LAN/VLAN networks should use 10.0.0.0/8, 172.16.0.0/12, "
            "or 192.168.0.0/16. If this public/non-private subnet is intentional, enable "
            "the Advanced non-RFC1918 override; CREATE will then require CREATE PUBLIC."
        )

    @staticmethod
    def _ipv4_address(value, label="IP address"):
        value=(value or "").strip()
        if not value:
            raise RuntimeError(f"Enter {label.lower()}.")
        try:
            addr=ipaddress.ip_address(value)
        except ValueError as exc:
            raise RuntimeError(f"{label} '{value}' is not a valid IPv4 address.") from exc
        if addr.version!=4:
            raise RuntimeError(f"{label} must be IPv4 in this build.")
        return addr

    @staticmethod
    def _split_ipv4_list(value, label):
        parts=[p for p in re.split(r"[\s,;]+",(value or "").strip()) if p]
        out=[]
        for part in parts:
            try:
                addr=ipaddress.ip_address(part)
            except ValueError as exc:
                raise RuntimeError(f"{label} contains invalid IPv4 address '{part}'.") from exc
            if addr.version!=4:
                raise RuntimeError(f"{label} supports IPv4 only in this build.")
            out.append(str(addr))
        return out

    def _normalize_vlan_record(self, record, allow_non_rfc1918=False):
        try:
            vlan_id=int(str(record.get("id","")).strip())
        except ValueError as exc:
            raise RuntimeError("VLAN ID must be a number from 1 through 4094.") from exc
        if not 1 <= vlan_id <= 4094:
            raise RuntimeError("VLAN ID must be from 1 through 4094.")
        name=(record.get("name") or "").strip()
        if not name:
            raise RuntimeError(f"Enter a name for VLAN {vlan_id}.")
        appliance=self._ipv4_address(record.get("applianceIp"),f"VLAN {vlan_id} appliance IP")
        net=self._lan_network_from_input(record.get("subnet"),appliance,f"VLAN {vlan_id} LAN subnet / mask")
        self._validate_lan_host_range(net,appliance,f"VLAN {vlan_id}")
        self._validate_rfc1918_lan(net,f"VLAN {vlan_id}",allow_non_rfc1918)

        handling=(record.get("dhcpHandling") or "Run a DHCP server").strip()
        allowed={"Run a DHCP server","Relay DHCP to another server","Do not respond to DHCP requests"}
        if handling not in allowed:
            raise RuntimeError(f"VLAN {vlan_id} has an unsupported DHCP mode.")
        lease=(record.get("dhcpLeaseTime") or "1 day").strip()
        allowed_leases={"30 minutes","1 hour","4 hours","12 hours","1 day","1 week"}
        if lease not in allowed_leases:
            raise RuntimeError(f"VLAN {vlan_id} has an unsupported DHCP lease time.")
        dns=(record.get("dnsNameservers") or "upstream_dns").strip()
        relay_text=(record.get("dhcpRelayServers") or "").strip()
        relay=self._split_ipv4_list(relay_text,f"VLAN {vlan_id} DHCP relay servers") if relay_text else []

        pool_start=(record.get("dhcpStart") or "").strip()
        pool_end=(record.get("dhcpEnd") or "").strip()
        if handling=="Run a DHCP server":
            if net.prefixlen>30:
                raise RuntimeError(f"VLAN {vlan_id} subnet {net.with_prefixlen} is too small to run a normal DHCP pool.")
            if bool(pool_start) != bool(pool_end):
                raise RuntimeError(f"VLAN {vlan_id}: enter both DHCP Start and DHCP End, or leave both blank for Meraki defaults.")
            if pool_start and pool_end:
                start=self._ipv4_address(pool_start,f"VLAN {vlan_id} DHCP start")
                end=self._ipv4_address(pool_end,f"VLAN {vlan_id} DHCP end")
                if start not in net or end not in net or start in {net.network_address,net.broadcast_address} or end in {net.network_address,net.broadcast_address}:
                    raise RuntimeError(f"VLAN {vlan_id} DHCP pool must use usable addresses inside {net.with_prefixlen}.")
                if int(start)>int(end):
                    raise RuntimeError(f"VLAN {vlan_id} DHCP Start must be lower than or equal to DHCP End.")
                if int(start) <= int(appliance) <= int(end):
                    raise RuntimeError(f"VLAN {vlan_id} DHCP pool includes the appliance IP {appliance}. Move the pool or appliance IP.")
                pool_start,pool_end=str(start),str(end)
            relay=[]
        elif handling=="Relay DHCP to another server":
            if not relay:
                raise RuntimeError(f"VLAN {vlan_id}: enter at least one DHCP relay server IP.")
            pool_start=pool_end=""
        else:
            pool_start=pool_end=""
            relay=[]

        return {
            "id":str(vlan_id),
            "name":name,
            "subnet":net.with_prefixlen,
            "applianceIp":str(appliance),
            "dhcpHandling":handling,
            "dhcpLeaseTime":lease,
            "dnsNameservers":dns or "upstream_dns",
            "dhcpRelayServers":", ".join(relay),
            "dhcpStart":pool_start,
            "dhcpEnd":pool_end,
        }

    def _validate_vlan_plan(self, records, allow_non_rfc1918=False):
        if not records:
            raise RuntimeError("Configure at least one VLAN, or choose Skip for now.")
        normalized=[self._normalize_vlan_record(r,allow_non_rfc1918=allow_non_rfc1918) for r in records]
        seen=set()
        networks=[]
        for row in normalized:
            if row["id"] in seen:
                raise RuntimeError(f"VLAN ID {row['id']} is listed more than once.")
            seen.add(row["id"])
            net=self._ipv4_network(row["subnet"])
            for other_id,other_net in networks:
                if net.overlaps(other_net):
                    raise RuntimeError(f"VLAN {row['id']} subnet {net.with_prefixlen} overlaps VLAN {other_id} subnet {other_net.with_prefixlen}.")
            networks.append((row["id"],net))
        return sorted(normalized,key=lambda r:int(r["id"]))

    def _normalize_single_lan(self, record, allow_non_rfc1918=None):
        if allow_non_rfc1918 is None:
            allow_non_rfc1918=bool(record.get("allowNonRfc1918",False))
        appliance=self._ipv4_address(record.get("applianceIp"),"Single LAN appliance IP")
        net=self._lan_network_from_input(record.get("subnet"),appliance,"Single LAN subnet / mask")
        self._validate_lan_host_range(net,appliance,"Single LAN")
        self._validate_rfc1918_lan(net,"Single LAN",allow_non_rfc1918)
        return {"subnet":net.with_prefixlen,"applianceIp":str(appliance),"allowNonRfc1918":bool(allow_non_rfc1918)}

    def _builder_configure_addressing(self):
        mode=self.build_addressing_mode.get()
        if mode=="VLANs":
            self._builder_open_vlan_dialog()
        elif mode=="Single LAN":
            self._builder_open_single_lan_dialog()

    def _builder_open_single_lan_dialog(self):
        dlg=tk.Toplevel(self)
        dlg.title("Single LAN Addressing")
        dlg.geometry("760x320")
        dlg.transient(self)
        dlg.grab_set()
        body=ttk.Frame(dlg,padding=18);body.pack(fill="both",expand=True)
        subnet_var=tk.StringVar(value=self.builder_single_lan.get("subnet",""))
        appliance_var=tk.StringVar(value=self.builder_single_lan.get("applianceIp",""))
        allow_nonprivate_var=tk.BooleanVar(value=bool(self.builder_single_lan.get("allowNonRfc1918",False)))
        ttk.Label(body,text="LAN subnet / mask").grid(row=0,column=0,sticky="w",pady=7)
        ttk.Entry(body,textvariable=subnet_var,width=28).grid(row=0,column=1,sticky="w",padx=8)
        ttk.Label(body,text="CIDR, /prefix, or mask. Example: 192.168.10.0/24 or 255.255.255.0").grid(row=0,column=2,sticky="w")
        ttk.Label(body,text="Appliance IP").grid(row=1,column=0,sticky="w",pady=7)
        ttk.Entry(body,textvariable=appliance_var,width=28).grid(row=1,column=1,sticky="w",padx=8)
        ttk.Label(body,text="Example: 192.168.10.1").grid(row=1,column=2,sticky="w")
        ttk.Label(body,text="LAN only — not WAN/ISP addressing. With a mask or /prefix, the network is derived from the Appliance IP.",foreground="#b26a00").grid(row=2,column=0,columnspan=3,sticky="w",pady=(12,5))
        ttk.Label(body,text="The network is created first, then VLAN mode is disabled and this LAN address is applied.").grid(row=3,column=0,columnspan=3,sticky="w",pady=(2,5))
        ttk.Checkbutton(
            body,
            text="Advanced: allow a non-RFC1918/public LAN subnet (requires typed CREATE PUBLIC)",
            variable=allow_nonprivate_var,
        ).grid(row=4,column=0,columnspan=3,sticky="w",pady=(10,2))
        ttk.Label(body,text="Normally leave this OFF. RFC1918 LAN space is 10/8, 172.16/12, or 192.168/16.",foreground="#b26a00").grid(row=5,column=0,columnspan=3,sticky="w",pady=(0,5))
        actions=ttk.Frame(body);actions.grid(row=6,column=0,columnspan=3,sticky="e",pady=(12,0))
        def save():
            try:
                plan=self._normalize_single_lan(
                    {"subnet":subnet_var.get(),"applianceIp":appliance_var.get()},
                    allow_non_rfc1918=allow_nonprivate_var.get(),
                )
            except Exception as exc:
                messagebox.showerror("Single LAN",str(exc),parent=dlg);return
            self.builder_single_lan=plan
            self.last_build_signature=None
            self._builder_update_addressing_summary()
            dlg.destroy()
        ttk.Button(actions,text="Cancel",command=dlg.destroy).pack(side="right",padx=(8,0))
        ttk.Button(actions,text="Save",style="Accent.TButton",command=save).pack(side="right")
        dlg.wait_window()

    def _builder_open_vlan_dialog(self):
        draft=[dict(v) for v in self.builder_vlans]
        allow_nonprivate_var=tk.BooleanVar(value=bool(self.builder_vlan_allow_non_rfc1918))
        dlg=tk.Toplevel(self)
        dlg.title("VLAN / IP Plan")
        dlg.geometry("1210x650")
        dlg.minsize(1050,620)
        dlg.transient(self)
        dlg.grab_set()
        outer=ttk.Frame(dlg,padding=14);outer.pack(fill="both",expand=True)
        outer.columnconfigure(0,weight=1)
        outer.rowconfigure(1,weight=1)
        ttk.Label(outer,text="VLANs will be applied only after the new network is created. The plan is verified before hardware is moved.",font=("Segoe UI",10,"bold")).grid(row=0,column=0,sticky="w",pady=(0,8))
        cols=("id","name","subnet","appliance","dhcp","pool","dns")
        tree=ttk.Treeview(outer,columns=cols,show="headings",height=10)
        widths=(70,150,165,135,200,190,145)
        titles=("VLAN","Name","Subnet","Appliance IP","DHCP","DHCP Pool","DNS")
        for c,w,t in zip(cols,widths,titles):
            tree.heading(c,text=t);tree.column(c,width=w,anchor="w")
        tree.grid(row=1,column=0,sticky="nsew")

        edit=ttk.LabelFrame(outer,text="Add / edit VLAN",padding=10);edit.grid(row=2,column=0,sticky="ew",pady=(10,6))
        vars={
            "id":tk.StringVar(),"name":tk.StringVar(),"subnet":tk.StringVar(),"applianceIp":tk.StringVar(),
            "dhcpHandling":tk.StringVar(value="Run a DHCP server"),"dhcpLeaseTime":tk.StringVar(value="1 day"),
            "dnsNameservers":tk.StringVar(value="upstream_dns"),"dhcpRelayServers":tk.StringVar(),
            "dhcpStart":tk.StringVar(),"dhcpEnd":tk.StringVar(),
        }
        labels=[
            ("VLAN ID","id",8),("Name","name",18),("LAN Subnet / Mask","subnet",19),("Appliance IP","applianceIp",16),
            ("DHCP Start","dhcpStart",16),("DHCP End","dhcpEnd",16),
        ]
        for i,(label,key,width) in enumerate(labels):
            ttk.Label(edit,text=label).grid(row=0,column=i,sticky="w",padx=(0,6))
            ttk.Entry(edit,textvariable=vars[key],width=width).grid(row=1,column=i,sticky="w",padx=(0,8))
        ttk.Label(edit,text="DHCP mode").grid(row=2,column=0,sticky="w",pady=(8,0))
        ttk.Combobox(edit,textvariable=vars["dhcpHandling"],values=["Run a DHCP server","Relay DHCP to another server","Do not respond to DHCP requests"],state="readonly",width=29).grid(row=3,column=0,columnspan=2,sticky="w")
        ttk.Label(edit,text="Lease").grid(row=2,column=2,sticky="w",pady=(8,0))
        ttk.Combobox(edit,textvariable=vars["dhcpLeaseTime"],values=["30 minutes","1 hour","4 hours","12 hours","1 day","1 week"],state="readonly",width=15).grid(row=3,column=2,sticky="w")
        ttk.Label(edit,text="DNS").grid(row=2,column=3,sticky="w",pady=(8,0))
        ttk.Combobox(edit,textvariable=vars["dnsNameservers"],values=["upstream_dns","google_dns","opendns"],width=24).grid(row=3,column=3,sticky="w")
        ttk.Label(edit,text="Relay server IP(s)").grid(row=2,column=4,sticky="w",pady=(8,0))
        ttk.Entry(edit,textvariable=vars["dhcpRelayServers"],width=28).grid(row=3,column=4,columnspan=2,sticky="w")

        selected_index={"value":None}
        def pool_text(row):
            if row.get("dhcpHandling")=="Run a DHCP server" and row.get("dhcpStart") and row.get("dhcpEnd"):
                return f"{row['dhcpStart']} - {row['dhcpEnd']}"
            return "Meraki default" if row.get("dhcpHandling")=="Run a DHCP server" else "—"
        def refresh():
            for item in tree.get_children():tree.delete(item)
            for i,row in enumerate(draft):
                tree.insert("","end",iid=str(i),values=(row["id"],row["name"],row["subnet"],row["applianceIp"],row["dhcpHandling"],pool_text(row),row.get("dnsNameservers","") if row.get("dhcpHandling")=="Run a DHCP server" else "—"))
        def clear_fields():
            selected_index["value"]=None
            for key in ("id","name","subnet","applianceIp","dhcpRelayServers","dhcpStart","dhcpEnd"):vars[key].set("")
            vars["dhcpHandling"].set("Run a DHCP server");vars["dhcpLeaseTime"].set("1 day");vars["dnsNameservers"].set("upstream_dns")
        def on_select(_event=None):
            sel=tree.selection()
            if not sel:return
            idx=int(sel[0]);selected_index["value"]=idx;row=draft[idx]
            for key,var in vars.items():var.set(row.get(key,""))
        tree.bind("<<TreeviewSelect>>",on_select)
        def add_update():
            raw={k:v.get() for k,v in vars.items()}
            try:row=self._normalize_vlan_record(raw,allow_non_rfc1918=allow_nonprivate_var.get())
            except Exception as exc:
                messagebox.showerror("VLAN Plan",str(exc),parent=dlg);return
            idx=selected_index["value"]
            duplicate=next((i for i,r in enumerate(draft) if r.get("id")==row["id"] and i!=idx),None)
            if duplicate is not None:
                messagebox.showerror("VLAN Plan",f"VLAN ID {row['id']} is already in the plan.",parent=dlg);return
            if idx is None:draft.append(row)
            else:draft[idx]=row
            try:self._validate_vlan_plan(draft,allow_non_rfc1918=allow_nonprivate_var.get())
            except Exception as exc:
                if idx is None:draft.pop()
                messagebox.showerror("VLAN Plan",str(exc),parent=dlg);return
            refresh();clear_fields()
        def remove_selected():
            sel=tree.selection()
            if not sel:return
            for idx in sorted((int(x) for x in sel),reverse=True):draft.pop(idx)
            refresh();clear_fields()
        edit_actions=ttk.Frame(edit);edit_actions.grid(row=3,column=6,sticky="e",padx=(12,0))
        ttk.Button(edit_actions,text="Add / Update",style="Accent.TButton",command=add_update).pack(side="left")
        ttk.Button(edit_actions,text="Clear",command=clear_fields).pack(side="left",padx=6)
        ttk.Button(edit_actions,text="Remove Selected",command=remove_selected).pack(side="left")

        ttk.Label(outer,text="LAN/VLAN only — not WAN/ISP. Subnet accepts 192.168.10.0/24, /24, 24, or 255.255.255.0; mask/prefix inputs are derived from Appliance IP.",foreground="#b26a00").grid(row=3,column=0,sticky="w",pady=(2,2))
        ttk.Label(outer,text="DHCP Start/End are optional. When supplied, the toolkit converts the addresses outside that pool into Meraki reserved ranges. Relay IPs may be comma-separated.").grid(row=4,column=0,sticky="w",pady=(0,4))
        ttk.Checkbutton(
            outer,
            text="Advanced: allow non-RFC1918/public LAN subnets (requires typed CREATE PUBLIC)",
            variable=allow_nonprivate_var,
        ).grid(row=5,column=0,sticky="w",pady=(2,0))
        ttk.Label(outer,text="Normally leave this OFF. Private LAN space: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.",foreground="#b26a00").grid(row=6,column=0,sticky="w",pady=(0,6))
        actions=ttk.Frame(outer,padding=(0,4,0,0));actions.grid(row=7,column=0,sticky="ew")
        actions.columnconfigure(0,weight=1)
        def save_plan():
            try:normalized=self._validate_vlan_plan(draft,allow_non_rfc1918=allow_nonprivate_var.get())
            except Exception as exc:
                messagebox.showerror("VLAN Plan",str(exc),parent=dlg);return
            self.builder_vlans=normalized
            self.builder_vlan_allow_non_rfc1918=bool(allow_nonprivate_var.get())
            self.last_build_signature=None
            self._builder_update_addressing_summary()
            dlg.destroy()
        ttk.Button(actions,text="Cancel",width=16,command=dlg.destroy).pack(side="right",padx=(8,0),ipady=4)
        ttk.Button(actions,text="Apply VLAN Plan",width=18,style="Accent.TButton",command=save_plan).pack(side="right",ipady=4)
        refresh()
        dlg.wait_window()

    def _builder_addressing_plan(self, products):
        if "appliance" not in products:
            return {"mode":"not_applicable"}
        clone_mode=(self.build_destination.get()=="Existing Organization" and self.build_mode.get()=="Clone Existing")
        mode=self.build_addressing_mode.get()
        if mode in {"","Choose...","Select clone source first"}:
            if clone_mode:
                raise RuntimeError("Choose how clone addressing should be handled. Use a new VLAN/Single-LAN plan, or explicitly choose Keep source addressing.")
            raise RuntimeError("Choose how appliance LAN/VLAN addressing should be handled before Preview.")
        if clone_mode and mode=="Keep source addressing":
            return {"mode":"copied_from_source"}
        if mode=="Skip for now":
            if clone_mode:
                raise RuntimeError("Skip for now is not available for Clone Existing because Meraki copies the source addressing during the clone. Choose replacement addressing or Keep source addressing explicitly.")
            return {"mode":"skip"}
        if mode=="Single LAN":
            plan=self._normalize_single_lan(self.builder_single_lan)
            return {"mode":"single_lan",**plan}
        if mode=="VLANs":
            allow_nonprivate=bool(self.builder_vlan_allow_non_rfc1918)
            return {
                "mode":"vlans",
                "allowNonRfc1918":allow_nonprivate,
                "vlans":self._validate_vlan_plan(self.builder_vlans,allow_non_rfc1918=allow_nonprivate),
            }
        raise RuntimeError(f"Unsupported addressing mode '{mode}'.")

    @staticmethod
    def _dhcp_reserved_ranges(row):
        if row.get("dhcpHandling")!="Run a DHCP server" or not row.get("dhcpStart") or not row.get("dhcpEnd"):
            return []
        net=ipaddress.ip_network(row["subnet"],strict=False)
        appliance=ipaddress.ip_address(row["applianceIp"])
        pool_start=ipaddress.ip_address(row["dhcpStart"])
        pool_end=ipaddress.ip_address(row["dhcpEnd"])
        first=net.network_address+1
        last=net.broadcast_address-1
        segments=[]
        if int(first)<=int(pool_start)-1:segments.append((first,ipaddress.ip_address(int(pool_start)-1)))
        if int(pool_end)+1<=int(last):segments.append((ipaddress.ip_address(int(pool_end)+1),last))
        cleaned=[]
        for start,end in segments:
            if int(start)<=int(appliance)<=int(end):
                if int(start)<=int(appliance)-1:cleaned.append((start,ipaddress.ip_address(int(appliance)-1)))
                if int(appliance)+1<=int(end):cleaned.append((ipaddress.ip_address(int(appliance)+1),end))
            else:cleaned.append((start,end))
        return [{"start":str(start),"end":str(end),"comment":"Outside configured DHCP pool"} for start,end in cleaned]

    def _vlan_api_body(self, row, include_id=True, allow_non_rfc1918=False):
        row=self._normalize_vlan_record(row,allow_non_rfc1918=allow_non_rfc1918)
        body={
            "name":row["name"],
            "subnet":row["subnet"],
            "applianceIp":row["applianceIp"],
            "dhcpHandling":row["dhcpHandling"],
        }
        if include_id:body["id"]=row["id"]
        if row["dhcpHandling"]=="Run a DHCP server":
            body["dhcpLeaseTime"]=row["dhcpLeaseTime"]
            body["dnsNameservers"]=row["dnsNameservers"]
            body["reservedIpRanges"]=self._dhcp_reserved_ranges(row)
        elif row["dhcpHandling"]=="Relay DHCP to another server":
            body["dhcpRelayServerIps"]=self._split_ipv4_list(row.get("dhcpRelayServers",""),f"VLAN {row['id']} DHCP relay servers")
        return body

    def _apply_builder_addressing(self, api, network_id, addressing):
        mode=addressing.get("mode")
        qid=urllib.parse.quote(str(network_id))
        if mode in {"skip","not_applicable","copied_from_source"}:
            return {"mode":mode,"verified":True,"details":[]}
        if mode=="single_lan":
            api.put(f"/networks/{qid}/appliance/vlans/settings",{"vlansEnabled":False})
            api.put(f"/networks/{qid}/appliance/singleLan",{"subnet":addressing["subnet"],"applianceIp":addressing["applianceIp"]})
            check=api.get(f"/networks/{qid}/appliance/singleLan") or {}
            if check.get("subnet")!=addressing["subnet"] or check.get("applianceIp")!=addressing["applianceIp"]:
                raise RuntimeError(f"Single LAN verification failed. Meraki returned subnet={check.get('subnet')} applianceIp={check.get('applianceIp')}.")
            return {"mode":mode,"verified":True,"details":[f"Single LAN {addressing['subnet']} · appliance {addressing['applianceIp']}"]}
        if mode!="vlans":
            raise RuntimeError(f"Unknown addressing mode '{mode}'.")
        allow_nonprivate=bool(addressing.get("allowNonRfc1918",False))
        planned=self._validate_vlan_plan(addressing.get("vlans") or [],allow_non_rfc1918=allow_nonprivate)
        api.put(f"/networks/{qid}/appliance/vlans/settings",{"vlansEnabled":True})
        current=api.get(f"/networks/{qid}/appliance/vlans") or []
        existing={str(v.get("id")):v for v in current if isinstance(v,dict) and v.get("id") is not None}
        planned_ids={row["id"] for row in planned}
        actions=[]
        for row in planned:
            vlan_id=row["id"]
            if vlan_id in existing:
                api.put(f"/networks/{qid}/appliance/vlans/{urllib.parse.quote(vlan_id)}",self._vlan_api_body(row,include_id=False,allow_non_rfc1918=allow_nonprivate))
                actions.append(f"Updated VLAN {vlan_id} {row['name']}")
            else:
                api.post(f"/networks/{qid}/appliance/vlans",self._vlan_api_body(row,include_id=True,allow_non_rfc1918=allow_nonprivate))
                actions.append(f"Created VLAN {vlan_id} {row['name']}")
        # The Builder applies explicit addressing only to a newly-created network. For Clone Existing,
        # this intentionally replaces the source addressing after the clone is created. Remove cloned/default
        # VLANs not present in the explicit plan, but only
        # after every desired VLAN has been created/updated successfully.
        refreshed=api.get(f"/networks/{qid}/appliance/vlans") or []
        for vlan in refreshed:
            vlan_id=str(vlan.get("id"))
            if vlan_id not in planned_ids:
                api.delete(f"/networks/{qid}/appliance/vlans/{urllib.parse.quote(vlan_id)}")
                actions.append(f"Removed unplanned default VLAN {vlan_id}")
        settings=api.get(f"/networks/{qid}/appliance/vlans/settings") or {}
        if settings.get("vlansEnabled") is not True:
            raise RuntimeError("VLAN verification failed because Meraki reports VLANs disabled.")
        final=api.get(f"/networks/{qid}/appliance/vlans") or []
        final_by_id={str(v.get("id")):v for v in final if isinstance(v,dict) and v.get("id") is not None}
        if set(final_by_id)!=planned_ids:
            raise RuntimeError(f"VLAN verification failed. Planned IDs={sorted(planned_ids)}; Meraki IDs={sorted(final_by_id)}.")
        for row in planned:
            got=final_by_id[row["id"]]
            for key in ("name","subnet","applianceIp","dhcpHandling"):
                if str(got.get(key))!=str(row.get(key)):
                    raise RuntimeError(f"VLAN {row['id']} verification failed for {key}: planned '{row.get(key)}', Meraki returned '{got.get(key)}'.")
        return {"mode":mode,"verified":True,"details":actions}

    def _builder_refresh_admin_tree(self):
        for item in self.build_admin_tree.get_children():
            self.build_admin_tree.delete(item)
        for index,admin in enumerate(self.pending_admins):
            self.build_admin_tree.insert(
                "", "end", iid=str(index),
                values=(admin.get("name",""),admin.get("email",""),admin.get("orgAccess","full"))
            )

    def _builder_add_admin(self):
        if self.build_destination.get() != "New Organization":
            return
        name=self.build_admin_name.get().strip()
        email=self.build_admin_email.get().strip()
        access=(self.build_admin_access.get().strip() or "full").lower()
        allowed={"full","read-only","enterprise","none"}
        if not name:
            messagebox.showerror("Additional Admin","Enter the administrator name.")
            return
        if not email or "@" not in email or " " in email:
            messagebox.showerror("Additional Admin","Enter a valid administrator email address.")
            return
        if access not in allowed:
            messagebox.showerror("Additional Admin","Access must be full, read-only, enterprise, or none.")
            return
        if any(a.get("email","").casefold()==email.casefold() for a in self.pending_admins):
            messagebox.showerror("Additional Admin",f"{email} is already in the additional-admin list.")
            return
        self.pending_admins.append({"name":name,"email":email,"orgAccess":access})
        self._builder_refresh_admin_tree()
        self.build_admin_name.set("")
        self.build_admin_email.set("")
        self.build_admin_access.set("full")
        self.build_admin_name_entry.focus_set()
        self.last_build_signature=None

    def _builder_remove_admin(self):
        selected=self.build_admin_tree.selection()
        if not selected:
            return
        indexes=sorted((int(i) for i in selected),reverse=True)
        for index in indexes:
            if 0 <= index < len(self.pending_admins):
                self.pending_admins.pop(index)
        self._builder_refresh_admin_tree()
        self.last_build_signature=None

    def _builder_admins(self):
        if self.build_destination.get() != "New Organization":
            return []
        # Prevent a partially typed admin from being silently ignored.
        typed_name=self.build_admin_name.get().strip()
        typed_email=self.build_admin_email.get().strip()
        if typed_name or typed_email:
            raise RuntimeError(
                "An additional administrator is entered but has not been added yet. "
                "Click Add Admin, or clear the Name and Email fields."
            )
        return [dict(a) for a in self.pending_admins]

    def _builder_destination(self):
        if self.build_destination.get() == "New Organization":
            name = self.build_new_org_name.get().strip()
            if not name:
                raise RuntimeError("Enter the new organization name.")
            duplicate = next(
                (o for o in self.orgs if (o.get("name") or "").strip().casefold() == name.casefold()),
                None,
            )
            if duplicate:
                raise RuntimeError(
                    f"An organization named '{name}' already exists. Select Existing Organization instead."
                )
            return {"kind":"new", "id":None, "name":name, "admins":self._builder_admins()}
        org = self.selected_org()
        return {"kind":"existing", "id":str(org.get("id")), "name":org.get("name",""), "admins":[]}

    def _builder_clone_source_subnets(self, source):
        if not source or "appliance" not in set(source.get("productTypes") or []):
            return []
        qid=urllib.parse.quote(str(source.get("id") or ""))
        if not qid:
            return []
        try:
            settings=self.require_api().get(f"/networks/{qid}/appliance/vlans/settings") or {}
            if settings.get("vlansEnabled") is True:
                vlans=self.require_api().get(f"/networks/{qid}/appliance/vlans") or []
                return [str(v.get("subnet")) for v in vlans if isinstance(v,dict) and v.get("subnet")]
            single=self.require_api().get(f"/networks/{qid}/appliance/singleLan") or {}
            return [str(single.get("subnet"))] if single.get("subnet") else []
        except Exception as exc:
            raise RuntimeError(f"Could not read clone source LAN/VLAN addressing for safety validation: {exc}") from exc

    def _builder_replacement_networks(self, addressing):
        mode=addressing.get("mode")
        if mode=="single_lan":
            return [self._ipv4_network(addressing.get("subnet"),"Single LAN subnet")]
        if mode=="vlans":
            return [self._ipv4_network(row.get("subnet"),f"VLAN {row.get('id')} subnet") for row in addressing.get("vlans") or []]
        return []

    def _builder_validate_clone_replacement(self, source, addressing):
        if addressing.get("mode") not in {"single_lan","vlans"}:
            return []
        source_subnets=self._builder_clone_source_subnets(source)
        source_networks=[]
        for value in source_subnets:
            try: source_networks.append(self._ipv4_network(value,"Clone source subnet"))
            except Exception: pass
        planned=self._builder_replacement_networks(addressing)
        overlaps=[]
        for new_net in planned:
            for source_net in source_networks:
                if new_net.overlaps(source_net):
                    overlaps.append(f"{new_net.with_prefixlen} overlaps source {source_net.with_prefixlen}")
        if overlaps:
            raise RuntimeError(
                "The replacement addressing still overlaps the clone source: " + "; ".join(overlaps) +
                ". Choose a different LAN/VLAN scheme. If duplicating the source is intentional, explicitly choose Keep source addressing instead."
            )
        return source_subnets

    def _builder_site_address(self):
        return normalize_site_address({
            "street": self.build_site_street.get(),
            "line2": self.build_site_line2.get(),
            "city": self.build_site_city.get(),
            "state": self.build_site_state.get(),
            "postal": self.build_site_postal.get(),
            "country": self.build_site_country.get(),
        })

    @staticmethod
    def _builder_api_payload(payload):
        return {k: v for k, v in payload.items() if not str(k).startswith("_")}

    def builder_payload(self):
        destination = self._builder_destination()
        name=self.build_name.get().strip()
        if not name: raise RuntimeError("Enter a new network name.")
        tz=self.build_tz.get().strip() or "America/New_York"
        site=self._builder_site_address()
        notes=notes_with_site_address(self.build_note.get().strip(),site)
        payload={"name":name,"timeZone":tz,"tags":[],"notes":notes,"_siteAddress":site}
        src=None
        if self.build_mode.get()=="Clone Existing":
            if destination["kind"] != "existing":
                raise RuntimeError("Clone Existing is available only for an existing organization in this build.")
            src=self.net_from_label(self.build_source.get())
            if not src: raise RuntimeError("Select a clone source network.")
            payload["productTypes"]=list(src.get("productTypes") or [])
            payload["copyFromNetworkId"]=src["id"]
        else:
            products=[p for p,v in self.product_vars.items() if v.get()]
            if not products:raise RuntimeError("Select at least one product type.")
            payload["productTypes"]=products
        addressing=self._builder_addressing_plan(list(payload.get("productTypes") or []))
        if src is not None and addressing.get("mode") in {"single_lan","vlans"}:
            addressing["cloneSourceSubnets"]=self._builder_validate_clone_replacement(src,addressing)
        return destination,payload,addressing

    @staticmethod
    def _builder_signature(destination, payload, addressing):
        return json.dumps({"destination":destination,"network":payload,"addressing":addressing},sort_keys=True,separators=(",",":"))

    def _addressing_non_rfc1918_networks(self, addressing):
        mode=addressing.get("mode")
        found=[]
        if mode=="vlans":
            for row in addressing.get("vlans") or []:
                try:
                    net=self._ipv4_network(row.get("subnet"),f"VLAN {row.get('id')} subnet")
                except Exception:
                    continue
                if not self._is_rfc1918_network(net):
                    found.append(f"VLAN {row.get('id')} {net.with_prefixlen}")
        elif mode=="single_lan":
            try:
                net=self._ipv4_network(addressing.get("subnet"),"Single LAN subnet")
            except Exception:
                return found
            if not self._is_rfc1918_network(net):
                found.append(f"Single LAN {net.with_prefixlen}")
        return found

    def _builder_plan_text(self, destination, payload, addressing):
        mode = self.build_mode.get()
        products = list(payload.get("productTypes") or [])
        new_org = destination.get("kind") == "new"
        product_labels = {
            "appliance": "Appliance (MX / Z / Teleworker)",
            "switch": "Switch",
            "wireless": "Wireless",
            "camera": "Camera",
            "sensor": "Sensor",
            "cellularGateway": "Cellular Gateway",
        }
        lines = [
            "MERAKI BUILD PLAN",
            "=" * 72,
            "DRY RUN - NO CHANGES WILL BE MADE",
            "",
            "DESTINATION ORGANIZATION",
            "------------------------",
            f"Create new organization : {'YES' if new_org else 'NO'}",
            f"Organization name       : {destination.get('name')}",
        ]
        if not new_org:
            lines.append(f"Organization ID         : {destination.get('id')}")
        if new_org:
            admins=list(destination.get("admins") or [])
            lines.extend(["", "ADDITIONAL ADMINISTRATORS", "-------------------------"])
            if admins:
                for admin in admins:
                    lines.append(f"- {admin.get('name')} | {admin.get('email')} | {admin.get('orgAccess')}")
            else:
                lines.append("- None requested (the API-key owner remains the creator/admin)")
        lines.extend([
            "",
            "NETWORK",
            "-------",
            f"Build mode   : {mode}",
            f"Network name : {payload.get('name')}",
            f"Timezone     : {payload.get('timeZone')}",
        ])
        if mode == "Clone Existing":
            src = self.net_from_label(self.build_source.get())
            if src:
                lines.extend([
                    f"Clone source : {src.get('name')}",
                    f"Source ID    : {src.get('id')}",
                ])
        lines.extend([
            "",
            "PRODUCTS",
            "--------",
        ])
        for product in products:
            lines.append(f"- {product_labels.get(product, product)}")

        site=normalize_site_address(payload.get("_siteAddress"))
        site_full=format_site_address(site)
        lines.extend(["", "PHYSICAL SITE LOCATION", "----------------------"])
        if site_full:
            lines.append(f"Address      : {site_full}")
            lines.append("Device action: Automatically apply this address to hardware when it is moved/claimed into the network and move the Dashboard map marker.")
            lines.append("Persistence  : Stored in the network notes and build verification record.")
        else:
            lines.append("Address      : Not specified")
            lines.append("Device action: No automatic device location update will occur until a site address is set in Post-Build > Site / Location.")

        lines.extend(["", "ADDRESSING", "----------"])
        addressing_mode=addressing.get("mode")
        if addressing_mode=="vlans":
            lines.append("Mode         : VLANs")
            lines.append("Desired set  : exact planned VLAN set for this newly-created network")
            for row in addressing.get("vlans") or []:
                lines.append(f"- VLAN {row.get('id')} | {row.get('name')} | {row.get('subnet')} | appliance {row.get('applianceIp')}")
                lines.append(f"  DHCP: {row.get('dhcpHandling')}")
                if row.get("dhcpHandling")=="Run a DHCP server":
                    pool=(f"{row.get('dhcpStart')} - {row.get('dhcpEnd')}" if row.get('dhcpStart') and row.get('dhcpEnd') else "Meraki default usable range")
                    lines.append(f"  Pool: {pool} | lease {row.get('dhcpLeaseTime')} | DNS {row.get('dnsNameservers')}")
                elif row.get("dhcpHandling")=="Relay DHCP to another server":
                    lines.append(f"  Relay: {row.get('dhcpRelayServers')}")
            lines.append("- After desired VLANs exist, Meraki-created default VLANs not in this explicit plan will be removed.")
        elif addressing_mode=="single_lan":
            lines.extend([
                "Mode         : Single LAN",
                f"Subnet       : {addressing.get('subnet')}",
                f"Appliance IP : {addressing.get('applianceIp')}",
            ])
        elif addressing_mode=="copied_from_source":
            lines.append("Mode         : KEEP SOURCE ADDRESSING (explicit)")
        elif addressing_mode=="not_applicable":
            lines.append("Mode         : Not applicable (no appliance product)")
        else:
            lines.append("Mode         : SKIP FOR NOW - Meraki default addressing will remain")

        clone_same_ip=(mode=="Clone Existing" and addressing_mode=="copied_from_source")
        if clone_same_ip:
            lines.extend([
                "",
                "CLONE ADDRESSING SAFETY",
                "-----------------------",
                "WARNING: THE SOURCE LAN/VLAN ADDRESSING WILL BE DUPLICATED",
                "- The clone will use the same IP scheme as the source network.",
                "- This can create overlapping subnets if both networks are routed, VPN-connected, or otherwise reachable.",
                "- Only use this when duplicate addressing is deliberately intended.",
                "- CREATE will require the stronger typed confirmation: CREATE SAME IP.",
            ])
        elif mode=="Clone Existing" and addressing_mode in {"single_lan","vlans"}:
            source_subnets=addressing.get("cloneSourceSubnets") or []
            lines.extend([
                "",
                "CLONE ADDRESSING SAFETY",
                "-----------------------",
                "PASS - source addressing will be replaced before the build is considered complete.",
            ])
            if source_subnets:
                lines.append("Source subnet(s): " + ", ".join(source_subnets))
            lines.append("- Meraki initially creates the clone, then the Toolkit applies and verifies the new addressing before any hardware is moved.")

        nonprivate_networks=self._addressing_non_rfc1918_networks(addressing)
        if nonprivate_networks:
            lines.extend([
                "",
                "LAN ADDRESS SAFETY",
                "------------------",
                "WARNING: NON-RFC1918 LAN OVERRIDE IS ACTIVE",
            ])
            for item in nonprivate_networks:
                lines.append(f"- {item}")
            lines.extend([
                "- This is public/non-private IPv4 space, not normal RFC1918 customer LAN space.",
                "- Verify this is intentional and is NOT WAN/ISP addressing before creating the network.",
                "- CREATE will require the stronger typed confirmation: CREATE PUBLIC.",
            ])

        lines.extend([
            "",
            "TAGS",
            "----",
            "- None" if not payload.get("tags") else "- " + ", ".join(str(x) for x in payload.get("tags") or []),
            "",
            "NOTES",
            "-----",
            self.build_note.get().strip() or "(none)",
            "",
            "WHAT WILL HAPPEN IF YOU CLICK CREATE",
            "------------------------------------",
        ])
        if new_org:
            admins=list(destination.get("admins") or [])
            lines.append(f"1. Create a new Meraki organization named '{destination.get('name')}' and capture the returned organization ID.")
            step=2
            if admins:
                lines.append(f"{step}. Add {len(admins)} requested additional administrator(s) before network creation.")
                step+=1
            lines.append(f"{step}. Create network '{payload.get('name')}' inside the new organization.")
            step+=1
            lines.append(f"{step}. Refresh the toolkit organization list and select the new organization.")
        elif mode == "Clone Existing":
            lines.append("1. Create a new network in the selected organization using the selected source network as the copy source.")
            lines.append("2. Product types will match the source network.")
        else:
            lines.append("1. Create a new blank network in the selected organization with the product types listed above.")
        if addressing_mode=="vlans":
            lines.append("- After network creation, enable VLANs, create/update the planned VLANs, remove only unplanned Meraki-created defaults, then verify the final VLAN set.")
        elif addressing_mode=="single_lan":
            lines.append("- After network creation, disable VLAN mode, apply the Single LAN subnet/appliance IP, then verify it.")
        elif addressing_mode=="skip":
            lines.append("- Addressing is explicitly skipped; Meraki defaults remain for later configuration.")
        elif addressing_mode=="copied_from_source":
            lines.append("- LAN/VLAN addressing will remain copied from the selected source network by explicit choice.")
        if mode=="Clone Existing" and addressing_mode in {"single_lan","vlans"}:
            lines.append("- The cloned source addressing will be replaced with the planned addressing and re-read for verification before completion.")
        confirm_text=("CREATE SAME IP" if clone_same_ip else ("CREATE PUBLIC" if nonprivate_networks else "CREATE"))
        lines.extend([
            "- No hardware will be claimed or moved by Network Builder.",
        ])
        if site_full:
            lines.append("- The physical site address will be stored with the network now; future Hardware / Inventory assignments will apply and verify it on the device automatically.")
        lines.append(f"- The toolkit will require typed confirmation: {confirm_text}.")
        if new_org:
            lines.extend([
                "",
                "PARTIAL-SUCCESS SAFETY",
                "----------------------",
                "If organization creation succeeds but an admin or network step fails, the new organization",
                "and any already-created admins will remain in Meraki. The toolkit will stop and report",
                "the exact partial result; it will NOT automatically delete or roll back the organization.",
            ])
        lines.extend([
            "",
            "POST-CREATION REVIEW",
            "--------------------",
            "Review AutoVPN, static routes, SSIDs, alert destinations, firewall rules, licensing,",
            "appliance/switch port roles, and any other customer-specific settings before putting the site in service.",
        ])
        if addressing_mode=="skip":
            lines.append("Addressing was skipped and remains a required post-build item.")
        return "\n".join(lines)

    def builder_preview(self):
        if self.builder_completed:
            messagebox.showinfo(
                "Build completed",
                "This completed build is locked. Click New Build / Reset before preparing another network."
            )
            return
        try:destination,payload,addressing=self.builder_payload()
        except Exception as e:messagebox.showerror("Network Builder",str(e));return
        signature = self._builder_signature(destination,payload,addressing)
        self.last_build_signature=signature
        plan = self._builder_plan_text(destination, payload, addressing)
        report_dir = REPORTS / "NetworkBuilder"
        report_dir.mkdir(parents=True, exist_ok=True)
        stem = f"Network-Build-Plan_{safe_filename(destination.get('name','org'))}_{safe_filename(payload.get('name','network'))}_{nowstamp()}"
        txt_path = report_dir / f"{stem}.txt"
        json_path = report_dir / f"{stem}.json"
        raw = {"destination":destination,"networkPayload":payload,"addressingPlan":addressing}
        txt_path.write_text(plan + "\n", encoding="utf-8")
        json_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
        self.builder_text.delete("1.0","end")
        self.builder_text.insert("end",plan)
        self.builder_status_var.set("Preview ready · TXT saved · no changes made")
        self.write_log(f"Network build preview ready for '{payload['name']}'. TXT: {txt_path}")

    def _builder_mark_completed(self, summary, network_id=None, network_name=None):
        self.builder_completed=True
        self.builder_completed_network_id=network_id
        self.builder_completed_network_name=network_name
        self.last_build_signature=None
        self.builder_preview_button.configure(state="disabled")
        self.builder_create_button.configure(text="COMPLETED",state="disabled")
        self.builder_reset_button.configure(state="normal")
        self._builder_set_controls_locked(True)
        self.builder_status_var.set(f"COMPLETED · {summary} · POST-BUILD PENDING")
        try:
            self.builder_text.insert(
                "end",
                "\n\n" + "="*72 +
                "\nBUILD COMPLETED - BUILDER IS LOCKED\n" +
                "Use Post-Build for the new network. Click New Build / Reset before changing Builder fields or starting another build.\n"
            )
            self.builder_text.see("end")
        except Exception:
            pass

    def builder_reset(self):
        # UI-only reset. This never deletes or changes anything already created in Meraki.
        self.builder_completed=False
        self.builder_completed_network_id=None
        self.builder_completed_network_name=None
        self.last_build_signature=None

        self.build_destination.set("Existing Organization")
        self.build_new_org_name.set("")
        self.pending_admins=[]
        self._builder_refresh_admin_tree()
        self.build_admin_name.set("")
        self.build_admin_email.set("")
        self.build_admin_access.set("full")

        self.build_mode.set("No Clone")
        self.build_name.set("")
        self.build_tz.set("America/New_York")
        self.build_site_street.set(""); self.build_site_line2.set(""); self.build_site_city.set("")
        self.build_site_state.set(""); self.build_site_postal.set(""); self.build_site_country.set("USA")
        self.build_source.set("")
        for product,var in self.product_vars.items():
            var.set(product in {"appliance","switch","wireless"})

        self.build_addressing_mode.set("Choose...")
        self.builder_vlans=[]
        self.builder_vlan_allow_non_rfc1918=False
        self.builder_single_lan={"subnet":"","applianceIp":"","allowNonRfc1918":False}
        self.build_note.set("Created with Meraki MSP Toolkit. Review site-specific settings before claiming devices.")

        self.builder_text.delete("1.0","end")
        self.builder_create_button.configure(text="CREATE",state="normal")
        self.builder_preview_button.configure(state="normal")
        self.builder_reset_button.configure(state="disabled")
        self.builder_status_var.set("Ready · new build")
        self._builder_set_controls_locked(False)
        self._builder_addressing_state()

    def _refresh_orgs_after_builder(self, preferred_org_id=None):
        orgs=self.require_api().get_all("/organizations")
        orgs=sorted(orgs,key=lambda x:(x.get("name") or "").lower())
        self.orgs=orgs
        self.holding_org=next((o for o in orgs if (o.get("name") or "").casefold()=="hardware holding".casefold()),None)
        if self.holding_org and not self.holding_networks:
            try:
                self.holding_networks=self.require_api().get_all(f"/organizations/{urllib.parse.quote(str(self.holding_org['id']))}/networks")
                self.holding_networks=sorted(self.holding_networks,key=lambda x:(x.get("name") or "").lower())
            except Exception:
                self.holding_networks=[]
        vals=["ALL ORGANIZATIONS"]+[self._org_label(o) for o in orgs]
        self.org_combo["values"]=vals
        chosen=None
        if preferred_org_id is not None:
            chosen=next((o for o in orgs if str(o.get("id"))==str(preferred_org_id)),None)
        self.selected_org_var.set(self._org_label(chosen) if chosen else "ALL ORGANIZATIONS")
        self.on_org_change()

    def _save_builder_verification(self, destination, payload, addressing, network_id, network_name, address_result):
        report_dir=REPORTS / "NetworkBuilder"
        report_dir.mkdir(parents=True,exist_ok=True)
        stem=f"Network-Build-Verified_{safe_filename(destination.get('name','org'))}_{safe_filename(network_name)}_{nowstamp()}"
        txt_path=report_dir / f"{stem}.txt"
        json_path=report_dir / f"{stem}.json"
        site=normalize_site_address(payload.get("_siteAddress"))
        site_full=format_site_address(site)
        lines=[
            "MERAKI NETWORK BUILD VERIFICATION",
            "="*72,
            f"Organization : {destination.get('name')}",
            f"Network      : {network_name} [{network_id}]",
            f"Build mode   : {self.build_mode.get()}",
            f"Addressing   : {addressing.get('mode')}",
            f"Verified     : {'YES' if address_result.get('verified') else 'NO'}",
            f"Site address : {site_full or '(not specified)'}",
            "",
            "ADDRESSING RESULT",
            "-----------------",
        ]
        details=list(address_result.get("details") or [])
        lines.extend([f"- {x}" for x in details] if details else ["- No addressing write was required."])
        lines.extend([
            "",
            "SITE LOCATION RESULT",
            "--------------------",
            (f"- Stored in network notes: {site_full}" if site_full else "- No physical site address was supplied during the build."),
            ("- Hardware / Inventory will automatically apply and verify this address on devices assigned to the network." if site_full else "- Set an address later under Post-Build > Site / Location if desired."),
            "",
            "NEXT",
            "----",
            "Complete Post-Build alert/site setup and verification, then move the required hardware from Hardware Holding.",
        ])
        data={
            "destination":destination,
            "networkPayload":payload,
            "addressingPlan":addressing,
            "networkId":network_id,
            "networkName":network_name,
            "addressingResult":address_result,
        }
        txt_path.write_text("\n".join(lines)+"\n",encoding="utf-8")
        json_path.write_text(json.dumps(data,indent=2)+"\n",encoding="utf-8")
        return txt_path

    def builder_apply(self):
        if self.builder_completed:
            messagebox.showinfo(
                "Build completed",
                "This build already completed successfully. Click New Build / Reset before creating another network."
            )
            return
        try:destination,payload,addressing=self.builder_payload()
        except Exception as e:messagebox.showerror("Network Builder",str(e));return
        if self.builder_create_button.instate(["disabled"]): return
        signature=self._builder_signature(destination,payload,addressing)
        if not self.last_build_signature or self.last_build_signature!=signature:
            messagebox.showwarning("Preview required","Run Preview / Dry Run after your last change before creating anything.");return
        nonprivate_networks=self._addressing_non_rfc1918_networks(addressing)
        clone_same_ip=(self.build_mode.get()=="Clone Existing" and addressing.get("mode")=="copied_from_source")
        required_confirm="CREATE SAME IP" if clone_same_ip else ("CREATE PUBLIC" if nonprivate_networks else "CREATE")
        warning_text=""
        if clone_same_ip:
            warning_text=(
                "\n\nWARNING: this clone will keep the source LAN/VLAN addressing and therefore duplicate its IP scheme. "
                "Only continue if overlapping/duplicate addressing is intentional."
            )
        elif nonprivate_networks:
            warning_text=(
                "\n\nWARNING: the LAN plan contains non-RFC1918/public address space: "
                + ", ".join(nonprivate_networks)
                + ". Confirm this is intentional and is NOT WAN/ISP addressing."
            )
        if destination["kind"]=="new":
            prompt=(
                f"Type {required_confirm} to create organization '{destination['name']}' and then create "
                f"network '{payload['name']}' inside it.{warning_text}"
            )
        else:
            prompt=f"Type {required_confirm} to create '{payload['name']}' in {destination.get('name')}.{warning_text}"
        confirm=simpledialog.askstring(required_confirm,prompt)
        if confirm!=required_confirm:return
        self._set_buttons([self.builder_preview_button,self.builder_create_button],"disabled")
        self.builder_create_button.configure(text="Creating...")
        self.builder_status_var.set("Creating...")
        completed={"ok":False}

        def work():
            api=self.require_api()
            if destination["kind"]=="new":
                self._emit("call",lambda:self.builder_status_var.set("Creating organization..."))
                created_org=api.post("/organizations",{"name":destination["name"]})
                if not isinstance(created_org,dict) or not created_org.get("id"):
                    raise RuntimeError("Meraki did not return an organization ID after create.")
                org_id=str(created_org["id"])
                org_name=created_org.get("name") or destination["name"]
                self._emit("log",f"Organization created: {org_name} [{org_id}]")
                admins=list(destination.get("admins") or [])
                created_admins=[]
                for index,admin in enumerate(admins,start=1):
                    self._emit("call",lambda i=index,t=len(admins):self.builder_status_var.set(f"Organization created · adding admin {i}/{t}..."))
                    try:
                        result_admin=api.post(
                            f"/organizations/{urllib.parse.quote(org_id)}/admins",
                            {
                                "email":admin["email"],
                                "name":admin["name"],
                                "orgAccess":admin["orgAccess"],
                            },
                        )
                        created_admins.append(admin["email"])
                        self._emit("log",f"Additional admin created: {admin['email']} ({admin['orgAccess']})")
                    except Exception as exc:
                        try:
                            self._emit("call",lambda oid=org_id:self._refresh_orgs_after_builder(oid))
                        except Exception:
                            pass
                        raise RuntimeError(
                            f"Organization '{org_name}' was created successfully (ID {org_id}). "
                            f"Additional admins already added: {', '.join(created_admins) if created_admins else 'none'}. "
                            f"Failed while adding {admin['email']}: {exc}. Network creation was NOT attempted, "
                            "and the organization was NOT rolled back."
                        ) from exc

                self._emit("call",lambda:self.builder_status_var.set("Organization/admins ready · creating network..."))
                try:
                    result=api.post(f"/organizations/{urllib.parse.quote(org_id)}/networks",self._builder_api_payload(payload))
                except Exception as exc:
                    # Deliberately do not delete the org or admins. Preserve partial success and report it.
                    try:
                        self._emit("call",lambda oid=org_id:self._refresh_orgs_after_builder(oid))
                    except Exception:
                        pass
                    raise RuntimeError(
                        f"Organization '{org_name}' was created successfully (ID {org_id}); "
                        f"additional admins added: {', '.join(created_admins) if created_admins else 'none requested'}. "
                        f"Network creation failed: {exc}. The organization/admins were NOT rolled back."
                    ) from exc
                if not isinstance(result,dict) or not result.get("id"):
                    raise RuntimeError(
                        f"Organization '{org_name}' and network '{payload['name']}' were created, but Meraki did not return the new network ID. "
                        "Addressing was NOT attempted and nothing was rolled back."
                    )
                created_net=result.get("name") or payload["name"]
                created_net_id=str(result["id"])
                self._emit("log",f"Network created: {created_net} [{created_net_id}] in new organization {org_name}")
                self._emit("call",lambda:self.builder_status_var.set("Network created · applying/verifying addressing..."))
                try:
                    address_result=self._apply_builder_addressing(api,created_net_id,addressing)
                except Exception as exc:
                    try:self._emit("call",lambda oid=org_id:self._refresh_orgs_after_builder(oid))
                    except Exception:pass
                    raise RuntimeError(
                        f"Organization '{org_name}' and network '{created_net}' [{created_net_id}] were created successfully, "
                        f"but addressing failed: {exc}. The network was NOT deleted or rolled back. Review the partial configuration before retrying."
                    ) from exc
                verify_path=self._save_builder_verification(destination,payload,addressing,created_net_id,created_net,address_result)
                self._emit("log",f"Addressing verified for {created_net}. Verification: {verify_path}")
                completed["ok"]=True
                def done_new():
                    admin_text=f" + {len(created_admins)} admin(s)" if created_admins else ""
                    addr_text="addressing skipped" if addressing.get("mode")=="skip" else "addressing verified"
                    self.postbuild_preferred_network_name=created_net
                    self._refresh_orgs_after_builder(org_id)
                    self._builder_mark_completed(
                        f"Created org{admin_text} + network · {addr_text}",
                        created_net_id,
                        created_net,
                    )
                self._emit("call",done_new)
            else:
                org_id=destination["id"]
                result=api.post(f"/organizations/{urllib.parse.quote(str(org_id))}/networks",self._builder_api_payload(payload))
                if not isinstance(result,dict) or not result.get("id"):
                    raise RuntimeError(
                        f"Network '{payload['name']}' appears to have been created, but Meraki did not return its network ID. "
                        "Addressing was NOT attempted. Check Dashboard before retrying."
                    )
                created=result.get("name") or payload["name"]
                created_id=str(result["id"])
                self._emit("log",f"Network created: {created} [{created_id}]")
                self._emit("call",lambda:self.builder_status_var.set("Network created · applying/verifying addressing..."))
                try:
                    address_result=self._apply_builder_addressing(api,created_id,addressing)
                except Exception as exc:
                    try:self._emit("call",self.on_org_change)
                    except Exception:pass
                    raise RuntimeError(
                        f"Network '{created}' [{created_id}] was created successfully, but addressing failed: {exc}. "
                        "The network was NOT deleted or rolled back. Review the partial configuration before retrying."
                    ) from exc
                verify_path=self._save_builder_verification(destination,payload,addressing,created_id,created,address_result)
                self._emit("log",f"Addressing verified for {created}. Verification: {verify_path}")
                completed["ok"]=True
                def done_existing():
                    addr_text="addressing skipped" if addressing.get("mode")=="skip" else "addressing verified"
                    self.postbuild_preferred_network_name=created
                    self.on_org_change()
                    self._builder_mark_completed(
                        f"Created · {created} · {addr_text}",
                        created_id,
                        created,
                    )
                self._emit("call",done_existing)

        def finished(error):
            if error is None and completed["ok"]:
                # Successful builds stay locked until New Build / Reset is explicitly clicked.
                self.builder_preview_button.configure(state="disabled")
                self.builder_create_button.configure(text="COMPLETED",state="disabled")
                self.builder_reset_button.configure(state="normal")
                return
            self.builder_create_button.configure(text="CREATE")
            self._finish_buttons([self.builder_preview_button,self.builder_create_button],self.builder_status_var,error)
            self.builder_reset_button.configure(state="disabled")
            if error is not None:self.builder_status_var.set("Create failed · safe to correct and Preview again")
        self.worker(work,finished)

    # ---------------- Organization cleanup ----------------
    @staticmethod
    def _cleanup_license_state(overview):
        if not isinstance(overview, dict):
            return {"activeValueCount": None, "expiredOnly": False, "notes": "License overview could not be read."}
        active_value = 0
        notes = []
        expired_only = False
        status = str(overview.get("status") or "").strip()
        expiration = overview.get("expirationDate")
        status_lower = status.lower()
        coterm_expired = "expired" in status_lower and "expires soon" not in status_lower
        ldc = overview.get("licensedDeviceCounts") or {}
        if isinstance(ldc, dict):
            total = sum(v for v in ldc.values() if isinstance(v, int) and v > 0)
            if total:
                if coterm_expired:
                    expired_only = True
                    notes.append(f"expired co-term licensedDeviceCounts={total}")
                else:
                    active_value += total
                    notes.append(f"licensedDeviceCounts={total}")
        states = overview.get("states") or {}
        if isinstance(states, dict):
            expired = ((states.get("expired") or {}).get("count"))
            if isinstance(expired, int) and expired > 0:
                notes.append(f"expired={expired}")
            for key in ("active", "expiring", "recentlyQueued", "unused", "unusedActive"):
                count = ((states.get(key) or {}).get("count"))
                if isinstance(count, int) and count > 0:
                    active_value += count
                    notes.append(f"{key}={count}")
        license_types = overview.get("licenseTypes") or []
        if isinstance(license_types, list):
            unassigned = 0
            for item in license_types:
                if isinstance(item, dict):
                    count = ((item.get("counts") or {}).get("unassigned"))
                    if isinstance(count, int) and count > 0:
                        unassigned += count
            if unassigned:
                active_value += unassigned
                notes.append(f"unassigned={unassigned}")
        sm = ((overview.get("systemsManager") or {}).get("counts") or {})
        if isinstance(sm, dict):
            for key in ("activeSeats", "unassignedSeats"):
                count = sm.get(key)
                if isinstance(count, int) and count > 0:
                    active_value += count
                    notes.append(f"SM {key}={count}")
        if status:
            notes.append(f"status={status}")
        if expiration:
            notes.append(f"expiration={expiration}")
        if active_value == 0 and (coterm_expired or expired_only):
            expired_only = True
        return {
            "activeValueCount": active_value,
            "expiredOnly": expired_only,
            "notes": "; ".join(notes) if notes else "No active license evidence returned.",
        }

    def _org_cleanup_reset(self, clear_text=False):
        self.last_cleanup_audit = None
        self.last_cleanup_admin_plan = None
        if hasattr(self, "cleanup_preview_admin_button"):
            self.cleanup_preview_admin_button.configure(state="disabled")
            self.cleanup_apply_admin_button.configure(state="disabled")
            self.cleanup_delete_org_button.configure(state="disabled")
            self.cleanup_status_var.set("Audit required")
        if hasattr(self, "cleanup_admin_tree"):
            for item in self.cleanup_admin_tree.get_children():
                self.cleanup_admin_tree.delete(item)
        if clear_text and hasattr(self, "cleanup_text"):
            self.cleanup_text.delete("1.0", "end")

    def _org_cleanup_fetch_audit(self, api, org):
        oid = str(org.get("id"))
        errors = {}
        def grab(label, fn, default=None):
            try:
                return fn()
            except Exception as exc:
                errors[label] = str(exc)
                return default

        networks = grab("networks", lambda: api.get_all(f"/organizations/{urllib.parse.quote(oid)}/networks"), None)
        inventory = grab("inventory", lambda: api.get_all(f"/organizations/{urllib.parse.quote(oid)}/inventory/devices"), None)
        admins = grab("admins", lambda: api.get(f"/organizations/{urllib.parse.quote(oid)}/admins"), None)
        saml = grab("saml", lambda: api.get(f"/organizations/{urllib.parse.quote(oid)}/saml"), None)
        licenses = grab("licenses", lambda: api.get(f"/organizations/{urllib.parse.quote(oid)}/licenses/overview"), None)
        templates = grab("configTemplates", lambda: api.get(f"/organizations/{urllib.parse.quote(oid)}/configTemplates"), None)

        network_count = len(networks) if isinstance(networks, list) else None
        inventory_count = len(inventory) if isinstance(inventory, list) else None
        admin_count = len(admins) if isinstance(admins, list) else None
        template_count = len(templates) if isinstance(templates, list) else None
        full_admin_count = sum(1 for a in admins if a.get("orgAccess") == "full") if isinstance(admins, list) else None
        saml_enabled = bool(saml.get("enabled")) if isinstance(saml, dict) else None
        license_state = self._cleanup_license_state(licenses) if isinstance(licenses, dict) else {"activeValueCount": None, "expiredOnly": False, "notes": errors.get("licenses", "License overview could not be read.")}

        blockers = []
        reviews = []
        if inventory_count is None:
            blockers.append(f"Inventory could not be verified: {errors.get('inventory','unknown error')}")
        elif inventory_count > 0:
            blockers.append(f"{inventory_count} device(s) remain in organization inventory.")
        if admin_count is None:
            blockers.append(f"Administrators could not be verified: {errors.get('admins','unknown error')}")
        elif admin_count != 1:
            blockers.append(f"{admin_count} dashboard administrator(s) exist; organization deletion requires one.")
        if full_admin_count is not None and full_admin_count != 1:
            blockers.append(f"{full_admin_count} full-access administrator(s) found; exactly one is required.")
        if saml_enabled is None:
            blockers.append(f"SAML status could not be verified: {errors.get('saml','unknown error')}")
        elif saml_enabled:
            blockers.append("SAML SSO is enabled.")
        active_value = license_state.get("activeValueCount")
        if active_value is None:
            reviews.append(f"License state could not be verified: {license_state.get('notes')}")
        elif active_value > 0:
            blockers.append(f"Active/valuable licensing evidence found ({license_state.get('notes')}).")
        elif license_state.get("expiredOnly"):
            reviews.append(f"Expired-only licensing found ({license_state.get('notes')}).")
        if network_count is None:
            blockers.append(f"Networks could not be verified: {errors.get('networks','unknown error')}")
        elif network_count > 0:
            blockers.append(f"{network_count} network(s) still exist; delete networks first.")
        if template_count is None:
            blockers.append(f"Configuration templates could not be verified: {errors.get('configTemplates','unknown error')}")
        elif template_count > 0:
            blockers.append(f"{template_count} configuration template(s) still exist.")

        if any(v is None for v in (inventory_count, admin_count, saml_enabled, network_count, template_count)):
            classification = "API ACCESS BLOCKED"
        elif (inventory_count or 0) > 0 or (active_value is not None and active_value > 0):
            classification = "ACTIVE - DO NOT DELETE"
        elif admin_count != 1 or full_admin_count != 1:
            classification = "SAFE AFTER ADMIN CLEANUP"
        elif saml_enabled or (network_count or 0) > 0 or (template_count or 0) > 0:
            classification = "CONFIG CLEANUP REQUIRED"
        else:
            classification = "READY FOR DELETE REVIEW"

        return {
            "organizationId": oid,
            "organizationName": str(org.get("name") or ""),
            "networks": networks if isinstance(networks, list) else [],
            "admins": admins if isinstance(admins, list) else [],
            "networkCount": network_count,
            "inventoryDeviceCount": inventory_count,
            "adminCount": admin_count,
            "fullAdminCount": full_admin_count,
            "samlEnabled": saml_enabled,
            "configTemplateCount": template_count,
            "licenseActiveValueCount": active_value,
            "licenseExpiredOnly": bool(license_state.get("expiredOnly")),
            "licenseNotes": str(license_state.get("notes") or ""),
            "blockers": blockers,
            "reviews": reviews,
            "classification": classification,
            "eligible": classification == "READY FOR DELETE REVIEW" and not blockers,
            "errors": errors,
        }

    def _org_cleanup_audit_text(self, audit):
        yn = lambda x: "YES" if x is True else ("NO" if x is False else "UNKNOWN")
        lines = [
            "MERAKI ORGANIZATION CLEANUP AUDIT",
            "=" * 72,
            f"Organization       : {audit['organizationName']}",
            f"Organization ID    : {audit['organizationId']}",
            "",
            "CURRENT STATE",
            "-------------",
            f"Networks           : {audit['networkCount'] if audit['networkCount'] is not None else 'UNKNOWN'}",
            f"Inventory devices  : {audit['inventoryDeviceCount'] if audit['inventoryDeviceCount'] is not None else 'UNKNOWN'}",
            f"Dashboard admins   : {audit['adminCount'] if audit['adminCount'] is not None else 'UNKNOWN'}",
            f"Full-access admins : {audit['fullAdminCount'] if audit['fullAdminCount'] is not None else 'UNKNOWN'}",
            f"SAML enabled       : {yn(audit['samlEnabled'])}",
            f"Config templates   : {audit['configTemplateCount'] if audit['configTemplateCount'] is not None else 'UNKNOWN'}",
            f"Active license val.: {audit['licenseActiveValueCount'] if audit['licenseActiveValueCount'] is not None else 'UNKNOWN'}",
            f"Expired-only lic.  : {yn(audit['licenseExpiredOnly'])}",
            "",
            f"CLASSIFICATION     : {audit['classification']}",
        ]
        if audit["blockers"]:
            lines += ["", "BLOCKERS", "--------"] + [f"[BLOCK] {x}" for x in audit["blockers"]]
        if audit["reviews"]:
            lines += ["", "REVIEW", "------"] + [f"[REVIEW] {x}" for x in audit["reviews"]]
        lines += ["", "CLEANUP PATH", "------------"]
        cls = audit["classification"]
        if cls == "SAFE AFTER ADMIN CLEANUP":
            lines.append("Select the ONE full-access admin to keep, preview the admin cleanup, then remove the extras.")
        elif cls == "CONFIG CLEANUP REQUIRED":
            if (audit.get("networkCount") or 0) > 0:
                lines.append("Networks remain. Use the separate Delete Network tab, then re-audit this organization.")
            if audit.get("samlEnabled"):
                lines.append("SAML is enabled. Disable/review SAML in Dashboard before organization deletion.")
            if (audit.get("configTemplateCount") or 0) > 0:
                lines.append("Configuration templates remain and must be reviewed/deleted before organization deletion.")
        elif cls == "READY FOR DELETE REVIEW":
            lines.append("All automated blockers are clear. Permanent organization deletion can be reviewed.")
        elif cls == "ACTIVE - DO NOT DELETE":
            lines.append("This organization still has hardware or current license value. Cleanup/delete is blocked.")
        else:
            lines.append("Required API checks could not be completed. Do not delete the organization.")
        return "\n".join(lines)

    def org_cleanup_audit(self):
        try:
            org = self.selected_org()
        except Exception as exc:
            messagebox.showerror("Organization Cleanup", str(exc))
            return
        self._org_cleanup_reset(clear_text=True)
        self.cleanup_audit_button.configure(text="Auditing...", state="disabled")
        self.cleanup_status_var.set("Auditing organization...")

        def work():
            audit = self._org_cleanup_fetch_audit(self.require_api(), org)
            text = self._org_cleanup_audit_text(audit)
            folder = REPORTS / "OrgCleanup"
            folder.mkdir(parents=True, exist_ok=True)
            stem = f"Org-Cleanup-Audit_{safe_filename(org.get('name','org'))}_{nowstamp()}"
            txt = folder / f"{stem}.txt"
            js = folder / f"{stem}.json"
            txt.write_text(text + "\n", encoding="utf-8")
            js.write_text(json.dumps(audit, indent=2), encoding="utf-8")
            def done():
                self.last_cleanup_audit = audit
                self.cleanup_text.delete("1.0", "end")
                self.cleanup_text.insert("end", text)
                for item in self.cleanup_admin_tree.get_children():
                    self.cleanup_admin_tree.delete(item)
                for admin in audit.get("admins") or []:
                    self.cleanup_admin_tree.insert("", "end", iid=str(admin.get("id")), values=(admin.get("name", ""), admin.get("email", ""), admin.get("orgAccess", "")))
                can_admin = audit.get("classification") == "SAFE AFTER ADMIN CLEANUP" and len(audit.get("admins") or []) > 1
                self.cleanup_preview_admin_button.configure(state="normal" if can_admin else "disabled")
                self.cleanup_apply_admin_button.configure(state="disabled")
                self.cleanup_delete_org_button.configure(state="normal" if audit.get("eligible") else "disabled")
                self.cleanup_status_var.set(audit.get("classification") or "Audit complete")
                self.write_log(f"Organization cleanup audit complete: {org.get('name')} · {audit.get('classification')} · TXT: {txt}")
            self._emit("call", done)

        def finished(error):
            self.cleanup_audit_button.configure(text="Audit Organization", state="normal")
            if error is not None:
                self.cleanup_status_var.set("Audit failed")
        self.worker(work, finished)

    def org_cleanup_preview_admin(self):
        audit = self.last_cleanup_audit or {}
        if audit.get("classification") != "SAFE AFTER ADMIN CLEANUP":
            messagebox.showwarning("Admin Cleanup", "Run an audit first. Admin cleanup is enabled only for a SAFE AFTER ADMIN CLEANUP candidate.")
            return
        selection = self.cleanup_admin_tree.selection()
        if len(selection) != 1:
            messagebox.showwarning("Admin Cleanup", "Select the ONE administrator to KEEP.")
            return
        keep_id = selection[0]
        admins = list(audit.get("admins") or [])
        keep = next((a for a in admins if str(a.get("id")) == keep_id), None)
        if not keep:
            messagebox.showerror("Admin Cleanup", "The selected administrator could not be matched. Re-audit the organization.")
            return
        if keep.get("orgAccess") != "full":
            messagebox.showerror("Admin Cleanup", "The administrator you keep must have full organization access.")
            return
        remove = [a for a in admins if str(a.get("id")) != keep_id]
        if not remove:
            messagebox.showinfo("Admin Cleanup", "There are no extra administrators to remove.")
            return
        plan = {
            "organizationId": audit["organizationId"],
            "organizationName": audit["organizationName"],
            "keepAdmin": keep,
            "removeAdmins": remove,
        }
        lines = [
            "MERAKI ADMIN CLEANUP PLAN",
            "=" * 72,
            "DRY RUN - NO ADMINISTRATORS WILL BE REMOVED",
            "",
            f"Organization : {plan['organizationName']} [{plan['organizationId']}]",
            "",
            "KEEP",
            "----",
            f"{keep.get('name') or '(no name)'} | {keep.get('email') or '(no email)'} | {keep.get('orgAccess') or 'unknown'}",
            "",
            "REMOVE",
            "------",
        ]
        for admin in remove:
            lines.append(f"- {admin.get('name') or '(no name)'} | {admin.get('email') or '(no email)'} | {admin.get('orgAccess') or 'unknown'}")
        lines += [
            "",
            "SAFETY",
            "------",
            "- The organization is currently classified SAFE AFTER ADMIN CLEANUP.",
            "- The selected KEEP administrator is full-access.",
            "- Admin membership will be re-read immediately before removal.",
            "- The operation must still leave exactly one administrator.",
            "- Networks, devices, licensing, SAML, and configuration templates are NOT changed.",
            "- If this API key belongs to an administrator in REMOVE, the current API session may lose access immediately.",
            "",
            "Typed confirmation required: REMOVE",
        ]
        text = "\n".join(lines)
        folder = REPORTS / "OrgCleanup"
        folder.mkdir(parents=True, exist_ok=True)
        stem = f"Admin-Cleanup-Plan_{safe_filename(plan['organizationName'])}_{nowstamp()}"
        txt = folder / f"{stem}.txt"
        js = folder / f"{stem}.json"
        txt.write_text(text + "\n", encoding="utf-8")
        js.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        self.last_cleanup_admin_plan = plan
        self.cleanup_text.delete("1.0", "end")
        self.cleanup_text.insert("end", text)
        self.cleanup_apply_admin_button.configure(state="normal")
        self.cleanup_status_var.set(f"Admin plan ready · remove {len(remove)}")
        self.write_log(f"Admin cleanup preview ready: keep={keep.get('email')} remove={len(remove)} · TXT: {txt}")

    def org_cleanup_apply_admin(self):
        plan = dict(self.last_cleanup_admin_plan or {})
        if not plan:
            messagebox.showwarning("Admin Cleanup", "Preview Admin Cleanup first.")
            return
        if self.public_var.get():
            messagebox.showwarning("Admin Cleanup", "Turn off Public display before making destructive changes.")
            return
        try:
            org = self.selected_org()
            if str(org.get("id")) != str(plan.get("organizationId")):
                raise RuntimeError("Organization selection changed after preview. Re-audit and preview again.")
        except Exception as exc:
            messagebox.showerror("Admin Cleanup", str(exc))
            return
        expected = "REMOVE"
        confirm = simpledialog.askstring(
            "REMOVE Extra Admins",
            f"Organization: {plan['organizationName']}\n"
            f"Keep: {plan['keepAdmin'].get('name')} <{plan['keepAdmin'].get('email')}>\n"
            f"Remove: {len(plan['removeAdmins'])} administrator(s)\n\n"
            f"Type exactly: {expected}"
        )
        if confirm != expected:
            self.cleanup_status_var.set("Admin cleanup cancelled")
            return
        self._set_buttons([self.cleanup_audit_button, self.cleanup_preview_admin_button, self.cleanup_apply_admin_button, self.cleanup_delete_org_button], "disabled")
        self.cleanup_apply_admin_button.configure(text="Removing...")
        self.cleanup_status_var.set("Re-verifying administrators...")

        def work():
            api = self.require_api()
            oid = str(plan["organizationId"])
            latest = api.get(f"/organizations/{urllib.parse.quote(oid)}/admins")
            if not isinstance(latest, list):
                raise RuntimeError("Could not re-read organization administrators. Nothing changed.")
            current = {str(a.get("id")): a for a in latest if a.get("id") is not None}
            keep_id = str(plan["keepAdmin"].get("id"))
            remove_ids = [str(a.get("id")) for a in plan["removeAdmins"]]
            if keep_id not in current or current[keep_id].get("orgAccess") != "full":
                raise RuntimeError("The selected keep-admin is missing or no longer full-access. Nothing changed.")
            if any(admin_id not in current for admin_id in remove_ids):
                raise RuntimeError("Administrator membership changed since preview. Re-audit before applying.")
            if len(latest) - len(remove_ids) != 1:
                raise RuntimeError("Safety check failed: this operation would not leave exactly one administrator.")
            removed = []
            for idx, admin_id in enumerate(remove_ids, 1):
                self._emit("call", lambda i=idx, t=len(remove_ids): self.cleanup_status_var.set(f"Removing admin {i}/{t}..."))
                api.delete(f"/organizations/{urllib.parse.quote(oid)}/admins/{urllib.parse.quote(admin_id)}")
                removed.append(admin_id)
            updated = self._org_cleanup_fetch_audit(api, org)
            def done():
                self.last_cleanup_admin_plan = None
                self.last_cleanup_audit = updated
                self.cleanup_text.delete("1.0", "end")
                self.cleanup_text.insert("end", self._org_cleanup_audit_text(updated))
                for item in self.cleanup_admin_tree.get_children():
                    self.cleanup_admin_tree.delete(item)
                for admin in updated.get("admins") or []:
                    self.cleanup_admin_tree.insert("", "end", iid=str(admin.get("id")), values=(admin.get("name", ""), admin.get("email", ""), admin.get("orgAccess", "")))
                self.cleanup_status_var.set(f"Removed {len(removed)} admin(s) · {updated.get('classification')}")
                self.cleanup_preview_admin_button.configure(state="normal" if updated.get("classification") == "SAFE AFTER ADMIN CLEANUP" and len(updated.get("admins") or []) > 1 else "disabled")
                self.cleanup_apply_admin_button.configure(state="disabled")
                self.cleanup_delete_org_button.configure(state="normal" if updated.get("eligible") else "disabled")
                self.write_log(f"Organization admin cleanup complete: removed {len(removed)} admin(s) from {plan['organizationName']}.")
            self._emit("call", done)

        def finished(error):
            self.cleanup_apply_admin_button.configure(text="REMOVE Extra Admins")
            self.cleanup_audit_button.configure(state="normal")
            if error is not None:
                self.cleanup_preview_admin_button.configure(state="disabled")
                self.cleanup_apply_admin_button.configure(state="disabled")
                self.cleanup_delete_org_button.configure(state="disabled")
                self.cleanup_status_var.set("Admin cleanup failed · re-audit required")
        self.worker(work, finished)

    def org_cleanup_delete_org(self):
        audit = dict(self.last_cleanup_audit or {})
        if not audit.get("eligible") or audit.get("classification") != "READY FOR DELETE REVIEW":
            messagebox.showwarning("Delete Organization", "Run a fresh organization audit. Delete is enabled only when every automated blocker is clear.")
            return
        if self.public_var.get():
            messagebox.showwarning("Delete Organization", "Turn off Public display before making destructive changes.")
            return
        try:
            org = self.selected_org()
            if str(org.get("id")) != str(audit.get("organizationId")):
                raise RuntimeError("Organization selection changed after audit. Re-audit before deletion.")
        except Exception as exc:
            messagebox.showerror("Delete Organization", str(exc))
            return
        expected = "DELETE ORG"
        confirm = simpledialog.askstring(
            "DELETE Organization",
            "PERMANENT ORGANIZATION DELETION\n\n"
            f"Organization: {audit['organizationName']} [{audit['organizationId']}]\n\n"
            "The toolkit will re-run the full audit immediately before DELETE.\n"
            "No networks, devices, active license value, SAML, templates, or extra admins may remain.\n\n"
            f"Type exactly: {expected}"
        )
        if confirm != expected:
            self.cleanup_status_var.set("Organization delete cancelled")
            return
        self._set_buttons([self.cleanup_audit_button, self.cleanup_preview_admin_button, self.cleanup_apply_admin_button, self.cleanup_delete_org_button], "disabled")
        self.cleanup_delete_org_button.configure(text="Deleting...")
        self.cleanup_status_var.set("Running final safety audit...")

        def work():
            api = self.require_api()
            oid = str(audit["organizationId"])
            latest = self._org_cleanup_fetch_audit(api, org)
            if not latest.get("eligible") or latest.get("classification") != "READY FOR DELETE REVIEW":
                raise RuntimeError("Delete blocked: the final safety audit no longer passes. Re-audit and review the blockers.")
            endpoint = f"/organizations/{urllib.parse.quote(oid)}"
            self._emit("log", f"ORGANIZATION DELETE REQUEST: DELETE {endpoint} | {audit['organizationName']} [{oid}]")
            api.delete(endpoint)

            # Meraki can acknowledge DELETE before the organization disappears from
            # subsequent reads. Verify with retries instead of reporting a false failure.
            verified = False
            verification_note = ""
            max_attempts = 12
            delay_seconds = 2

            for attempt in range(1, max_attempts + 1):
                self._emit(
                    "call",
                    lambda a=attempt, m=max_attempts: self.cleanup_status_var.set(
                        f"DELETE accepted · verifying {a}/{m}..."
                    ),
                )

                # A direct GET returning 404 is the strongest confirmation that the
                # exact organization ID no longer exists.
                direct_absent = False
                try:
                    api.get(endpoint)
                except RuntimeError as exc:
                    if str(exc).startswith("HTTP 404:"):
                        direct_absent = True
                    else:
                        self._emit("log", f"Org delete verification GET warning: {exc}")

                if direct_absent:
                    verified = True
                    verification_note = "Direct organization lookup returned HTTP 404."
                    break

                # Also check the accessible-organization list. This handles cases where
                # the API returns a different response for a just-deleted org.
                try:
                    orgs = api.get_all("/organizations")
                    if not any(str(o.get("id")) == oid for o in orgs):
                        verified = True
                        verification_note = "The organization ID disappeared from the organization list."
                        break
                except Exception as exc:
                    self._emit("log", f"Org delete verification list warning: {exc}")

                if attempt < max_attempts:
                    time.sleep(delay_seconds)

            if not verified:
                raise RuntimeError(
                    "Meraki accepted the DELETE request, but the organization ID is still "
                    f"being returned after {max_attempts} verification attempts over about "
                    f"{(max_attempts - 1) * delay_seconds} seconds. Do NOT click delete again. "
                    "Refresh Meraki Dashboard and the toolkit, then verify whether the org is gone."
                )

            def done():
                self.cleanup_text.delete("1.0", "end")
                self.cleanup_text.insert(
                    "end",
                    "ORGANIZATION DELETE VERIFIED\n"
                    + "=" * 72
                    + f"\nName : {audit['organizationName']}\nID   : {oid}\n\n"
                    + verification_note
                    + "\n\nThe toolkit waited for Meraki propagation before reporting success.",
                )
                self.cleanup_status_var.set("Deleted · VERIFIED")
                self.last_cleanup_audit = None
                self.last_cleanup_admin_plan = None
                self.write_log(
                    f"Organization deletion verified after propagation: "
                    f"{audit['organizationName']} [{oid}] | {verification_note}"
                )
                self.connect()
            self._emit("call", done)

        def finished(error):
            self.cleanup_delete_org_button.configure(text="DELETE Organization")
            self.cleanup_audit_button.configure(state="normal")
            if error is not None:
                self.cleanup_status_var.set("Organization delete failed · re-audit required")
        self.worker(work, finished)

    def org_cleanup_go_delete_network(self):
        try:
            target = next(tab for tab in self.nb.tabs() if self.nb.tab(tab, "text") == "Delete Network")
            self.nb.select(target)
        except Exception:
            pass

    # ---------------- Network deletion ----------------
    @staticmethod
    def _delete_device_product_type(device):
        pt=str(device.get("productType") or "").strip()
        if pt:
            return pt
        model=str(device.get("model") or "").strip().upper()
        if model.startswith(("MX","Z")):
            return "appliance"
        if model.startswith(("MS","C9","C9300","C9200")):
            return "switch"
        if model.startswith("MR"):
            return "wireless"
        if model.startswith("MV"):
            return "camera"
        if model.startswith("MT"):
            return "sensor"
        if model.startswith("MG"):
            return "cellularGateway"
        return ""

    def _delete_holding_target_spec(self, device, holding_networks=None):
        if not self.holding_org:
            raise RuntimeError("Hardware Holding was not found in this API session.")
        networks=list(self.holding_networks if holding_networks is None else holding_networks)
        serial=str(device.get("serial") or "").strip().upper()
        model=str(device.get("model") or "").strip().upper()
        pt=self._delete_device_product_type(device)
        if not serial:
            raise RuntimeError("An assigned device does not have a serial number; automatic disposition is blocked.")
        if not pt:
            raise RuntimeError(f"Cannot determine the Meraki product type for {model or 'device'} {serial}.")

        def compatible(net):
            pts=[str(x) for x in (net.get("productTypes") or [])]
            return pt in pts

        # Appliances / teleworker gateways get a dedicated holding network.
        if pt == "appliance":
            exact=next((n for n in networks if serial.casefold() in str(n.get("name") or "").casefold() and compatible(n)),None)
            if exact:
                return {"networkId":str(exact.get("id")),"networkName":str(exact.get("name") or ""),"productType":pt,"create":False}
            safe_model=model or "Appliance"
            name=f"Hardware Holding - {safe_model} - {serial}"
            named=next((n for n in networks if str(n.get("name") or "").casefold()==name.casefold() and compatible(n)),None)
            if named:
                return {"networkId":str(named.get("id")),"networkName":str(named.get("name") or ""),"productType":pt,"create":False}
            return {"networkId":None,"networkName":name,"productType":pt,"create":True}

        canonical={
            "switch":"Hardware Holding - Switches",
            "wireless":"Hardware Holding - Wireless",
            "camera":"Hardware Holding - Cameras",
            "sensor":"Hardware Holding - Sensors",
            "cellularGateway":"Hardware Holding - Cellular",
            "campusGateway":"Hardware Holding - Campus Gateways",
            "wirelessController":"Hardware Holding - Wireless Controllers",
        }
        target_name=canonical.get(pt)
        if not target_name:
            raise RuntimeError(f"No Hardware Holding rule exists for product type '{pt}' ({serial}).")
        named=next((n for n in networks if str(n.get("name") or "").casefold()==target_name.casefold() and compatible(n)),None)
        if named:
            return {"networkId":str(named.get("id")),"networkName":str(named.get("name") or ""),"productType":pt,"create":False}
        matches=[n for n in networks if compatible(n)]
        if len(matches)==1:
            n=matches[0]
            return {"networkId":str(n.get("id")),"networkName":str(n.get("name") or ""),"productType":pt,"create":False}
        return {"networkId":None,"networkName":target_name,"productType":pt,"create":True}

    @staticmethod
    def _delete_device_snapshot(devices):
        rows=[]
        for d in devices or []:
            rows.append({
                "serial":str(d.get("serial") or "").strip().upper(),
                "model":str(d.get("model") or "").strip(),
                "name":str(d.get("name") or "").strip(),
                "productType":Toolkit._delete_device_product_type(d),
            })
        return sorted(rows,key=lambda x:(x["serial"],x["model"],x["name"]))

    def _delete_network_signature(self, org, net, disposition, devices):
        return json.dumps(
            {
                "orgId":str(org.get("id")),
                "networkId":str(net.get("id")),
                "disposition":disposition,
                "devices":self._delete_device_snapshot(devices),
            },
            sort_keys=True,
            separators=(",",":"),
        )

    @staticmethod
    def _delete_confirmation_word(disposition, device_count):
        if not device_count:
            return "DELETE"
        return {
            "holding":"RETURN DELETE",
            "keep":"KEEP DELETE",
            "unclaim":"UNCLAIM DELETE",
        }[disposition]

    def _delete_network_plan_text(self, org, net, devices, disposition, holding_targets=None):
        products=list(net.get("productTypes") or [])
        disp_label={
            "holding":"1 - Return to Hardware Holding",
            "keep":"2 - Keep in Customer Organization Inventory",
            "unclaim":"3 - Unclaim from Customer Organization",
        }[disposition]
        lines=[
            "MERAKI NETWORK DELETE PLAN",
            "="*72,
            "DRY RUN - NO CHANGES WILL BE MADE",
            "",
            "ORGANIZATION",
            "------------",
            f"Name       : {org.get('name')}",
            f"ID         : {org.get('id')}",
            "",
            "NETWORK",
            "-------",
            f"Name       : {net.get('name')}",
            f"ID         : {net.get('id')}",
            f"Products   : {', '.join(products) if products else '(none reported)'}",
            f"Devices    : {len(devices)} assigned",
            "",
            "HARDWARE DISPOSITION",
            "--------------------",
            disp_label,
        ]
        if not devices:
            lines.extend(["- No assigned hardware; no hardware disposition action is required."])
        elif disposition=="holding":
            lines.append(f"Destination organization: {self.holding_org.get('name')} [{self.holding_org.get('id')}]")
            for d in self._delete_device_snapshot(devices):
                spec=(holding_targets or {}).get(d["serial"],{})
                suffix=" (will create)" if spec.get("create") else ""
                lines.append(
                    f"- {d['model']} {d['serial']} {d['name'] or ''}".rstrip()
                    + f" -> {spec.get('networkName','(unresolved)')}{suffix}"
                )
            lines.extend([
                "",
                "Devices will be removed from the customer network, released from the customer organization,",
                "claimed into Hardware Holding, assigned to the mapped holding network, and verified there before deletion continues.",
            ])
        elif disposition=="keep":
            for d in self._delete_device_snapshot(devices):
                lines.append(f"- {d['model']} {d['serial']} {d['name'] or ''}".rstrip())
            lines.extend([
                "",
                "Devices will be removed from this network but will remain claimed in the SAME customer organization inventory.",
                "The toolkit will verify each serial is unassigned before deleting the network.",
            ])
        else:
            for d in self._delete_device_snapshot(devices):
                lines.append(f"- {d['model']} {d['serial']} {d['name'] or ''}".rstrip())
            lines.extend([
                "",
                "WARNING: Devices will be removed from this network AND RELEASED from the customer organization inventory.",
                "After release, the customer organization will no longer claim these serials.",
            ])

        confirm=self._delete_confirmation_word(disposition,len(devices))
        lines.extend([
            "",
            "WHAT APPLY WILL DO",
            "------------------",
            f"1. Re-check exact organization ID {org.get('id')} and network ID {net.get('id')}.",
            "2. Re-read assigned hardware and require the exact same serial list shown in this preview.",
            "3. Perform the selected hardware disposition and verify its final state.",
            "4. Re-check that the target network has zero assigned devices.",
            f"5. Delete only network ID {net.get('id')}.",
            "6. Re-read the organization network list and verify the exact network ID is absent.",
            "",
            f"Typed confirmation required: {confirm}",
            "No automatic rollback is attempted after a partial API success; the toolkit stops and reports the exact stage.",
        ])
        if disposition=="unclaim" and devices:
            lines.extend([
                "",
                "UNCLAIM WARNING",
                "---------------",
                "This option intentionally releases the listed serials from the customer organization. Use only when the hardware should no longer belong to that organization.",
            ])
        return "\n".join(lines)

    def delete_network_preview(self):
        try:
            org=self.selected_org()
            net=self.net_from_label(self.delete_net_var.get())
            if not net:
                raise RuntimeError("Select a network to delete.")
            disposition=self._delete_disposition_code()
            if disposition=="holding":
                if not self.holding_org:
                    raise RuntimeError("Hardware Holding was not found in this API session.")
                if str(org.get("id"))==str(self.holding_org.get("id")):
                    raise RuntimeError("Return to Hardware Holding cannot be used while deleting a network already inside Hardware Holding.")
        except Exception as exc:
            messagebox.showerror("Delete Network",str(exc))
            return
        self._set_buttons([self.delete_preview_button,self.delete_apply_button],"disabled")
        self.delete_preview_button.configure(text="Checking...")
        self.delete_status_var.set("Checking network and hardware...")
        self.last_delete_signature=None

        def work():
            api=self.require_api()
            devices=api.get_all(f"/networks/{urllib.parse.quote(str(net['id']))}/devices")
            if not isinstance(devices,list):
                devices=[]
            holding_targets={}
            fresh_holding=[]
            if disposition=="holding" and devices:
                fresh_holding=api.get_all(f"/organizations/{urllib.parse.quote(str(self.holding_org['id']))}/networks")
                if not isinstance(fresh_holding,list):
                    fresh_holding=[]
                for d in devices:
                    serial=str(d.get("serial") or "").strip().upper()
                    holding_targets[serial]=self._delete_holding_target_spec(d,fresh_holding)
            plan=self._delete_network_plan_text(org,net,devices,disposition,holding_targets)
            signature=self._delete_network_signature(org,net,disposition,devices)
            report_dir=REPORTS/"NetworkBuilder"
            report_dir.mkdir(parents=True,exist_ok=True)
            stem=f"Network-Delete-Plan_{safe_filename(org.get('name','org'))}_{safe_filename(net.get('name','network'))}_{nowstamp()}"
            txt_path=report_dir/f"{stem}.txt"
            json_path=report_dir/f"{stem}.json"
            txt_path.write_text(plan+"\n",encoding="utf-8")
            json_path.write_text(
                json.dumps({
                    "organization":org,
                    "network":net,
                    "disposition":disposition,
                    "devices":self._delete_device_snapshot(devices),
                    "holdingTargets":holding_targets,
                },indent=2)+"\n",
                encoding="utf-8",
            )
            def done():
                if disposition=="holding":
                    self.holding_networks=sorted(fresh_holding,key=lambda x:(x.get("name") or "").lower())
                    self._refresh_holding_controls()
                self.delete_text.delete("1.0","end")
                self.delete_text.insert("end",plan)
                self.delete_status_var.set(f"Preview ready · {len(devices)} device(s) · disposition locked")
                self.last_delete_signature=signature
                self.last_delete_preview={
                    "orgId":str(org.get("id")),
                    "orgName":str(org.get("name") or ""),
                    "networkId":str(net.get("id")),
                    "networkName":str(net.get("name") or ""),
                    "disposition":disposition,
                    "devices":self._delete_device_snapshot(devices),
                    "holdingTargets":holding_targets,
                    "signature":signature,
                }
                self.delete_apply_button.configure(state="normal")
                self.write_log(
                    f"Network delete preview: {org.get('name')} / {net.get('name')} · devices={len(devices)} · disposition={disposition} · TXT: {txt_path}"
                )
            self._emit("call",done)

        def finished(error):
            self.delete_preview_button.configure(text="Preview Delete",state="normal")
            if error is not None:
                self.delete_apply_button.configure(state="disabled")
                self.last_delete_preview=None
                self.last_delete_signature=None
                self.delete_status_var.set("Delete preview failed")
        self.worker(work,finished)

    @staticmethod
    def _inventory_by_serial(inventory):
        return {norm_serial(str(d.get("serial") or "")):d for d in (inventory or []) if d.get("serial")}

    def _delete_wait_for_network_empty(self, api, net_id, attempts=8, delay=1.5):
        last=[]
        for i in range(attempts):
            last=api.get_all(f"/networks/{urllib.parse.quote(str(net_id))}/devices")
            if not isinstance(last,list) or not last:
                return []
            if i<attempts-1:
                time.sleep(delay)
        return last if isinstance(last,list) else []

    def _delete_wait_inventory(self, api, org_id, predicate, attempts=8, delay=1.5):
        last=[]
        for i in range(attempts):
            last=api.get_all(f"/organizations/{urllib.parse.quote(str(org_id))}/inventory/devices")
            if predicate(last if isinstance(last,list) else []):
                return last if isinstance(last,list) else []
            if i<attempts-1:
                time.sleep(delay)
        return last if isinstance(last,list) else []

    def delete_network_apply(self):
        preview=dict(self.last_delete_preview or {})
        if not preview:
            messagebox.showwarning("Preview required","Run Preview Delete immediately before deleting a network.")
            return
        try:
            org=self.selected_org()
            net=self.net_from_label(self.delete_net_var.get())
            disposition=self._delete_disposition_code()
            if not net:
                raise RuntimeError("Select a network to delete.")
            if str(org.get("id"))!=preview.get("orgId") or str(net.get("id"))!=preview.get("networkId"):
                raise RuntimeError("Organization or network selection changed after preview. Run Preview Delete again.")
            if disposition!=preview.get("disposition"):
                raise RuntimeError("Hardware disposition changed after preview. Run Preview Delete again.")
        except Exception as exc:
            messagebox.showerror("Delete Network",str(exc))
            return

        expected=self._delete_confirmation_word(preview["disposition"],len(preview.get("devices") or []))
        confirm=simpledialog.askstring(
            "DELETE Network",
            "Hardware disposition + permanent network deletion\n\n"
            f"Organization: {preview['orgName']} [{preview['orgId']}]\n"
            f"Network: {preview['networkName']} [{preview['networkId']}]\n"
            f"Devices in preview: {len(preview.get('devices') or [])}\n"
            f"Disposition: {self.delete_disposition_var.get()}\n\n"
            f"Type exactly: {expected}"
        )
        if confirm!=expected:
            self.delete_status_var.set("Delete cancelled")
            return

        self._set_buttons([self.delete_preview_button,self.delete_apply_button,self.delete_disposition_combo],"disabled")
        self.delete_apply_button.configure(text="Working...")
        self.delete_status_var.set("Verifying exact IDs and hardware list...")

        def set_status(text):
            self._emit("call",lambda t=text:self.delete_status_var.set(t))

        def work():
            api=self.require_api()
            org_id=preview["orgId"]
            net_id=preview["networkId"]
            disposition=preview["disposition"]
            preview_devices=list(preview.get("devices") or [])
            preview_serials=[d["serial"] for d in preview_devices]
            preview_norm=sorted(norm_serial(x) for x in preview_serials)
            action_log=[]

            # Verify exact network identity.
            org_nets=api.get_all(f"/organizations/{urllib.parse.quote(org_id)}/networks")
            current=next((n for n in org_nets if str(n.get("id"))==net_id),None)
            if not current:
                raise RuntimeError("Delete aborted: the previewed network ID is no longer present in the selected organization.")
            if str(current.get("name") or "")!=preview["networkName"]:
                raise RuntimeError(
                    f"Delete aborted: network ID {net_id} is now named '{current.get('name')}'. Run Preview Delete again."
                )

            # Lock the hardware serial list to the preview.
            live_devices=api.get_all(f"/networks/{urllib.parse.quote(net_id)}/devices")
            if not isinstance(live_devices,list):
                live_devices=[]
            live_snapshot=self._delete_device_snapshot(live_devices)
            live_norm=sorted(norm_serial(d["serial"]) for d in live_snapshot)
            if live_norm!=preview_norm:
                raise RuntimeError(
                    "Delete aborted: assigned hardware changed after preview. "
                    f"Preview serials={preview_serials or ['NONE']} · Current serials={[d['serial'] for d in live_snapshot] or ['NONE']}. "
                    "Run Preview Delete again."
                )

            if live_devices and disposition=="holding":
                if not self.holding_org:
                    raise RuntimeError("Hardware Holding is no longer available in this API session.")
                holding_id=str(self.holding_org.get("id"))
                set_status("Preparing Hardware Holding targets...")
                holding_nets=api.get_all(f"/organizations/{urllib.parse.quote(holding_id)}/networks")
                if not isinstance(holding_nets,list):
                    holding_nets=[]
                target_by_serial={}
                # Create any required holding networks BEFORE releasing customer hardware.
                for d in live_devices:
                    serial=str(d.get("serial") or "").strip().upper()
                    planned=(preview.get("holdingTargets") or {}).get(serial) or self._delete_holding_target_spec(d,holding_nets)
                    target=None
                    planned_id=planned.get("networkId")
                    if planned_id:
                        target=next((n for n in holding_nets if str(n.get("id"))==str(planned_id)),None)
                        if not target or str(target.get("name") or "")!=str(planned.get("networkName") or ""):
                            raise RuntimeError(f"Holding target for {serial} changed after preview. Run Preview Delete again.")
                    else:
                        target=next((n for n in holding_nets if str(n.get("name") or "").casefold()==str(planned.get("networkName") or "").casefold()),None)
                        if target and planned.get("productType") not in [str(x) for x in (target.get("productTypes") or [])]:
                            raise RuntimeError(f"Existing holding network '{target.get('name')}' has incompatible product types for {serial}.")
                        if not target:
                            payload={
                                "name":planned["networkName"],
                                "productTypes":[planned["productType"]],
                                "timeZone":"America/New_York",
                                "tags":[],
                                "notes":"Created by Meraki MSP Toolkit for Hardware Holding.",
                            }
                            target=api.post(f"/organizations/{urllib.parse.quote(holding_id)}/networks",payload)
                            if not target or not target.get("id"):
                                raise RuntimeError(f"Could not create holding network '{planned['networkName']}' for {serial}.")
                            holding_nets.append(target)
                            action_log.append(f"Created holding network: {target.get('name')} [{target.get('id')}]")
                    target_by_serial[serial]=target

                set_status("Returning hardware to Hardware Holding...")
                for d in live_devices:
                    serial=str(d.get("serial") or "").strip().upper()
                    api.post(f"/networks/{urllib.parse.quote(net_id)}/devices/remove",{"serial":serial})
                    action_log.append(f"Removed {serial} from customer network {net_id}")

                remaining=self._delete_wait_for_network_empty(api,net_id)
                if remaining:
                    raise RuntimeError(f"Hardware disposition stopped: {len(remaining)} device(s) still appear assigned to the source network.")

                api.post(f"/organizations/{urllib.parse.quote(org_id)}/inventory/release",{"serials":preview_serials})
                action_log.append(f"Released {len(preview_serials)} device(s) from customer organization inventory")
                api.post(f"/organizations/{urllib.parse.quote(holding_id)}/inventory/claim",{"serials":preview_serials})
                action_log.append(f"Claimed {len(preview_serials)} device(s) into Hardware Holding inventory")

                for serial in preview_serials:
                    target=target_by_serial[serial]
                    api.post(f"/networks/{urllib.parse.quote(str(target['id']))}/devices/claim",{"serials":[serial]})
                    action_log.append(f"Assigned {serial} to {target.get('name')} [{target.get('id')}]")

                def holding_ok(inv):
                    m=self._inventory_by_serial(inv)
                    return all(
                        norm_serial(serial) in m and str(m[norm_serial(serial)].get("networkId") or "")==str(target_by_serial[serial].get("id"))
                        for serial in preview_serials
                    )
                holding_inv=self._delete_wait_inventory(api,holding_id,holding_ok)
                if not holding_ok(holding_inv):
                    raise RuntimeError("Hardware was transferred toward Hardware Holding, but final holding inventory/network verification did not pass. Network deletion was NOT attempted.")
                source_inv=api.get_all(f"/organizations/{urllib.parse.quote(org_id)}/inventory/devices")
                source_map=self._inventory_by_serial(source_inv if isinstance(source_inv,list) else [])
                still_source=[s for s in preview_serials if norm_serial(s) in source_map]
                if still_source:
                    raise RuntimeError(f"Holding verification failed: serial(s) still appear in the customer inventory: {', '.join(still_source)}. Network deletion was NOT attempted.")

            elif live_devices and disposition=="keep":
                set_status("Removing hardware from network; keeping customer ownership...")
                for d in live_devices:
                    serial=str(d.get("serial") or "").strip().upper()
                    api.post(f"/networks/{urllib.parse.quote(net_id)}/devices/remove",{"serial":serial})
                    action_log.append(f"Removed {serial} from network; retained in customer organization inventory")
                remaining=self._delete_wait_for_network_empty(api,net_id)
                if remaining:
                    raise RuntimeError(f"Hardware disposition stopped: {len(remaining)} device(s) still appear assigned to the source network.")
                def keep_ok(inv):
                    m=self._inventory_by_serial(inv)
                    return all(norm_serial(s) in m and not m[norm_serial(s)].get("networkId") for s in preview_serials)
                inv=self._delete_wait_inventory(api,org_id,keep_ok)
                if not keep_ok(inv):
                    raise RuntimeError("Customer-inventory verification failed: one or more devices are not present as unassigned inventory. Network deletion was NOT attempted.")

            elif live_devices and disposition=="unclaim":
                set_status("Removing and unclaiming customer hardware...")
                for d in live_devices:
                    serial=str(d.get("serial") or "").strip().upper()
                    api.post(f"/networks/{urllib.parse.quote(net_id)}/devices/remove",{"serial":serial})
                    action_log.append(f"Removed {serial} from network")
                remaining=self._delete_wait_for_network_empty(api,net_id)
                if remaining:
                    raise RuntimeError(f"Hardware disposition stopped: {len(remaining)} device(s) still appear assigned to the source network.")
                api.post(f"/organizations/{urllib.parse.quote(org_id)}/inventory/release",{"serials":preview_serials})
                action_log.append(f"Released {len(preview_serials)} device(s) from customer organization inventory")
                def unclaim_ok(inv):
                    m=self._inventory_by_serial(inv)
                    return all(norm_serial(s) not in m for s in preview_serials)
                inv=self._delete_wait_inventory(api,org_id,unclaim_ok)
                if not unclaim_ok(inv):
                    raise RuntimeError("Unclaim verification failed: one or more serials still appear in the customer organization inventory. Network deletion was NOT attempted.")

            # Final empty-network gate after disposition.
            set_status("Verifying network is empty...")
            remaining=self._delete_wait_for_network_empty(api,net_id)
            if remaining:
                raise RuntimeError(f"Deletion blocked: {len(remaining)} device(s) are still assigned after hardware disposition.")

            endpoint=f"/networks/{urllib.parse.quote(net_id)}"
            self._emit("log",f"NETWORK DELETE REQUEST: DELETE {endpoint} | org={preview['orgName']} [{org_id}] | network={preview['networkName']} [{net_id}] | disposition={disposition}")
            set_status("Deleting exact network ID...")
            api.delete(endpoint)

            set_status("Verifying deletion...")
            verify_nets=api.get_all(f"/organizations/{urllib.parse.quote(org_id)}/networks")
            still_there=next((n for n in verify_nets if str(n.get("id"))==net_id),None)
            if still_there:
                raise RuntimeError(
                    f"Meraki accepted the DELETE request but network ID {net_id} still appears in the organization. "
                    "Hardware disposition may already be complete; no success will be reported. Refresh Dashboard and investigate."
                )

            result_dir=REPORTS/"NetworkDeletion"
            result_dir.mkdir(parents=True,exist_ok=True)
            result_path=result_dir/f"Network-Delete-Verified_{safe_filename(preview['orgName'])}_{safe_filename(preview['networkName'])}_{nowstamp()}.txt"
            disp_text={"holding":"Returned to Hardware Holding","keep":"Kept in customer organization inventory","unclaim":"Unclaimed from customer organization"}[disposition]
            result_lines=[
                "MERAKI NETWORK DELETE VERIFIED",
                "="*72,
                f"Organization : {preview['orgName']} [{org_id}]",
                f"Network      : {preview['networkName']} [{net_id}]",
                f"Disposition  : {disp_text}",
                f"Devices      : {len(preview_serials)}",
            ]
            for d in preview_devices:
                result_lines.append(f"- {d.get('model','')} {d.get('serial','')} {d.get('name','') or ''}".rstrip())
            result_lines.extend([
                "",
                "VERIFICATION",
                "------------",
                "Hardware disposition : PASS",
                "Source network empty : PASS",
                f"Network deletion     : PASS - exact network ID {net_id} absent after DELETE",
                "Administrators        : NOT READ / NOT MODIFIED",
            ])
            if action_log:
                result_lines.extend(["","ACTIONS PERFORMED","-----------------"]+action_log)
            result_text="\n".join(result_lines)+"\n"
            result_path.write_text(result_text,encoding="utf-8")

            def done():
                self.last_delete_preview=None
                self.last_delete_signature=None
                self.delete_apply_button.configure(state="disabled",text="DELETE Network")
                self.delete_disposition_combo.configure(state="readonly")
                self.delete_text.delete("1.0","end")
                self.delete_text.insert("end",result_text)
                self.delete_status_var.set(f"VERIFIED DELETED · {preview['networkName']}")
                self.write_log(
                    f"VERIFIED network deletion: {preview['orgName']} / {preview['networkName']} [{net_id}] · disposition={disposition} · result: {result_path}"
                )
                self.on_org_change()
            self._emit("call",done)

        def finished(error):
            self.delete_apply_button.configure(text="DELETE Network")
            self.delete_preview_button.configure(state="normal")
            self.delete_disposition_combo.configure(state="readonly")
            if error is not None:
                self.delete_apply_button.configure(state="disabled")
                self.last_delete_preview=None
                self.last_delete_signature=None
                self.delete_status_var.set("Delete NOT verified · preview again before retry")
        self.worker(work,finished)

    # ---------------- Admin Access ----------------
    def _admin_identity_refresh(self):
        if not hasattr(self,"admin_identity_var"): return
        email=str((self.current_identity or {}).get("email") or "").strip()
        self.admin_identity_var.set(f"Authenticated identity: {email or 'unknown'}")

    def _admin_reset(self, clear_text=False):
        self.last_admin_plan=None
        if hasattr(self,"admin_apply_button"): self.admin_apply_button.configure(state="disabled",text="APPLY + VERIFY")
        if hasattr(self,"admin_status_var"): self.admin_status_var.set("Dry run required")
        if hasattr(self,"admin_plan_tree"):
            for i in self.admin_plan_tree.get_children(): self.admin_plan_tree.delete(i)
        if clear_text and hasattr(self,"admin_text"):
            self.admin_text.delete("1.0","end")

    def _admin_refresh_network_tree(self, nets=None):
        if not hasattr(self,"admin_network_tree"): return
        for i in self.admin_network_tree.get_children(): self.admin_network_tree.delete(i)
        for n in (self.networks if nets is None else nets):
            nid=str(n.get("id") or "")
            if nid: self.admin_network_tree.insert("","end",iid=nid,values=(n.get("name") or "",nid))
        self._admin_form_changed()

    def _admin_select_all_networks(self):
        ids=self.admin_network_tree.get_children()
        if ids: self.admin_network_tree.selection_set(ids)
        self._admin_form_changed()

    def _admin_workflow_changed(self):
        if not hasattr(self,"admin_workflow_var"): return
        mode=self.admin_workflow_var.get()
        if mode=="Employee Offboarding - All Organizations":
            self.admin_scope_var.set("All Accessible Organizations")
            self.admin_scope_combo.configure(state="disabled")
            self.admin_name_entry.configure(state="disabled")
            self.admin_access_combo.configure(state="disabled")
            self.admin_grant_combo.configure(state="disabled")
        elif mode=="Remove Admin":
            self.admin_scope_combo.configure(state="readonly")
            self.admin_name_entry.configure(state="disabled")
            self.admin_access_combo.configure(state="disabled")
            self.admin_grant_combo.configure(state="disabled")
        else:
            self.admin_scope_combo.configure(state="readonly")
            self.admin_name_entry.configure(state="normal")
            self.admin_access_combo.configure(state="readonly")
            self.admin_grant_combo.configure(state="readonly")
        self._admin_scope_changed()

    def _admin_scope_changed(self):
        if not hasattr(self,"admin_scope_var"): return
        all_orgs=self.admin_scope_var.get()=="All Accessible Organizations"
        add=self.admin_workflow_var.get()=="Add / Change Admin"
        if add and all_orgs and self.admin_grant_var.get()=="Selected Networks":
            self.admin_grant_var.set("Organization-wide")
        network_enabled=add and not all_orgs and self.admin_grant_var.get()=="Selected Networks"
        state="normal" if network_enabled else "disabled"
        self.admin_network_tree.configure(selectmode="extended")
        self.admin_select_all_button.configure(state=state); self.admin_clear_networks_button.configure(state=state)
        self._admin_form_changed()

    def _admin_form_changed(self):
        if not hasattr(self,"admin_apply_button"): return
        self.last_admin_plan=None
        self.admin_apply_button.configure(state="disabled",text="APPLY + VERIFY")
        self.admin_status_var.set("Dry run required")
        if hasattr(self,"admin_workflow_var"):
            all_orgs=self.admin_scope_var.get()=="All Accessible Organizations"
            add=self.admin_workflow_var.get()=="Add / Change Admin"
            selected_grant=add and self.admin_grant_var.get()=="Selected Networks"
            state="normal" if selected_grant and not all_orgs else "disabled"
            self.admin_select_all_button.configure(state=state); self.admin_clear_networks_button.configure(state=state)

    @staticmethod
    def _admin_access_text(admin):
        if not admin: return "Not present"
        oa=str(admin.get("orgAccess") or "none")
        if oa!="none": return oa
        nets=admin.get("networks") or []
        tags=admin.get("tags") or []
        parts=[]
        if nets: parts.append(f"{len(nets)} network grant(s)")
        if tags: parts.append(f"{len(tags)} tag grant(s)")
        return ", ".join(parts) if parts else "none"

    def _admin_target_orgs(self):
        if self.admin_scope_var.get()=="All Accessible Organizations": return list(self.orgs)
        return [self.selected_org()]

    def _admin_signature(self):
        return {
            "workflow":self.admin_workflow_var.get(),"scope":self.admin_scope_var.get(),
            "email":self.admin_email_var.get().strip().lower(),"name":self.admin_name_var.get().strip(),
            "access":self.admin_access_var.get(),"grant":self.admin_grant_var.get(),
            "networks":sorted(self.admin_network_tree.selection()) if self.admin_grant_var.get()=="Selected Networks" else [],
        }

    def admin_access_dry_run(self):
        if self.public_var.get():
            messagebox.showwarning("Admin Access","Turn off Public display before preparing administrator changes."); return
        email=self.admin_email_var.get().strip().lower()
        if not email or "@" not in email:
            messagebox.showwarning("Admin Access","Enter the administrator email address."); return
        mode=self.admin_workflow_var.get(); add=mode=="Add / Change Admin"
        if add and not self.admin_name_var.get().strip():
            messagebox.showwarning("Admin Access","Enter the administrator name."); return
        if add and self.admin_scope_var.get()=="All Accessible Organizations" and self.admin_grant_var.get()=="Selected Networks":
            messagebox.showwarning("Admin Access","Selected Networks is available only for one selected organization."); return
        selected_networks=[]
        if add and self.admin_grant_var.get()=="Selected Networks":
            ids=list(self.admin_network_tree.selection())
            if not ids:
                messagebox.showwarning("Admin Access","Select at least one network."); return
            byid={str(n.get("id")):n for n in self.networks}
            selected_networks=[byid[i] for i in ids if i in byid]
            if len(selected_networks)!=len(ids):
                messagebox.showwarning("Admin Access","Network selection changed. Refresh the organization and try again."); return
        try: orgs=self._admin_target_orgs()
        except Exception as exc: messagebox.showerror("Admin Access",str(exc)); return
        if not orgs:
            messagebox.showwarning("Admin Access","No organizations are in scope."); return
        self._admin_reset(clear_text=True); self.admin_dry_button.configure(state="disabled",text="Scanning..."); self.admin_status_var.set("Reading administrator access...")
        signature=self._admin_signature()
        def work():
            api=self.require_api()
            try: ident=api.get("/administered/identities/me") or {}
            except Exception: ident=self.current_identity or {}
            ident_email=str(ident.get("email") or "").strip().lower()
            if not add and not ident_email:
                raise RuntimeError("Authenticated Meraki identity could not be verified. Administrator removal is blocked to prevent removing the API-key owner by accident.")
            items=[]; errors=[]; found=0
            for idx,org in enumerate(orgs,1):
                oid=str(org.get("id")); oname=str(org.get("name") or oid)
                self._emit("call",lambda i=idx,t=len(orgs),n=oname:self.admin_status_var.set(f"Scanning {i}/{t}: {n}"))
                try: admins=api.get(f"/organizations/{urllib.parse.quote(oid)}/admins")
                except Exception as exc:
                    errors.append(f"{oname}: {exc}"); items.append({"orgId":oid,"orgName":oname,"action":"blocked","current":"API read failed","planned":"none","status":f"BLOCKED - {exc}"}); continue
                admins=admins if isinstance(admins,list) else []
                current=next((a for a in admins if str(a.get("email") or "").strip().lower()==email),None)
                if add:
                    name=signature["name"]; access="full" if signature["access"]=="Full" else "read-only"
                    payload={"name":name}
                    if signature["grant"]=="Selected Networks":
                        payload.update({"orgAccess":"none","tags":[],"networks":[{"id":str(n.get("id")),"access":access} for n in selected_networks]})
                        planned=f"{access} on {len(selected_networks)} selected network(s)"
                    else:
                        payload.update({"orgAccess":access}); planned=f"{access} organization-wide"
                    if current:
                        action="update"; payload["adminId"]=str(current.get("id") or "")
                        cur=self._admin_access_text(current)
                        same_name=str(current.get("name") or "")==name
                        if signature["grant"]=="Selected Networks":
                            exp=sorted((str(x["id"]),x["access"]) for x in payload["networks"])
                            got=sorted((str(x.get("id")),str(x.get("access"))) for x in (current.get("networks") or []))
                            same= current.get("orgAccess")=="none" and not (current.get("tags") or []) and got==exp and same_name
                        else: same=current.get("orgAccess")==access and same_name
                        if same: action="noop"
                    else:
                        action="create"; payload["email"]=email; cur="Not present"
                    target_org_access=str(payload.get("orgAccess") or "none")
                    full_count=sum(1 for a in admins if a.get("orgAccess")=="full")
                    resulting_full=full_count-(1 if current and current.get("orgAccess")=="full" else 0)+(1 if target_org_access=="full" else 0)
                    blocker=""
                    if action!="noop" and resulting_full<1:
                        blocker="Would leave the organization without a full-access administrator"
                        action="blocked"
                    items.append({"orgId":oid,"orgName":oname,"action":action,"current":cur,"planned":planned,"status":f"BLOCKED - {blocker}" if blocker else ("NO CHANGE" if action=="noop" else "READY"),"payload":payload,"adminId":str(current.get("id") or "") if current else ""})
                else:
                    if not current: continue
                    found+=1; cur=self._admin_access_text(current); blocker=""
                    if email==ident_email: blocker="Authenticated API-key owner"
                    full_count=sum(1 for a in admins if a.get("orgAccess")=="full")
                    if not blocker and current.get("orgAccess")=="full" and full_count<=1: blocker="Would remove the organization's last full-access admin"
                    if not blocker and len(admins)<=1: blocker="Would leave the organization with no dashboard administrator"
                    items.append({"orgId":oid,"orgName":oname,"action":"blocked" if blocker else "remove","current":cur,"planned":"Remove administrator","status":f"BLOCKED - {blocker}" if blocker else "READY","adminId":str(current.get("id") or ""),"adminName":current.get("name") or ""})
            blockers=[i for i in items if i.get("action")=="blocked"]
            executable=[i for i in items if i.get("action") in ("create","update","remove")]
            lines=["MERAKI ADMIN ACCESS PLAN","="*72,"DRY RUN - NO ADMINISTRATOR ACCESS WILL BE CHANGED","",f"Workflow : {mode}",f"Email    : {email}",f"Scope    : {signature['scope']}",f"Organizations scanned : {len(orgs)}"]
            if not add: lines.append(f"Organizations where admin was found : {found}")
            lines += ["","PLAN","----"]
            if not items: lines.append("No matching administrator was found in scope.")
            for i in items: lines.append(f"- {i['orgName']}: {i['current']} -> {i['planned']} [{i['status']}]")
            lines += ["","SAFETY","------","- This workflow changes Dashboard administrator access only. It NEVER deletes Meraki networks or hardware.","- Every organization is re-read immediately before a write and again afterward for verification."]
            if not add: lines += [f"- Authenticated identity: {ident_email or 'UNKNOWN'}","- Removal is blocked if it targets the authenticated API-key owner.","- Removal is blocked if it would leave an organization without a full-access administrator."]
            if blockers: lines += ["",f"APPLY BLOCKED: {len(blockers)} preflight blocker(s) must be resolved before any administrator removal/change is attempted."]
            elif not executable: lines += ["","NO WRITES REQUIRED."]
            else:
                confirm="REMOVE ADMIN ALL" if mode=="Employee Offboarding - All Organizations" or (mode=="Remove Admin" and signature["scope"]=="All Accessible Organizations") else ("REMOVE ADMIN" if not add else ("CHANGE ADMIN" if any(i.get('action')=='update' for i in executable) else "ADD ADMIN"))
                lines += ["",f"Typed confirmation required: {confirm}"]
            plan={"signature":signature,"workflow":mode,"email":email,"scope":signature["scope"],"items":items,"blockers":len(blockers),"executable":len(executable),"identityEmail":ident_email,"confirmation":None if blockers or not executable else confirm}
            folder=REPORTS/"AdminAccess"; folder.mkdir(parents=True,exist_ok=True); stem=f"Admin-Access-Plan_{safe_filename(email)}_{nowstamp()}"; txt=folder/f"{stem}.txt"; js=folder/f"{stem}.json"; txt.write_text("\n".join(lines)+"\n",encoding="utf-8"); js.write_text(json.dumps(plan,indent=2),encoding="utf-8")
            def done():
                self.current_identity=ident if isinstance(ident,dict) else self.current_identity; self._admin_identity_refresh(); self.last_admin_plan=plan
                self.admin_text.delete("1.0","end"); self.admin_text.insert("end","\n".join(lines))
                for x in self.admin_plan_tree.get_children(): self.admin_plan_tree.delete(x)
                for n,i in enumerate(items): self.admin_plan_tree.insert("","end",iid=f"p{n}",values=(i['orgName'],i['current'],i['planned'],i['status']))
                self.admin_apply_button.configure(state="normal" if plan.get("confirmation") else "disabled")
                self.admin_status_var.set((f"Plan ready · {len(executable)} write(s)" if plan.get("confirmation") else (f"BLOCKED · {len(blockers)} issue(s)" if blockers else "No writes required")))
                self.write_log(f"Admin Access dry run: {email} · scanned {len(orgs)} org(s) · writes {len(executable)} · blockers {len(blockers)} · {txt}")
            self._emit("call",done)
        def finished(error):
            self.admin_dry_button.configure(state="normal",text="Dry Run")
            if error is not None: self.admin_status_var.set("Dry run failed")
        self.worker(work,finished)

    def admin_access_apply(self):
        plan=dict(self.last_admin_plan or {})
        if not plan or not plan.get("confirmation"):
            messagebox.showwarning("Admin Access","Run a successful Dry Run first."); return
        if plan.get("signature")!=self._admin_signature():
            messagebox.showwarning("Admin Access","The workflow, scope, email, name, access, or selected networks changed after Dry Run. Run Dry Run again."); self._admin_reset(); return
        expected=plan["confirmation"]
        confirm=simpledialog.askstring("Admin Access",f"Email: {plan['email']}\nWorkflow: {plan['workflow']}\nWrites: {plan['executable']}\n\nType exactly: {expected}")
        if confirm!=expected: self.admin_status_var.set("Cancelled"); return
        self.admin_apply_button.configure(state="disabled",text="Applying..."); self.admin_dry_button.configure(state="disabled"); self.admin_status_var.set("Re-verifying before write...")
        def work():
            api=self.require_api(); email=plan["email"]; identity_email=str((api.get("/administered/identities/me") or {}).get("email") or "").strip().lower()
            if plan["workflow"]!="Add / Change Admin" and (not identity_email or identity_email==email): raise RuntimeError("Removal blocked: authenticated API-key identity cannot be safely distinguished from the target administrator.")
            results=[]
            for idx,item in enumerate([x for x in plan["items"] if x.get("action") in ("create","update","remove")],1):
                oid=item["orgId"]; oname=item["orgName"]
                self._emit("call",lambda i=idx,t=plan['executable'],n=oname:self.admin_status_var.set(f"Applying {i}/{t}: {n}"))
                try:
                    admins=api.get(f"/organizations/{urllib.parse.quote(oid)}/admins"); admins=admins if isinstance(admins,list) else []
                    current=next((a for a in admins if str(a.get("email") or "").strip().lower()==email),None)
                    action=item["action"]
                    if action=="create":
                        if current: raise RuntimeError("Administrator appeared after Dry Run; no write made.")
                        payload=dict(item["payload"]); payload.pop("adminId",None); api.post(f"/organizations/{urllib.parse.quote(oid)}/admins",payload)
                    elif action=="update":
                        if not current or str(current.get("id") or "")!=item.get("adminId"): raise RuntimeError("Administrator membership changed after Dry Run; no write made.")
                        payload=dict(item["payload"]); aid=payload.pop("adminId",None); payload.pop("email",None)
                        full_count=sum(1 for a in admins if a.get("orgAccess")=="full")
                        resulting_full=full_count-(1 if current.get("orgAccess")=="full" else 0)+(1 if payload.get("orgAccess")=="full" else 0)
                        if resulting_full<1: raise RuntimeError("Access change would leave the organization without a full-access administrator.")
                        api.put(f"/organizations/{urllib.parse.quote(oid)}/admins/{urllib.parse.quote(str(aid))}",payload)
                    else:
                        if not current or str(current.get("id") or "")!=item.get("adminId"): raise RuntimeError("Administrator membership changed after Dry Run; no write made.")
                        full_count=sum(1 for a in admins if a.get("orgAccess")=="full")
                        if current.get("orgAccess")=="full" and full_count<=1: raise RuntimeError("Removal would eliminate the last full-access administrator.")
                        if len(admins)<=1: raise RuntimeError("Removal would leave the organization with no dashboard administrator.")
                        api.delete(f"/organizations/{urllib.parse.quote(oid)}/admins/{urllib.parse.quote(str(current.get('id')))}")
                    verify=api.get(f"/organizations/{urllib.parse.quote(oid)}/admins"); verify=verify if isinstance(verify,list) else []
                    after=next((a for a in verify if str(a.get("email") or "").strip().lower()==email),None)
                    if action=="remove": ok=after is None
                    else:
                        p=item["payload"]; ok=after is not None and str(after.get("name") or "")==str(p.get("name") or "") and str(after.get("orgAccess") or "")==str(p.get("orgAccess") or "")
                        if ok and p.get("orgAccess")=="none":
                            exp=sorted((str(x.get("id")),str(x.get("access"))) for x in p.get("networks",[])); got=sorted((str(x.get("id")),str(x.get("access"))) for x in (after.get("networks") or [])); ok=exp==got and not (after.get("tags") or [])
                    results.append({"orgName":oname,"ok":ok,"detail":"Verified" if ok else "Read-back did not match planned state"})
                except Exception as exc: results.append({"orgName":oname,"ok":False,"detail":str(exc)})
            passes=sum(1 for r in results if r['ok']); fails=len(results)-passes
            lines=["MERAKI ADMIN ACCESS APPLY + VERIFY RESULT","="*72,f"Workflow : {plan['workflow']}",f"Email    : {email}","",f"PASS : {passes}",f"FAIL : {fails}","","VERIFICATION","------------"]+[f"{'PASS' if r['ok'] else 'FAIL'} - {r['orgName']}: {r['detail']}" for r in results]
            folder=REPORTS/"AdminAccess"; folder.mkdir(parents=True,exist_ok=True); path=folder/f"Admin-Access-Result_{safe_filename(email)}_{nowstamp()}.txt"; path.write_text("\n".join(lines)+"\n",encoding="utf-8")
            def done():
                self.admin_text.delete("1.0","end"); self.admin_text.insert("end","\n".join(lines))
                for x in self.admin_plan_tree.get_children(): self.admin_plan_tree.delete(x)
                for n,r in enumerate(results): self.admin_plan_tree.insert("","end",iid=f"r{n}",values=(r['orgName'],"","",("PASS - " if r['ok'] else "FAIL - ")+r['detail']))
                self.last_admin_plan=None; self.admin_apply_button.configure(state="disabled",text="APPLY + VERIFY"); self.admin_status_var.set(f"Verified · PASS {passes} / FAIL {fails}"); self.write_log(f"Admin Access complete: {email} · PASS {passes} FAIL {fails} · {path}")
            self._emit("call",done)
        def finished(error):
            self.admin_dry_button.configure(state="normal"); self.admin_apply_button.configure(text="APPLY + VERIFY")
            if error is not None: self.admin_status_var.set("Apply failed · Dry Run required"); self.last_admin_plan=None; self.admin_apply_button.configure(state="disabled")
        self.worker(work,finished)

    # ---------------- Hardware / Inventory ----------------
    def _holding_target_changed(self):
        if hasattr(self,"last_new_claim_preview"):
            self.last_new_claim_preview=None
        if hasattr(self,"last_holding_preview_signature"):
            self.last_holding_preview_signature=None
        if hasattr(self,"last_offboarding_preview"):
            self.last_offboarding_preview=None
        if hasattr(self,"hold_direction") and self.hold_direction.get()=="Claim New Hardware" and hasattr(self,"hold_status_var"):
            self.hold_status_var.set("Target changed · dry run required")

    def _holding_set_tree_mode(self, claiming=False, offboarding=False):
        if not hasattr(self,"hold_tree"):
            return
        if offboarding:
            headings={"serial":"Serial","model":"Model","name":"Product","network":"Current Network"}
            widths={"serial":165,"model":115,"name":120,"network":535}
        elif claiming:
            headings={"serial":"Serial","model":"Model","name":"Product","network":"Preflight / Result"}
            widths={"serial":165,"model":115,"name":120,"network":535}
        else:
            headings={"serial":"Serial","model":"Model","name":"Name","network":"Network"}
            widths={"serial":165,"model":115,"name":220,"network":430}
        for col in ("serial","model","name","network"):
            self.hold_tree.heading(col,text=headings[col])
            self.hold_tree.column(col,width=widths[col],anchor="w")

    def _holding_direction_changed(self):
        mode=self.hold_direction.get()
        returning=mode=="Return to Holding"
        claiming=mode=="Claim New Hardware"
        offboarding=mode=="Client Offboarding - Unclaim"
        self.last_new_claim_preview=None
        self.last_holding_preview_signature=None
        self.last_offboarding_preview=None

        # Restore target-network control before applying mode-specific state.
        try:
            self.hold_net_combo.configure(state="readonly")
        except Exception:
            pass

        if returning:
            self.hold_direction_help_var.set("Source: selected organization/network → destination: Hardware Holding")
            self.hold_net_label_var.set("Holding network")
            self.hold_list_button.configure(text="List Source Inventory")
            self.hold_move_button.configure(text="RETURN Hardware")
        elif claiming:
            self.hold_direction_help_var.set("Source: brand-new/unclaimed serial(s) → selected organization/network")
            self.hold_net_label_var.set("Target network")
            self.hold_list_button.configure(text="List Destination Inventory")
            self.hold_move_button.configure(text="CLAIM + VERIFY")
        elif offboarding:
            self.hold_direction_help_var.set("Client offboarding: selected organization inventory → unclaimed from Meraki ownership")
            self.hold_net_label_var.set("Scope")
            self.hold_net_combo.configure(state="disabled")
            self.hold_net.set("Entire selected organization · all networks + unassigned")
            self.hold_list_button.configure(text="Inventory Client Hardware")
            self.hold_move_button.configure(text="UNCLAIM + VERIFY")
        else:
            self.hold_direction_help_var.set("Source: Hardware Holding → destination: selected organization/network")
            self.hold_net_label_var.set("Target network")
            self.hold_list_button.configure(text="List Holding Inventory")
            self.hold_move_button.configure(text="MOVE Hardware")

        self.hold_serial.set("")
        if hasattr(self,"hold_claim_text"):
            self.hold_claim_text.delete("1.0","end")

        if claiming:
            if self.hold_single_serial_frame.winfo_manager():
                self.hold_single_serial_frame.pack_forget()
            if not self.hold_claim_serial_frame.winfo_manager():
                self.hold_claim_serial_frame.pack(fill="x",padx=18,pady=(6,2),before=self.hold_net_combo.master)
        elif offboarding:
            if self.hold_claim_serial_frame.winfo_manager():
                self.hold_claim_serial_frame.pack_forget()
            if self.hold_single_serial_frame.winfo_manager():
                self.hold_single_serial_frame.pack_forget()
        else:
            if self.hold_claim_serial_frame.winfo_manager():
                self.hold_claim_serial_frame.pack_forget()
            if not self.hold_single_serial_frame.winfo_manager():
                self.hold_single_serial_frame.pack(fill="x",padx=18,pady=(6,2),before=self.hold_net_combo.master)

        # Offboarding uses multi-selection with explicit Select All / Clear Selection controls.
        if offboarding:
            if not self.offboard_select_all_button.winfo_manager():
                self.offboard_select_all_button.pack(side="left",padx=(8,0))
            if not self.offboard_clear_selection_button.winfo_manager():
                self.offboard_clear_selection_button.pack(side="left",padx=(8,0))
        else:
            if self.offboard_select_all_button.winfo_manager():
                self.offboard_select_all_button.pack_forget()
            if self.offboard_clear_selection_button.winfo_manager():
                self.offboard_clear_selection_button.pack_forget()

        self._holding_set_tree_mode(claiming=claiming,offboarding=offboarding)
        if offboarding:
            self.hold_status_var.set("Inventory client hardware · select devices · dry run required")
        else:
            self.hold_status_var.set("Ready" if not claiming else "Paste serials · dry run required")
        if hasattr(self,"hold_tree"):
            for item in self.hold_tree.get_children():
                self.hold_tree.delete(item)
        self._refresh_holding_controls()

    def _refresh_holding_controls(self):
        if not hasattr(self,"hold_net_combo"):
            return
        mode=getattr(self,"hold_direction",tk.StringVar(value="Move from Holding")).get()
        returning=mode=="Return to Holding"
        offboarding=mode=="Client Offboarding - Unclaim"
        if offboarding:
            self.hold_net_combo["values"]=["Entire selected organization · all networks + unassigned"]
            self.hold_net.set("Entire selected organization · all networks + unassigned")
            try:
                self.hold_net_combo.configure(state="disabled")
            except Exception:
                pass
            return
        try:
            self.hold_net_combo.configure(state="readonly")
        except Exception:
            pass
        if returning:
            vals=[self._net_label(n) for n in self.holding_networks]
        else:
            vals=[self._net_label(n) for n in self.networks]
        self.hold_net_combo["values"]=vals
        current=self.hold_net.get()
        if current not in vals:
            self.hold_net.set(vals[0] if vals else "")

    def _holding_net_from_label(self,label):
        return next((n for n in self.holding_networks if self._net_label(n)==label),None)

    def _suggest_holding_network(self,model,serial):
        if self.hold_direction.get()!="Return to Holding" or not self.holding_networks:
            return
        model=(model or "").strip().casefold()
        serial=(serial or "").strip().casefold()
        scored=[]
        for net in self.holding_networks:
            name=(net.get("name") or "").casefold()
            score=0
            if serial and serial in name:
                score+=100
            if model and model in name:
                score+=60
            if model.startswith("ms") and "switch" in name:
                score+=30
            if model.startswith("mr") and any(x in name for x in ("wireless","ap","access point")):
                score+=30
            if (model.startswith("mx") or model.startswith("z")) and any(x in name for x in ("appliance","teleworker",model)):
                score+=25
            if model.startswith("mv") and "camera" in name:
                score+=30
            if model.startswith("mt") and "sensor" in name:
                score+=30
            if score:
                scored.append((score,net))
        if scored:
            scored.sort(key=lambda x:x[0],reverse=True)
            self.hold_net.set(self._net_label(scored[0][1]))

    def _offboarding_selected_serials(self):
        if not hasattr(self,"hold_tree"):
            return []
        serials=[]; seen=set()
        for iid in self.hold_tree.selection():
            vals=self.hold_tree.item(iid,"values")
            if not vals:
                continue
            serial=str(vals[0] or "").strip().upper()
            key=norm_serial(serial)
            if key and key not in seen:
                seen.add(key); serials.append(serial)
        return serials

    def _offboarding_selection_changed(self):
        self.last_offboarding_preview=None
        serials=self._offboarding_selected_serials()
        total=len(self.hold_tree.get_children()) if hasattr(self,"hold_tree") else 0
        if hasattr(self,"hold_status_var"):
            self.hold_status_var.set(f"Selected {len(serials)} of {total} device(s) · dry run required")

    def _offboarding_select_all(self):
        if self.hold_direction.get()!="Client Offboarding - Unclaim":
            return
        items=self.hold_tree.get_children()
        if items:
            self.hold_tree.selection_set(items)
        self._offboarding_selection_changed()

    def _offboarding_clear_selection(self):
        if hasattr(self,"hold_tree"):
            self.hold_tree.selection_remove(self.hold_tree.selection())
        self._offboarding_selection_changed()

    def _holding_pick(self,event=None):
        mode=self.hold_direction.get()
        if mode=="Claim New Hardware":
            return
        if mode=="Client Offboarding - Unclaim":
            self._offboarding_selection_changed()
            return
        sel=self.hold_tree.selection()
        if sel:
            vals=self.hold_tree.item(sel[0],"values")
            if vals:
                self.hold_serial.set(vals[0])
                if mode=="Return to Holding":
                    self._suggest_holding_network(vals[1] if len(vals)>1 else "", vals[0])

    def holding_list(self):
        mode=self.hold_direction.get()
        claiming=mode=="Claim New Hardware"
        returning=mode=="Return to Holding"
        offboarding=mode=="Client Offboarding - Unclaim"
        if not claiming and not offboarding and not self.holding_org:
            messagebox.showerror("Hardware / Inventory","Hardware Holding was not found in this API session.")
            return
        if self.hold_list_button.instate(["disabled"]):
            return
        try:
            if claiming or offboarding:
                source_org=self.selected_org()
                if offboarding and self.holding_org and str(source_org.get("id"))==str(self.holding_org.get("id")):
                    raise RuntimeError("Client Offboarding cannot target Hardware Holding. Select the departing customer organization.")
            else:
                source_org=self.selected_org() if returning else self.holding_org
                if returning and source_org["id"]==self.holding_org["id"]:
                    raise RuntimeError("Select a customer/test organization, not Hardware Holding, before returning hardware.")
        except Exception as exc:
            messagebox.showerror("Hardware / Inventory",str(exc))
            return
        buttons=[self.hold_list_button,self.hold_dry_button,self.hold_move_button]
        if offboarding:
            buttons += [self.offboard_select_all_button,self.offboard_clear_selection_button]
        self._set_buttons(buttons,"disabled")
        self.hold_list_button.configure(text="Loading Inventory...")
        self.hold_status_var.set("Inventorying client hardware..." if offboarding else ("Loading destination inventory..." if claiming else "Loading source inventory..."))
        self.last_offboarding_preview=None
        for i in self.hold_tree.get_children():
            self.hold_tree.delete(i)

        def work():
            api=self.require_api(); oid=source_org["id"]
            inv=api.get_all(f"/organizations/{urllib.parse.quote(str(oid))}/inventory/devices")
            if claiming or returning or offboarding:
                nets=list(self.networks)
            else:
                nets=list(self.holding_networks)
                if not nets:
                    try:
                        nets=api.get_all(f"/organizations/{urllib.parse.quote(str(oid))}/networks")
                    except Exception:
                        nets=[]
            nmap={n.get("id"):n.get("name","") for n in nets}
            if claiming or offboarding:
                rows=[]
                for d in inv:
                    pt=self._delete_device_product_type(d) or "unknown"
                    rows.append((d.get("serial",""),d.get("model",""),pt,nmap.get(d.get("networkId"),"Unassigned")))
            else:
                rows=[(d.get("serial",""),d.get("model",""),d.get("name","") or "",nmap.get(d.get("networkId"),"Unassigned")) for d in inv]
            rows=sorted(rows,key=lambda r:(str(r[3]).lower(),str(r[1]).lower(),str(r[0]).lower()))
            def done():
                if not claiming and not returning and not offboarding and nets:
                    self.holding_networks=sorted(nets,key=lambda x:(x.get("name") or "").lower())
                    self._refresh_holding_controls()
                for r in rows:
                    self.hold_tree.insert("","end",values=r)
                if offboarding:
                    self.hold_status_var.set(f"Loaded {len(rows)} device(s) · select devices or Select All · dry run required")
                    self.write_log(f"Client offboarding inventory loaded: {len(rows)} device(s) in {source_org.get('name')}.")
                else:
                    label="destination" if claiming else ("source" if returning else "holding")
                    self.hold_status_var.set(f"Loaded · {len(rows)} device(s)")
                    self.write_log(f"{label.title()} inventory loaded: {len(rows)} device(s).")
            self._emit("call",done)

        def finished(error):
            if offboarding:
                list_text="Inventory Client Hardware"; move_text="UNCLAIM + VERIFY"
            elif claiming:
                list_text="List Destination Inventory"; move_text="CLAIM + VERIFY"
            elif returning:
                list_text="List Source Inventory"; move_text="RETURN Hardware"
            else:
                list_text="List Holding Inventory"; move_text="MOVE Hardware"
            self.hold_list_button.configure(text=list_text)
            self.hold_move_button.configure(text=move_text)
            self._finish_buttons(buttons,self.hold_status_var,error)
            if error is not None:
                self.hold_status_var.set("Inventory load failed")
        self.worker(work,finished)

    def _holding_plan(self):
        if not self.holding_org:
            raise RuntimeError("Hardware Holding was not found.")
        serial=self.hold_serial.get().strip().upper()
        if not serial:
            raise RuntimeError("Enter a serial number.")
        returning=self.hold_direction.get()=="Return to Holding"
        if returning:
            source_org=self.selected_org()
            if source_org["id"]==self.holding_org["id"]:
                raise RuntimeError("Select the organization currently holding the device, not Hardware Holding.")
            holding_net=self._holding_net_from_label(self.hold_net.get())
            if not holding_net:
                raise RuntimeError("Select a target network inside Hardware Holding.")
            return {
                "direction":"return",
                "serial":serial,
                "source_org":source_org,
                "target_org":self.holding_org,
                "target_net":holding_net,
            }
        target_org=self.selected_org()
        if target_org["id"]==self.holding_org["id"]:
            raise RuntimeError("Select a target organization other than Hardware Holding.")
        net=self.net_from_label(self.hold_net.get())
        if not net:
            raise RuntimeError("Select a target network.")
        return {
            "direction":"outbound",
            "serial":serial,
            "source_org":self.holding_org,
            "target_org":target_org,
            "target_net":net,
        }

    @staticmethod
    def _parse_new_claim_serials(raw):
        tokens=[t.strip().upper() for t in re.split(r"[\s,;]+",raw or "") if t.strip()]
        out=[]; seen=set(); bad=[]
        for token in tokens:
            token=token.strip("[](){}<>\"'")
            if not re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}",token):
                bad.append(token); continue
            key=norm_serial(token)
            if not key or key in seen:
                continue
            seen.add(key); out.append(token)
        if bad:
            raise RuntimeError("Invalid Meraki device serial token(s) (expected XXXX-XXXX-XXXX): " + ", ".join(bad[:8]) + ("..." if len(bad)>8 else ""))
        if not out:
            raise RuntimeError("Paste or scan at least one Meraki serial number.")
        if len(out)>100:
            raise RuntimeError("Claim New Hardware supports up to 100 serials per batch.")
        return out

    def _new_claim_plan(self):
        org=self.selected_org()
        net=self.net_from_label(self.hold_net.get())
        if not net:
            raise RuntimeError("Select the destination network.")
        serials=self._parse_new_claim_serials(self.hold_claim_text.get("1.0","end"))
        return {"target_org":org,"target_net":net,"serials":serials}

    @staticmethod
    def _new_claim_signature(plan):
        return json.dumps({
            "orgId":str(plan["target_org"].get("id")),
            "networkId":str(plan["target_net"].get("id")),
            "serials":[norm_serial(x) for x in plan["serials"]],
        },sort_keys=True,separators=(",",":"))

    @staticmethod
    def _inventory_by_serial(devices):
        return {norm_serial(str(d.get("serial") or "")):d for d in (devices or []) if d.get("serial")}

    @staticmethod
    def _claim_network_compatible(device, net):
        pt=Toolkit._delete_device_product_type(device)
        supported={str(x) for x in (net.get("productTypes") or [])}
        return pt, bool(pt and pt in supported)

    def _scan_claim_locations(self, api, serials, target_org):
        wanted={norm_serial(x) for x in serials}
        locations={}
        scan_errors=[]
        target_id=str(target_org.get("id"))
        target_inv=api.get_all(f"/organizations/{urllib.parse.quote(target_id)}/inventory/devices")
        for dev in target_inv:
            key=norm_serial(str(dev.get("serial") or ""))
            if key in wanted:
                locations[key]={"org":target_org,"device":dev,"target":True}
        remaining=wanted-set(locations)
        if remaining:
            for org in self.orgs:
                oid=str(org.get("id"))
                if oid==target_id:
                    continue
                try:
                    inv=api.get_all(f"/organizations/{urllib.parse.quote(oid)}/inventory/devices")
                except Exception as exc:
                    scan_errors.append(f"{org.get('name')}: {exc}")
                    continue
                for dev in inv:
                    key=norm_serial(str(dev.get("serial") or ""))
                    if key in remaining:
                        locations[key]={"org":org,"device":dev,"target":False}
                        remaining.discard(key)
                if not remaining:
                    break
        return target_inv, locations, scan_errors

    def _new_claim_preview(self):
        try:
            plan=self._new_claim_plan()
        except Exception as exc:
            messagebox.showerror("Claim New Hardware",str(exc)); return
        if self.hold_dry_button.instate(["disabled"]):
            return
        self.last_new_claim_preview=None
        self._set_buttons([self.hold_list_button,self.hold_dry_button,self.hold_move_button],"disabled")
        self.hold_status_var.set("Preflight scanning accessible inventories...")
        for i in self.hold_tree.get_children(): self.hold_tree.delete(i)
        target_org=plan["target_org"]; net=plan["target_net"]; serials=plan["serials"]
        signature=self._new_claim_signature(plan)

        def work():
            api=self.require_api()
            target_inv,locations,scan_errors=self._scan_claim_locations(api,serials,target_org)
            nmap={n.get("id"):n.get("name","") for n in self.networks}
            rows=[]; blocked=0; already=0; new_count=0; ready_existing=0
            for serial in serials:
                key=norm_serial(serial); loc=locations.get(key)
                model=""; product="unknown"; status=""
                if loc:
                    dev=loc["device"]; model=str(dev.get("model") or ""); product=self._delete_device_product_type(dev) or "unknown"
                    if not loc["target"]:
                        blocked+=1
                        status=f"BLOCKED - already claimed in {loc['org'].get('name')}"
                    else:
                        nid=dev.get("networkId")
                        if nid==net.get("id"):
                            already+=1; status="PASS - already assigned to this target network"
                        elif nid:
                            blocked+=1; status=f"BLOCKED - already assigned to {nmap.get(nid,nid)} in destination org"
                        else:
                            pt,ok=self._claim_network_compatible(dev,net)
                            if ok:
                                ready_existing+=1; status="READY - already in destination inventory; will assign to target network"
                            else:
                                blocked+=1; status=f"BLOCKED - product {pt or 'unknown'} is not supported by target network"
                else:
                    new_count+=1
                    status="NEW/UNSEEN - claim to destination org; product compatibility checked before network assignment"
                rows.append((serial,model,product,status))
            preview={
                "signature":signature,"serials":list(serials),"orgId":str(target_org.get("id")),
                "networkId":str(net.get("id")),"rows":rows,"scan_errors":scan_errors,
                "blocked":blocked,"already":already,"new":new_count,"ready_existing":ready_existing,
            }
            def done():
                self.last_new_claim_preview=preview
                for row in rows: self.hold_tree.insert("","end",values=row)
                self.hold_status_var.set(f"Dry run ready · {len(serials)} serial(s) · {blocked} preflight blocked")
                products=", ".join(net.get("productTypes") or []) or "(none)"
                site_full=format_site_address(site_address_from_notes(net.get("notes") or ""))
                site_text=(f"\nSite address: {site_full} (will auto-apply + verify after assignment)" if site_full else "")
                warning=(f"\n\nInventory scan warning: {len(scan_errors)} organization(s) could not be checked. Claim will still re-validate the destination inventory and Meraki will reject serials claimed elsewhere." if scan_errors else "")
                messagebox.showinfo(
                    "Claim New Hardware dry run",
                    f"NO CHANGES MADE\n\nDestination org: {target_org.get('name')} [{target_org.get('id')}]\n"
                    f"Target network: {net.get('name')} [{net.get('id')}]\nNetwork products: {products}{site_text}\n\n"
                    f"Serials: {len(serials)}\nNew/unseen: {new_count}\nAlready in destination inventory and ready: {ready_existing}\n"
                    f"Already assigned here: {already}\nPreflight blocked: {blocked}\n\n"
                    "Apply will claim new/unseen serials into the destination organization, re-read the inventory to learn model/product type, "
                    "assign only compatible devices to the selected network, then verify each serial in BOTH destination inventory and network device lists."
                    + warning
                )
                self.write_log(f"DRY RUN new hardware claim: {len(serials)} serial(s) -> {target_org.get('name')} / {net.get('name')} | blocked={blocked}")
            self._emit("call",done)

        def finished(error):
            self.hold_list_button.configure(text="List Destination Inventory")
            self.hold_move_button.configure(text="CLAIM + VERIFY")
            self._finish_buttons([self.hold_list_button,self.hold_dry_button,self.hold_move_button],self.hold_status_var,error)
            if error is not None:
                self.hold_status_var.set("Preflight failed")
        self.worker(work,finished)

    def _new_claim_apply(self):
        try:
            plan=self._new_claim_plan()
        except Exception as exc:
            messagebox.showerror("Claim New Hardware",str(exc)); return
        sig=self._new_claim_signature(plan)
        if not self.last_new_claim_preview or self.last_new_claim_preview.get("signature")!=sig:
            messagebox.showerror("Claim New Hardware","Run Dry Run again. The organization, network, or serial list changed after the last preview.")
            return
        target_org=plan["target_org"]; net=plan["target_net"]; serials=plan["serials"]
        confirm=simpledialog.askstring(
            "Claim New Hardware",
            f"Type CLAIM HARDWARE to claim {len(serials)} serial(s) into:\n{target_org.get('name')} / {net.get('name')}"
        )
        if confirm!="CLAIM HARDWARE":
            return
        self._set_buttons([self.hold_list_button,self.hold_dry_button,self.hold_move_button],"disabled")
        self.hold_move_button.configure(text="Claiming...")
        self.hold_status_var.set("Step 1/4 · Re-validating inventory...")

        def set_status(text): self._emit("call",lambda t=text:self.hold_status_var.set(t))

        def work():
            api=self.require_api(); oid=str(target_org["id"]); nid=str(net["id"])
            quoted_oid=urllib.parse.quote(oid); quoted_nid=urllib.parse.quote(nid)
            target_inv,locations,scan_errors=self._scan_claim_locations(api,serials,target_org)
            invmap=self._inventory_by_serial(target_inv)
            result={norm_serial(s):{"serial":s,"model":"","product":"unknown","status":"PENDING","reason":""} for s in serials}
            to_org_claim=[]; assign_candidates=[]

            nmap={n.get("id"):n.get("name","") for n in self.networks}
            for serial in serials:
                key=norm_serial(serial); r=result[key]; loc=locations.get(key)
                if loc and not loc["target"]:
                    r["status"]="FAIL"; r["reason"]=f"Already claimed in {loc['org'].get('name')}"
                    dev=loc["device"]; r["model"]=str(dev.get("model") or ""); r["product"]=self._delete_device_product_type(dev) or "unknown"
                    continue
                dev=invmap.get(key)
                if dev:
                    r["model"]=str(dev.get("model") or ""); r["product"]=self._delete_device_product_type(dev) or "unknown"
                    existing_nid=dev.get("networkId")
                    if str(existing_nid or "")==nid:
                        r["status"]="PASS"; r["reason"]="Already assigned to target network"
                    elif existing_nid:
                        r["status"]="FAIL"; r["reason"]=f"Already assigned to another destination-org network: {nmap.get(existing_nid,existing_nid)}"
                    else:
                        pt,ok=self._claim_network_compatible(dev,net)
                        if ok:
                            assign_candidates.append(serial)
                        else:
                            r["status"]="FAIL"; r["reason"]=f"Product {pt or 'unknown'} is not supported by target network"
                else:
                    to_org_claim.append(serial)

            org_claim_errors={}
            if to_org_claim:
                set_status(f"Step 2/4 · Claiming {len(to_org_claim)} new serial(s) into organization...")
                try:
                    api.post(f"/organizations/{quoted_oid}/inventory/claim",{"serials":to_org_claim})
                    self._emit("log",f"Organization claim submitted for {len(to_org_claim)} serial(s).")
                except Exception as exc:
                    bulk_error=str(exc)
                    self._emit("log",f"Bulk organization claim returned an error: {bulk_error}")
                    low=bulk_error.casefold()
                    transient_bulk=(
                        "not found" in low
                        or "try again" in low
                        or "temporar" in low
                        or "timeout" in low
                        or "connection failed" in low
                        or "propagat" in low
                    )

                    # A newly shipped/unclaimed serial can briefly lag in Meraki's
                    # claim backend even though Dashboard can claim it moments later.
                    # For a single-device job, retry transient organization-claim
                    # failures with bounded backoff before declaring the serial bad.
                    if len(to_org_claim)==1 and transient_bulk:
                        serial=to_org_claim[0]
                        key=norm_serial(serial)
                        last_error=bulk_error
                        for retry,delay in enumerate((3,7),1):
                            set_status(
                                f"Step 2/4 · Organization claim not ready for {serial} "
                                f"· retry {retry}/2 in {delay}s..."
                            )
                            time.sleep(delay)
                            try:
                                api.post(f"/organizations/{quoted_oid}/inventory/claim",{"serials":[serial]})
                                self._emit("log",f"Organization claim retry {retry}/2 accepted for {serial}.")
                                last_error=""
                                break
                            except Exception as one_exc:
                                last_error=str(one_exc)
                                self._emit("log",f"Organization claim retry {retry}/2 failed for {serial}: {last_error}")
                                retry_low=last_error.casefold()
                                transient_retry=(
                                    "not found" in retry_low
                                    or "try again" in retry_low
                                    or "temporar" in retry_low
                                    or "timeout" in retry_low
                                    or "connection failed" in retry_low
                                    or "propagat" in retry_low
                                )
                                if not transient_retry:
                                    break
                        if last_error:
                            org_claim_errors[key]=last_error
                    elif len(to_org_claim)<=8:
                        # Non-transient bulk errors are retried individually so one
                        # bad serial does not hide the result for the rest of the batch.
                        for serial in to_org_claim:
                            try:
                                api.post(f"/organizations/{quoted_oid}/inventory/claim",{"serials":[serial]})
                            except Exception as one_exc:
                                org_claim_errors[norm_serial(serial)]=str(one_exc)
                    else:
                        for serial in to_org_claim:
                            org_claim_errors[norm_serial(serial)]=bulk_error

                # Inventory claim propagation can lag briefly. Always re-read even
                # after an API error because the backend may complete asynchronously.
                for attempt in range(8):
                    target_inv=api.get_all(f"/organizations/{quoted_oid}/inventory/devices")
                    invmap=self._inventory_by_serial(target_inv)
                    missing=[s for s in to_org_claim if norm_serial(s) not in invmap]
                    if not missing:
                        break
                    if attempt<7:
                        set_status(
                            f"Step 2/4 · Waiting for organization inventory propagation "
                            f"({attempt+1}/8)..."
                        )
                        time.sleep(2)

                for serial in to_org_claim:
                    key=norm_serial(serial); r=result[key]; dev=invmap.get(key)
                    if not dev:
                        detail=org_claim_errors.get(key,"Not present in destination inventory after organization claim")
                        r["status"]="FAIL"; r["reason"]="Organization inventory claim failed: " + detail
                        continue
                    r["model"]=str(dev.get("model") or ""); r["product"]=self._delete_device_product_type(dev) or "unknown"
                    existing_nid=dev.get("networkId")
                    if str(existing_nid or "")==nid:
                        r["status"]="PASS"; r["reason"]="Claimed and already assigned to target network"
                        continue
                    if existing_nid:
                        r["status"]="FAIL"; r["reason"]=f"Claimed into org but unexpectedly assigned to network {existing_nid}; automatic move stopped"
                        continue
                    pt,ok=self._claim_network_compatible(dev,net)
                    if not ok:
                        r["status"]="FAIL"; r["reason"]=f"Claimed into org, but product {pt or 'unknown'} is not supported by target network; left unassigned"
                        continue
                    assign_candidates.append(serial)

            # Deduplicate assign list while preserving order, excluding already-failed rows.
            seen=set(); eligible=[]
            for serial in assign_candidates:
                key=norm_serial(serial)
                if key in seen or result[key]["status"]=="FAIL": continue
                seen.add(key); eligible.append(serial)

            network_errors={}
            if eligible:
                # Meraki documents that devices may take time to become usable by
                # network-level API calls immediately after an organization claim.
                # Retry only propagation-style failures and verify after every attempt.
                pending=list(eligible)
                last_network_errors={}
                retry_delays=(0,2,4,8,12,18)
                for attempt,delay in enumerate(retry_delays,1):
                    if not pending:
                        break
                    if delay:
                        set_status(f"Step 3/4 · Waiting {delay}s for Meraki claim propagation...")
                        time.sleep(delay)
                    set_status(
                        f"Step 3/4 · Assigning {len(pending)} device(s) to network "
                        f"· attempt {attempt}/{len(retry_delays)}..."
                    )
                    attempt_errors={}
                    try:
                        response=api.post(
                            f"/networks/{quoted_nid}/devices/claim?addAtomically=false",
                            {"serials":pending},
                        ) or {}
                        for err in response.get("errors") or []:
                            key=norm_serial(str(err.get("serial") or ""))
                            msgs=err.get("errors") or []
                            msg="; ".join(str(x) for x in msgs) or "Network claim failed"
                            if key:
                                attempt_errors[key]=msg
                                last_network_errors[key]=msg
                    except Exception as exc:
                        msg=str(exc)
                        for serial in pending:
                            key=norm_serial(serial)
                            attempt_errors[key]=msg
                            last_network_errors[key]=msg

                    # A successful claim can still take a moment to appear in the
                    # network device list. Read back before deciding whether to retry.
                    try:
                        current_devices=api.get_all(f"/networks/{quoted_nid}/devices")
                        current_serials={
                            norm_serial(str(d.get("serial") or ""))
                            for d in current_devices
                        }
                    except Exception:
                        current_serials=set()

                    next_pending=[]
                    for serial in pending:
                        key=norm_serial(serial)
                        if key in current_serials:
                            network_errors.pop(key,None)
                            continue
                        msg=attempt_errors.get(key) or last_network_errors.get(key) or ""
                        low=msg.casefold()
                        transient=(
                            not msg
                            or "not found" in low
                            or "recently claimed" in low
                            or "already claimed" in low
                            or "try again" in low
                            or "temporar" in low
                            or "propagat" in low
                        )
                        if transient and attempt < len(retry_delays):
                            next_pending.append(serial)
                        else:
                            network_errors[key]=(
                                msg
                                or "Device was claimed into organization inventory but did not become "
                                   "assignable to the target network before the propagation timeout."
                            )
                    pending=next_pending

            set_status("Step 4/4 · Re-reading inventory and network for verification...")
            final_inv=[]; final_devices=[]
            expected={norm_serial(s) for s in eligible}
            for attempt in range(6):
                final_inv=api.get_all(f"/organizations/{quoted_oid}/inventory/devices")
                final_devices=api.get_all(f"/networks/{quoted_nid}/devices")
                final_invmap=self._inventory_by_serial(final_inv)
                network_serials={norm_serial(str(d.get("serial") or "")) for d in final_devices}
                pending=[]
                for serial in eligible:
                    key=norm_serial(serial); dev=final_invmap.get(key)
                    if not dev or str(dev.get("networkId") or "")!=nid or key not in network_serials:
                        pending.append(serial)
                if not pending: break
                if attempt<5: time.sleep(2)

            final_invmap=self._inventory_by_serial(final_inv)
            network_serials={norm_serial(str(d.get("serial") or "")) for d in final_devices}
            for serial in eligible:
                key=norm_serial(serial); r=result[key]; dev=final_invmap.get(key)
                if dev:
                    r["model"]=str(dev.get("model") or r["model"]); r["product"]=self._delete_device_product_type(dev) or r["product"]
                inv_ok=bool(dev and str(dev.get("networkId") or "")==nid)
                net_ok=key in network_serials
                if inv_ok and net_ok:
                    r["status"]="PASS"; r["reason"]="Verified in destination inventory and target network"
                else:
                    r["status"]="FAIL"
                    if network_errors.get(key):
                        r["reason"]="Network assignment failed: " + network_errors[key]
                    else:
                        r["reason"]=f"Verification failed (inventory target={inv_ok}, network list={net_ok})"

            # Verify rows that were already assigned at start in both places too.
            for serial in serials:
                key=norm_serial(serial); r=result[key]
                if r["status"]=="PASS" and "Already assigned" in r["reason"]:
                    dev=final_invmap.get(key)
                    inv_ok=bool(dev and str(dev.get("networkId") or "")==nid)
                    net_ok=key in network_serials
                    if not (inv_ok and net_ok):
                        r["status"]="FAIL"; r["reason"]=f"Existing assignment verification failed (inventory target={inv_ok}, network list={net_ok})"

            # If the destination network has a physical site address stored in notes, apply it to every PASS device now.
            pass_serials=[r["serial"] for r in result.values() if r.get("status")=="PASS"]
            site_result=self._apply_site_address_to_devices(api,nid,pass_serials,True) if pass_serials else {"configured":False,"verified":True,"results":[]}
            if site_result.get("configured"):
                by_serial={norm_serial(str(r.get("serial") or "")):r for r in site_result.get("results") or []}
                for serial in pass_serials:
                    key=norm_serial(serial); sr=by_serial.get(key)
                    if sr and sr.get("status")=="PASS":
                        result[key]["reason"] += f"; site address verified: {site_result.get('address')}"
                    elif sr and sr.get("status")=="WARN":
                        result[key]["reason"] += "; site address warning: " + (sr.get("detail") or "device metadata update unavailable")
                    else:
                        result[key]["status"]="FAIL"
                        result[key]["reason"] += "; site address auto-apply failed: " + ((sr or {}).get("detail") or "no verification result")

            ordered=[result[norm_serial(s)] for s in serials]
            passed=sum(1 for r in ordered if r["status"]=="PASS")
            failed=len(ordered)-passed
            report_dir=REPORTS/"HardwareInventory"; report_dir.mkdir(parents=True,exist_ok=True)
            report_path=report_dir/f"claim-new-hardware-{safe_filename(target_org.get('name','org'))}-{safe_filename(net.get('name','network'))}-{nowstamp()}.txt"
            lines=[
                "MERAKI CLAIM NEW HARDWARE - APPLY + VERIFY",
                "="*72,
                f"Organization : {target_org.get('name')} [{target_org.get('id')}]",
                f"Network      : {net.get('name')} [{net.get('id')}]",
                f"Products     : {', '.join(net.get('productTypes') or []) or '(none)'}",
                f"Serials      : {len(ordered)}",
                f"PASS         : {passed}",
                f"FAIL         : {failed}",
                "",
                "PER-DEVICE RESULT",
                "-----------------",
            ]
            for r in ordered:
                lines.append(f"{r['status']:4} | {r['serial']} | {r['model'] or '(unknown model)'} | {r['product']} | {r['reason']}")
            if scan_errors:
                lines += ["","PREFLIGHT INVENTORY SCAN WARNINGS","---------------------------------"] + scan_errors
            report_path.write_text("\n".join(lines)+"\n",encoding="utf-8")

            def done():
                for i in self.hold_tree.get_children(): self.hold_tree.delete(i)
                for r in ordered:
                    self.hold_tree.insert("","end",values=(r["serial"],r["model"],r["product"],f"{r['status']} - {r['reason']}"))
                self.hold_status_var.set(f"Claim complete · PASS {passed} · FAIL {failed}")
                self.write_log(f"Claim New Hardware complete: PASS={passed} FAIL={failed} | {report_path}")
                messagebox.showinfo(
                    "Claim New Hardware complete",
                    f"PASS: {passed}\nFAIL: {failed}\n\nEvery PASS was verified in both the destination organization inventory and the target network device list.\n\nReport:\n{report_path}"
                )
            self._emit("call",done)

        def finished(error):
            self.hold_move_button.configure(text="CLAIM + VERIFY")
            self.hold_list_button.configure(text="List Destination Inventory")
            self._finish_buttons([self.hold_list_button,self.hold_dry_button,self.hold_move_button],self.hold_status_var,error)
            if error is not None:
                self.hold_status_var.set("Claim workflow failed · inspect inventory before retry")
            self.last_new_claim_preview=None
        self.worker(work,finished)

    @staticmethod
    def _offboarding_snapshot_signature(org_id, rows):
        normalized=[]
        for row in rows:
            normalized.append({
                "serial":norm_serial(str(row.get("serial") or "")),
                "model":str(row.get("model") or ""),
                "product":str(row.get("product") or "unknown"),
                "networkId":str(row.get("networkId") or ""),
            })
        normalized.sort(key=lambda x:x["serial"])
        return json.dumps({"orgId":str(org_id),"devices":normalized},sort_keys=True,separators=(",",":"))

    def _offboarding_live_rows(self, api, org, selected_serials):
        oid=str(org.get("id"))
        inv=api.get_all(f"/organizations/{urllib.parse.quote(oid)}/inventory/devices")
        invmap=self._inventory_by_serial(inv)
        nets=api.get_all(f"/organizations/{urllib.parse.quote(oid)}/networks")
        nmap={str(n.get("id")):str(n.get("name") or "") for n in (nets or [])}
        rows=[]; missing=[]
        for serial in selected_serials:
            key=norm_serial(serial); dev=invmap.get(key)
            if not dev:
                missing.append(serial); continue
            network_id=str(dev.get("networkId") or "")
            rows.append({
                "serial":str(dev.get("serial") or serial).upper(),
                "model":str(dev.get("model") or ""),
                "product":self._delete_device_product_type(dev) or "unknown",
                "networkId":network_id,
                "networkName":nmap.get(network_id,network_id) if network_id else "Unassigned",
            })
        return rows,missing

    def _offboarding_preview(self):
        try:
            org=self.selected_org()
            if self.holding_org and str(org.get("id"))==str(self.holding_org.get("id")):
                raise RuntimeError("Client Offboarding cannot target Hardware Holding. Select the departing customer organization.")
            selected=self._offboarding_selected_serials()
            if not selected:
                raise RuntimeError("Select at least one device to unclaim, or click Select All Devices.")
        except Exception as exc:
            messagebox.showerror("Client Offboarding",str(exc)); return
        if self.hold_dry_button.instate(["disabled"]):
            return
        self.last_offboarding_preview=None
        buttons=[self.hold_list_button,self.hold_dry_button,self.hold_move_button,self.offboard_select_all_button,self.offboard_clear_selection_button]
        self._set_buttons(buttons,"disabled")
        self.hold_status_var.set("Dry run · re-reading selected organization inventory...")

        def work():
            api=self.require_api()
            rows,missing=self._offboarding_live_rows(api,org,selected)
            if missing:
                raise RuntimeError("Dry run stopped because selected serial(s) are no longer in the organization inventory: " + ", ".join(missing))
            signature=self._offboarding_snapshot_signature(org.get("id"),rows)
            report_dir=REPORTS/"HardwareInventory"; report_dir.mkdir(parents=True,exist_ok=True)
            report_path=report_dir/f"client-offboarding-preflight-{safe_filename(org.get('name','org'))}-{nowstamp()}.txt"
            lines=[
                "MERAKI CLIENT OFFBOARDING - PREFLIGHT / DRY RUN",
                "="*72,
                "NO CHANGES MADE",
                "",
                f"Organization : {org.get('name')} [{org.get('id')}]",
                f"Selected     : {len(rows)} device(s)",
                "Action       : Remove selected devices from assigned networks, then release/unclaim them from this organization.",
                "Networks/org : LEFT INTACT",
                "Licensing    : NOT CHANGED - review licensing/subscriptions/billing separately.",
                "",
                "SELECTED HARDWARE",
                "-----------------",
            ]
            for r in rows:
                lines.append(f"{r['serial']} | {r['model'] or '(unknown model)'} | {r['product']} | {r['networkName']}")
            lines += [
                "",
                "SAFETY",
                "------",
                "Apply requires typed confirmation: UNCLAIM ALL",
                "The toolkit will verify each released serial no longer appears in the customer organization inventory.",
            ]
            report_path.write_text("\n".join(lines)+"\n",encoding="utf-8")
            preview={
                "orgId":str(org.get("id")),"orgName":str(org.get("name") or ""),
                "serials":[r["serial"] for r in rows],"rows":rows,"signature":signature,
                "reportPath":str(report_path),
            }
            def done():
                self.last_offboarding_preview=preview
                self.hold_status_var.set(f"Dry run ready · {len(rows)} selected · preflight report saved")
                self.write_log(f"DRY RUN client offboarding: {org.get('name')} | selected={len(rows)} | report={report_path}")
                assigned=sum(1 for r in rows if r.get("networkId"))
                messagebox.showinfo(
                    "Client Offboarding dry run",
                    f"NO CHANGES MADE\n\nOrganization: {org.get('name')} [{org.get('id')}]\n"
                    f"Selected devices: {len(rows)}\nCurrently assigned to networks: {assigned}\nCurrently unassigned: {len(rows)-assigned}\n\n"
                    "Apply will remove selected assigned devices from their current networks, release/unclaim the selected serials from this organization, "
                    "and verify every successful serial is gone from the organization inventory.\n\n"
                    "The organization and its networks will NOT be deleted. Licensing/subscriptions/billing are NOT changed.\n\n"
                    f"Preflight report saved BEFORE any write:\n{report_path}\n\nTyped confirmation required: UNCLAIM ALL"
                )
            self._emit("call",done)

        def finished(error):
            self._finish_buttons(buttons,self.hold_status_var,error)
            if error is not None:
                self.hold_status_var.set("Offboarding dry run failed")
        self.worker(work,finished)

    def _offboarding_apply(self):
        preview=self.last_offboarding_preview
        if not preview:
            messagebox.showerror("Client Offboarding","Run Dry Run first and review the selected devices.")
            return
        try:
            org=self.selected_org()
            if str(org.get("id"))!=str(preview.get("orgId")):
                raise RuntimeError("Selected organization changed after Dry Run. Run Dry Run again.")
            selected=self._offboarding_selected_serials()
            if [norm_serial(x) for x in selected] != [norm_serial(x) for x in preview.get("serials",[])]:
                # Selection order may differ; compare as sets, then use preview order.
                if set(norm_serial(x) for x in selected)!=set(norm_serial(x) for x in preview.get("serials",[])):
                    raise RuntimeError("Selected device list changed after Dry Run. Run Dry Run again.")
            report_path=Path(str(preview.get("reportPath") or ""))
            if not report_path.exists():
                raise RuntimeError("The required preflight report is missing. Run Dry Run again before any unclaim operation.")
        except Exception as exc:
            messagebox.showerror("Client Offboarding",str(exc)); return

        confirm=simpledialog.askstring(
            "Client Offboarding - Unclaim Hardware",
            f"Organization: {preview.get('orgName')} [{preview.get('orgId')}]\n"
            f"Selected devices: {len(preview.get('serials',[]))}\n\n"
            "This releases the selected hardware from the customer's Meraki organization.\n"
            "Organization/networks remain intact. Licensing is separate.\n\n"
            "Type UNCLAIM ALL to continue:"
        )
        if confirm!="UNCLAIM ALL":
            return

        buttons=[self.hold_list_button,self.hold_dry_button,self.hold_move_button,self.offboard_select_all_button,self.offboard_clear_selection_button]
        self._set_buttons(buttons,"disabled")
        self.hold_move_button.configure(text="Unclaiming...")
        self.hold_status_var.set("Safety check · re-reading exact hardware snapshot...")

        def set_status(text):
            self._emit("call",lambda t=text:self.hold_status_var.set(t))

        def work():
            api=self.require_api(); oid=str(preview["orgId"]); serials=list(preview["serials"])
            live_rows,missing=self._offboarding_live_rows(api,org,serials)
            if missing:
                raise RuntimeError("Offboarding aborted: serial(s) disappeared from inventory after Dry Run: " + ", ".join(missing))
            live_signature=self._offboarding_snapshot_signature(oid,live_rows)
            if live_signature!=preview.get("signature"):
                raise RuntimeError("Offboarding aborted: device assignment/model state changed after Dry Run. Inventory again and repeat Dry Run.")

            result={}
            for r in live_rows:
                key=norm_serial(r["serial"])
                result[key]={**r,"status":"PENDING","reason":""}

            # Step 1: remove selected assigned devices from their exact current networks.
            assigned=[r for r in live_rows if r.get("networkId")]
            set_status(f"Step 1/3 · Removing {len(assigned)} assigned device(s) from current networks...")
            for r in assigned:
                key=norm_serial(r["serial"])
                try:
                    api.post(f"/networks/{urllib.parse.quote(str(r['networkId']))}/devices/remove",{"serial":r["serial"]})
                    result[key]["reason"]="Removed from current network; ready for release"
                except Exception as exc:
                    result[key]["status"]="FAIL"
                    result[key]["reason"]=f"Network removal failed: {exc}"

            # Wait until every non-failed selected device is unassigned in organization inventory.
            release_candidates=[r["serial"] for r in live_rows if result[norm_serial(r["serial"])]["status"]!="FAIL"]
            if release_candidates:
                set_status("Step 2/3 · Verifying selected devices are unassigned before release...")
                latest=[]
                for attempt in range(6):
                    latest=api.get_all(f"/organizations/{urllib.parse.quote(oid)}/inventory/devices")
                    m=self._inventory_by_serial(latest)
                    still_assigned=[]
                    for serial in release_candidates:
                        dev=m.get(norm_serial(serial))
                        if dev and dev.get("networkId"):
                            still_assigned.append(serial)
                    if not still_assigned:
                        break
                    if attempt<5: time.sleep(2)
                m=self._inventory_by_serial(latest)
                ready=[]
                for serial in release_candidates:
                    key=norm_serial(serial); dev=m.get(key)
                    if not dev:
                        result[key]["status"]="FAIL"; result[key]["reason"]="Device disappeared from organization inventory before release verification"
                    elif dev.get("networkId"):
                        result[key]["status"]="FAIL"; result[key]["reason"]=f"Still assigned to network {dev.get('networkId')} after removal request"
                    else:
                        ready.append(serial)
                release_candidates=ready

            # Step 3: release/unclaim in bounded batches; one failed batch does not hide other results.
            set_status(f"Step 3/3 · Releasing {len(release_candidates)} device(s) from customer organization...")
            released=[]
            for i in range(0,len(release_candidates),100):
                batch=release_candidates[i:i+100]
                try:
                    api.post(f"/organizations/{urllib.parse.quote(oid)}/inventory/release",{"serials":batch})
                    released.extend(batch)
                except Exception as exc:
                    for serial in batch:
                        key=norm_serial(serial); result[key]["status"]="FAIL"; result[key]["reason"]=f"Organization release failed: {exc}"

            # Final verification: successful releases must be absent from the org inventory.
            final_inv=[]
            released_keys={norm_serial(s) for s in released}
            for attempt in range(6):
                final_inv=api.get_all(f"/organizations/{urllib.parse.quote(oid)}/inventory/devices")
                final_map=self._inventory_by_serial(final_inv)
                still={k for k in released_keys if k in final_map}
                if not still:
                    break
                if attempt<5: time.sleep(2)
            final_map=self._inventory_by_serial(final_inv)
            for serial in released:
                key=norm_serial(serial)
                if key not in final_map:
                    result[key]["status"]="PASS"; result[key]["reason"]="Verified absent from customer organization inventory"
                else:
                    result[key]["status"]="FAIL"; result[key]["reason"]="Release request completed, but serial still appears in customer organization inventory"

            ordered=[result[norm_serial(s)] for s in serials]
            passed=sum(1 for r in ordered if r["status"]=="PASS")
            failed=len(ordered)-passed
            result_dir=REPORTS/"HardwareInventory"; result_dir.mkdir(parents=True,exist_ok=True)
            result_path=result_dir/f"client-offboarding-result-{safe_filename(preview.get('orgName','org'))}-{nowstamp()}.txt"
            lines=[
                "MERAKI CLIENT OFFBOARDING - UNCLAIM + VERIFY",
                "="*72,
                f"Organization : {preview.get('orgName')} [{oid}]",
                f"Selected     : {len(ordered)}",
                f"PASS         : {passed}",
                f"FAIL         : {failed}",
                f"Preflight    : {preview.get('reportPath')}",
                "Networks/org : LEFT INTACT",
                "Licensing    : NOT CHANGED - review licensing/subscriptions/billing separately.",
                "",
                "PER-DEVICE RESULT",
                "-----------------",
            ]
            for r in ordered:
                lines.append(f"{r['status']:4} | {r['serial']} | {r['model'] or '(unknown model)'} | {r['product']} | {r['networkName']} | {r['reason']}")
            result_path.write_text("\n".join(lines)+"\n",encoding="utf-8")

            def done():
                for iid in self.hold_tree.get_children(): self.hold_tree.delete(iid)
                for r in ordered:
                    self.hold_tree.insert("","end",values=(r["serial"],r["model"],r["product"],f"{r['status']} - {r['reason']}"))
                self.hold_status_var.set(f"Offboarding complete · PASS {passed} · FAIL {failed}")
                self.write_log(f"Client Offboarding complete: {preview.get('orgName')} | PASS={passed} FAIL={failed} | {result_path}")
                messagebox.showinfo(
                    "Client Offboarding complete",
                    f"PASS: {passed}\nFAIL: {failed}\n\n"
                    "Each PASS serial was verified absent from the customer organization inventory.\n"
                    "The organization and networks were left intact. Licensing/subscriptions were not changed.\n\n"
                    f"Preflight report:\n{preview.get('reportPath')}\n\nResult report:\n{result_path}"
                )
            self._emit("call",done)

        def finished(error):
            self.hold_move_button.configure(text="UNCLAIM + VERIFY")
            self.hold_list_button.configure(text="Inventory Client Hardware")
            self._finish_buttons(buttons,self.hold_status_var,error)
            if error is not None:
                self.hold_status_var.set("Offboarding NOT fully verified · inspect inventory before retry")
            self.last_offboarding_preview=None
        self.worker(work,finished)

    @staticmethod
    def _holding_plan_signature(plan):
        return json.dumps({
            "direction":plan.get("direction"),
            "serial":norm_serial(str(plan.get("serial") or "")),
            "sourceOrgId":str((plan.get("source_org") or {}).get("id") or ""),
            "targetOrgId":str((plan.get("target_org") or {}).get("id") or ""),
            "targetNetworkId":str((plan.get("target_net") or {}).get("id") or ""),
        },sort_keys=True,separators=(",",":"))

    def holding_preview(self):
        if self.hold_direction.get()=="Claim New Hardware":
            self._new_claim_preview(); return
        if self.hold_direction.get()=="Client Offboarding - Unclaim":
            self._offboarding_preview(); return
        try:
            plan=self._holding_plan()
        except Exception as exc:
            messagebox.showerror("Hardware / Inventory",str(exc))
            return
        serial=plan["serial"]
        source=plan["source_org"]
        target=plan["target_org"]
        net=plan["target_net"]
        returning=plan["direction"]=="return"
        self.last_holding_preview_signature=self._holding_plan_signature(plan)
        self.hold_status_var.set("Dry run ready · no changes made")
        action="RETURN" if returning else "MOVE"
        site_full=format_site_address(site_address_from_notes(net.get("notes") or ""))
        self.write_log(f"DRY RUN hardware {action.lower()}: {serial} | {source.get('name')} -> {target.get('name')} -> {net.get('name')}")
        site_text=(f"\n\nSite address: {site_full}\nAfter assignment, the Toolkit will apply this address to the device and verify it." if site_full else "")
        messagebox.showinfo(
            "Hardware / Inventory dry run",
            f"No changes made.\n\nSerial: {serial}\nSource org: {source.get('name')}\n"
            f"Target org: {target.get('name')}\nTarget network: {net.get('name')}" + site_text + "\n\n"
            "Apply will remove the device from its current network if assigned, release it from the source organization inventory, "
            "claim it into the destination organization inventory, then claim it into the selected destination network."
        )

    def holding_apply(self):
        if self.hold_direction.get()=="Claim New Hardware":
            self._new_claim_apply(); return
        if self.hold_direction.get()=="Client Offboarding - Unclaim":
            self._offboarding_apply(); return
        try:
            plan=self._holding_plan()
        except Exception as exc:
            messagebox.showerror("Hardware / Inventory",str(exc))
            return
        if self.hold_move_button.instate(["disabled"]):
            return
        if self.last_holding_preview_signature!=self._holding_plan_signature(plan):
            messagebox.showerror("Hardware / Inventory","Run Dry Run first. The serial, organization, direction, or target network changed after the last preview.")
            return
        serial=plan["serial"]
        source=plan["source_org"]
        target=plan["target_org"]
        net=plan["target_net"]
        returning=plan["direction"]=="return"
        word="RETURN" if returning else "MOVE"
        confirm=simpledialog.askstring(
            f"{word} hardware",
            f"Type {word} to transfer {serial}:\n{source.get('name')} -> {target.get('name')} / {net.get('name')}"
        )
        if confirm!=word:
            return
        self._set_buttons([self.hold_list_button,self.hold_dry_button,self.hold_move_button],"disabled")
        self.hold_move_button.configure(text="Returning..." if returning else "Moving...")
        self.hold_status_var.set("Locating device in source organization...")

        def set_status(text):
            self._emit("call",lambda t=text:self.hold_status_var.set(t))

        def work():
            api=self.require_api()
            source_id=str(source["id"]); target_id=str(target["id"])
            inv=api.get_all(f"/organizations/{urllib.parse.quote(source_id)}/inventory/devices")
            dev=next((d for d in inv if norm_serial(str(d.get('serial','')))==norm_serial(serial)),None)
            if not dev:
                raise RuntimeError(f"{serial} was not found in {source.get('name')} inventory.")
            oldnet=dev.get("networkId")
            if oldnet:
                set_status("Step 1/4 · Removing from source network...")
                self._emit("log",f"Removing {serial} from source network {oldnet}...")
                api.post(f"/networks/{urllib.parse.quote(str(oldnet))}/devices/remove",{"serial":serial})
            else:
                self._emit("log",f"{serial} is unassigned in the source organization; network removal skipped.")
            set_status("Step 2/4 · Releasing from source inventory...")
            self._emit("log",f"Releasing {serial} from {source.get('name')} inventory...")
            api.post(f"/organizations/{urllib.parse.quote(source_id)}/inventory/release",{"serials":[serial]})
            set_status("Step 3/4 · Claiming into destination organization...")
            self._emit("log",f"Claiming {serial} into {target.get('name')} inventory...")
            api.post(f"/organizations/{urllib.parse.quote(target_id)}/inventory/claim",{"serials":[serial]})
            set_status("Step 4/4 · Claiming into destination network...")
            self._emit("log",f"Claiming {serial} into destination network {net.get('name')}...")
            api.post(f"/networks/{urllib.parse.quote(str(net['id']))}/devices/claim",{"serials":[serial]})
            # Re-read both inventory and network for an explicit transfer verification.
            final_inv=api.get_all(f"/organizations/{urllib.parse.quote(target_id)}/inventory/devices")
            final_net=api.get_all(f"/networks/{urllib.parse.quote(str(net['id']))}/devices")
            idev=next((d for d in final_inv if norm_serial(str(d.get('serial','')))==norm_serial(serial)),None)
            net_ok=any(norm_serial(str(d.get('serial','')))==norm_serial(serial) for d in final_net)
            if not idev or str(idev.get("networkId") or "")!=str(net["id"]) or not net_ok:
                raise RuntimeError("Transfer API calls completed, but final destination inventory/network verification did not pass.")
            site_result=self._apply_site_address_to_devices(api,net["id"],[serial],True)
            site_warning=""
            if site_result.get("configured"):
                if site_result.get("failures"):
                    detail="; ".join(f"{r.get('serial')}: {r.get('detail')}" for r in site_result.get("results") or [] if r.get("status")=="FAIL")
                    site_warning=(
                        f"Hardware transfer succeeded and was verified, but the site-address device update failed: {detail}.\n\n"
                        "The device remains safely in the destination network. Use Post-Build > Site / Location to retry the address update."
                    )
                    self._emit("log",f"WARNING: {site_warning}")
                    self._emit("call",lambda m=site_warning: messagebox.showwarning("Hardware transfer verified · Site address failed",m))
                elif site_result.get("warnings"):
                    detail="; ".join(f"{r.get('serial')}: {r.get('detail')}" for r in site_result.get("results") or [] if r.get("status")=="WARN")
                    site_warning=(
                        f"Hardware transfer succeeded and was verified. The site address remains stored on the network, but Meraki did not expose a writable device metadata path for this device: {detail}"
                    )
                    self._emit("log",f"WARNING: {site_warning}")
                    self._emit("call",lambda m=site_warning: messagebox.showwarning("Hardware transfer verified · Device site metadata unavailable",m))
                else:
                    self._emit("log",f"Site address auto-applied and verified on {serial}: {site_result.get('address')}")
            self._emit("log",f"SUCCESS: {serial} transferred and verified in {target.get('name')} / {net.get('name')}.")
            final_status=("Return complete · VERIFIED" if returning else "Move complete · VERIFIED")
            if site_result.get("configured"):
                if site_result.get("failures"):
                    final_status += " · SITE ADDRESS FAILED"
                elif site_result.get("warnings"):
                    final_status += " · SITE ADDRESS STORED / DEVICE API WARNING"
                else:
                    final_status += " · SITE ADDRESS VERIFIED"
            self._emit("call",lambda t=final_status:self.hold_status_var.set(t))

        def finished(error):
            self.last_holding_preview_signature=None
            self.hold_move_button.configure(text="RETURN Hardware" if returning else "MOVE Hardware")
            self.hold_list_button.configure(text="List Source Inventory" if returning else "List Holding Inventory")
            self._finish_buttons([self.hold_list_button,self.hold_dry_button,self.hold_move_button],self.hold_status_var,error)
            if error is not None:
                self.hold_status_var.set("Return failed" if returning else "Move failed")
        self.worker(work,finished)

    # ---------------- Safe wrappers ----------------
    def _launch_console(self, script: Path, args=None):
        if not self.api: messagebox.showwarning("Connect first","Connect to Meraki first so the API key can be passed securely in memory.");return False
        if not script.exists():messagebox.showerror("Missing tool",str(script));return False
        args=args or []
        key=self.key_entry.get().strip()
        # Start a new PowerShell window. Set key only in that child process environment.
        env=os.environ.copy(); env["MERAKI_DASHBOARD_API_KEY"]=key
        cmd=[self._tool_python_executable(),str(script),*args]
        try:
            if os.name=="nt":
                subprocess.Popen(["powershell.exe","-NoExit","-Command","& " + " ".join([f"'{x}'" for x in cmd])],cwd=str(ROOT),env=env,creationflags=subprocess.CREATE_NEW_CONSOLE)
            else:
                subprocess.Popen(cmd,cwd=str(ROOT),env=env)
            self.write_log(f"Launched {script.name}")
            return True
        except Exception as e:
            messagebox.showerror("Launch failed",str(e)); return False
    def launch_compliance(self):
        args=["--output-root",str(REPORTS/"Compliance")]
        if self.public_var.get():args.append("--public-display")
        self.more_status_var.set("Launching compliance audit...")
        if self._launch_console(TOOLS/"Meraki-Multi-Org-Compliance-Report-v2.1.py",args): self.more_status_var.set("Compliance audit launched in separate window")
        else: self.more_status_var.set("Launch failed")
    def launch_cleanup(self):
        args=["--audit-all"]
        if self.public_var.get():args.append("--public-display")
        self.more_status_var.set("Launching organization cleanup...")
        if self._launch_console(TOOLS/"Meraki-Organization-Cleanup-Safe-v7.py",args): self.more_status_var.set("Organization cleanup launched in separate window")
        else: self.more_status_var.set("Launch failed")
    def launch_clone_wrapper(self):
        args=[]
        try:
            org=self.selected_org();args.extend(["--org-id",str(org['id'])])
        except Exception:pass
        if self.public_var.get():args.append("--public-display")
        self.more_status_var.set("Launching legacy clone wrapper...")
        if self._launch_console(TOOLS/"Meraki-Network-Clone-Safe-v3.py",args): self.more_status_var.set("Legacy clone wrapper launched in separate window")
        else: self.more_status_var.set("Launch failed")


if __name__ == "__main__":
    try:
        Toolkit().mainloop()
    except Exception:
        try:
            log_dir = ROOT / "Logs"
            log_dir.mkdir(exist_ok=True)
            log_path = log_dir / "Meraki-MSP-Toolkit-crash.log"
            stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"\n[{stamp}] Fatal application exception\n")
                traceback.print_exc(file=fh)
        finally:
            raise
