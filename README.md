# Meraki MSP Toolkit v0.2.2

## v0.2.2 - Windows Defender packaging hardening

- Replaced the BAT -> WScript/VBS -> hidden PowerShell launch chain with a transparent BAT launcher that starts Python directly.
- Removed `-ExecutionPolicy Bypass`, hidden PowerShell execution, and the VBS launcher.
- Removed the old nested `Meraki-MSP-Toolkit-v0.2.0.zip` archive from the source tree so GitHub source downloads contain only the current source files.
- No Meraki API workflow logic was changed by this packaging hardening release.
- Bumped the GUI/application version to v0.2.2.

## v0.2.1 - Claim New Hardware reliability fix

- Fixed Claim New Hardware propagation handling at both stages. For a single new device, transient organization-inventory **Device not found** responses now get bounded retries and inventory read-back; after the organization claim succeeds, transient network-assignment propagation failures are also retried with read-back verification instead of immediately failing the workflow.
- Tightened new-hardware serial validation to the Meraki device format `XXXX-XXXX-XXXX`, preventing hashes/internal IDs from being submitted as serials.
- Claim result reports now distinguish **organization inventory claim** failures from **network assignment** failures.
- Existing dry-run, typed confirmation, compatibility checks, and final organization + network verification remain in place.

## v0.2.0 - Final release


This release packages the live-tested MSP workflow that was validated end to end against Meraki Dashboard: create a new organization/network, apply addressing, move or claim hardware, configure Post-Build settings, verify compliance, manage administrators, return/unclaim hardware, delete networks, and safely review/delete empty organizations.

### Final feature set

- **Network Builder** with No Clone / Clone Existing, explicit Single LAN or VLAN planning, RFC1918 safeguards, new-organization creation, full completed-build lockout, and physical site address fields.
- **Physical Site / Location** stored in network notes and applied/verified on assigned devices, including Dashboard map-marker updates when supported.
- **Post-Build** workspaces for Alerts, Site / Location, Wireless, Switches, Appliance, and scoped Compliance.
- **Appliance management** includes human-readable WAN inspection and guarded MX/Z naming with Preview + Apply + Verify.
- **Hardware / Inventory** covers Hardware Holding transfers, new/unclaimed serial claims, client offboarding, return-to-holding, and final destination verification.
- **Admin Access** supports full-org and selected-network grants, admin removal, and all-org employee offboarding with self-removal and sole-full-admin safety checks.
- **Delete Network** supports keep-in-customer-inventory, return-to-holding, or unclaim-from-customer dispositions with exact-ID verification.
- **Org Cleanup** audits blockers and permits permanent organization deletion only after networks, hardware, licensing value, templates, SAML, and administrator requirements are safe.
- **Compliance** separates selected-network findings from organization context and produces HTML/CSV reports without making Dashboard changes.
- Quiet launcher, crash/launcher logs, dry-run-first destructive workflows, typed confirmations, and API read-back verification throughout.

### Final validation highlights

- Full v0.2 lifecycle completed successfully against disposable Meraki organizations and real lab hardware.
- A post-build network went from **9 FAIL / 1 WARN** to **0 network findings** after the Toolkit applied and verified the baseline configuration.
- MX60 physical address, Dashboard map marker, and device name were verified directly in Meraki Dashboard.
- All three network-delete hardware dispositions and permanent organization cleanup/delete were tested successfully.

See `FINAL-REGRESSION-CHECKLIST.md` for the short release regression sequence.

## Release history

## v0.1.32 - Admin Access

- Added a dedicated **Admin Access** tab, separate from Org Cleanup.
- **Add / Change Admin** can create or update a Dashboard admin in one organization or every accessible organization.
- **Selected Networks** grants Full or Read-only access only to the selected networks in one organization (`orgAccess=none` with exact network grants; tag grants are cleared so they cannot silently broaden access).
- **Remove Admin** removes one administrator from the selected organization or every accessible organization where the email is found.
- **Employee Offboarding - All Organizations** scans every accessible org for the departing employee and prepares one all-org removal plan.
- Removal is blocked if the target is the authenticated API-key owner, if the current identity cannot be verified, or if removal would leave an organization without a full-access administrator.
- Admin Access changes administrator permissions only. It never deletes networks, devices, licensing, or organizations.
- Every write path requires Dry Run, typed confirmation, and post-write API read-back with PASS/FAIL per organization.

## v0.1.31 - Network compliance scope clarity

- **This Network** compliance reports now separate **NETWORK FINDINGS** from **ORGANIZATION CONTEXT**.
- The headline FAIL/WARN/REVIEW/INFO/Total cards for a network-scoped audit count only findings tied directly to the selected network.
- Organization-level items such as licensing or Dashboard-admin security remain visible in a separate context section but no longer inflate the network headline totals.
- The in-app completion summary uses the same split counts.
- Network-scoped audits now also write `network-findings.csv` and `organization-context.csv` alongside the combined `findings.csv`.
- Organization-scoped and fleet-wide compliance reports retain their existing combined summary behavior.


## v0.1.30 - Post-Build Compliance background runner

- Post-Build Compliance now runs inside the Toolkit in a background worker instead of opening a PowerShell window.
- Audit stdout/stderr and the completion summary are rendered directly in the Compliance tab.
- Added **Open Last Report** for the generated HTML report.
- The API key remains memory-only and is passed only to the child audit process environment.
- Fixed the displayed application version so the GUI now reports the actual v0.1.30 package version.
- Legacy More Tools wrappers still use their separate-window workflow, but now resolve `python.exe` when the GUI itself was launched with `pythonw.exe`.



## v0.1.29 client hardware offboarding

- Added **Client Offboarding - Unclaim** under **Hardware / Inventory**.
- Inventories every device in the selected client organization, including assigned and unassigned inventory.
- Supports individual multi-selection plus **Select All Devices** / **Clear Selection**.
- **Dry Run is mandatory** and saves a preflight report before any write action.
- Apply requires typed confirmation **UNCLAIM ALL**.
- Assigned devices are removed from their current networks first, then selected serials are released from the client organization in bounded batches.
- Re-reads the organization inventory and reports **PASS / FAIL per serial**; PASS means the serial was verified absent from the client organization.
- The client organization and networks are left intact. Licensing/subscriptions/billing are explicitly not changed.
- Hardware Holding is blocked as a Client Offboarding target.

## v0.1.27 brand-new hardware claim + inventory verification

- Renamed **Hardware Holding** to **Hardware / Inventory** and added a third workflow: **Claim New Hardware**.
- Paste or scan one or many Meraki serials (spaces, commas, semicolons, or new lines are accepted).
- **Dry Run is mandatory** before Claim, Move from Holding, or Return to Holding. If the serial, organization, direction, or target network changes, a new dry run is required.
- New-hardware preflight checks the selected destination inventory and scans accessible organizations for serials that are already claimed. Known conflicts are shown per device before any write.
- Apply requires the typed confirmation **`CLAIM HARDWARE`**.
- New/unseen serials are claimed into the selected organization first. The Toolkit then re-reads inventory to learn the model/product type and assigns only devices compatible with the selected network.
- If a newly claimed device is incompatible with the target network, it is **left unassigned in the destination organization** rather than being forced into the wrong network.
- Final verification re-reads both the destination organization inventory and the target network device list. The result is **PASS / FAIL per serial** and a TXT report under `Reports\HardwareInventory`.
- Existing Holding transfers now also re-read destination inventory + network for an explicit verified result.
- Small UI cleanup: the Post-Build Switches field now says **Management VLAN** instead of **Mgmt VLAN**.


## v0.1.26 clone-addressing safety + full Builder lock

- **Clone Existing no longer silently accepts the source IP scheme.** Appliance clones must explicitly choose **VLANs**, **Single LAN**, or **Keep source addressing**.
- When VLANs or Single LAN are chosen for a clone, the Toolkit reads the source addressing, blocks any replacement subnet that still overlaps the source, creates the clone, then immediately replaces and verifies the new addressing before the build is considered complete.
- **Keep source addressing** is deliberately labeled as the risky option and requires the stronger typed confirmation `CREATE SAME IP`.
- Clone mode mirrors the source product types in the Builder and locks those product checkboxes because Meraki determines them from the source network.
- After a successful build, the **entire Network Builder form is locked**: destination, mode, clone source, product controls, addressing, name, timezone, notes, and new-org admin inputs. **New Build / Reset** is required before any Builder field can be changed.
- The top-level organization selector remains usable for Post-Build and the rest of the toolkit.

## v0.1.25 quiet launcher

- Double-clicking `Launch-Meraki-MSP-Toolkit.bat` now starts the GUI without leaving CMD or PowerShell windows open behind it.
- Added a hidden VBScript/PowerShell launch chain that prefers `pyw.exe` / `pythonw.exe` and detaches immediately.
- Launcher failures are written to `Logs\Launcher.log`.
- Unhandled GUI/fatal Python exceptions are written to `Logs\Meraki-MSP-Toolkit-crash.log`.

## v0.1.24 connection status clarity
- The connection banner now reads **Connected · N organizations · Selected org: M networks** so the network count is clearly tied to the organization currently selected.

## v0.1.23 readable Post-Build device output
- Appliance WAN inspection now renders human-readable WAN1/WAN2 text instead of raw JSON.
- Switch current settings, preview, and verification reports now use MSP-friendly labels such as Management VLAN, IP assignment, Static IP, Gateway, and DNS.
- Switch verification reports now include an explicit PASS/FAIL plus the final re-read state.

## v0.1.21 WPA3 / PMF fix

- Wireless Post-Build now exposes **PMF / 802.11w** as Preserve current, Disabled, Enabled, or Required.
- Selecting **WPA3 only** with PMF on Preserve current automatically submits PMF **Required** in the same SSID update.
- Selecting **WPA3 Transition Mode** with PMF on Preserve current automatically submits PMF **Enabled** (not required).
- Explicit incompatible PMF choices are blocked before the API call instead of returning a Meraki HTTP 400.
- Wireless inventory now shows the current PMF state for each SSID.

## v0.1.20 Post-Build workspace

Post-Build is now the site-configuration workspace instead of one long alert-only screen. The selected network is shared across five internal sections:

- **Alerts** — existing alert destination + approved baseline Preview / Apply + Verify workflow.
- **Wireless** — inventory SSIDs, select one SSID, then preview/apply/verify name, enable state, PSK/open auth, WPA2/WPA3 mode, bridge/NAT addressing, VLAN assignment, band selection, visibility, and LAN isolation. PSKs are masked in the UI and never written to TXT reports.
- **Switches** — after switch hardware is assigned, inventory the switches and preview/apply/verify the selected switch name plus DHCP/static management-interface settings (IP, mask, gateway, up to two DNS servers, and management VLAN).
- **Appliance** — read-only WAN1/WAN2 inspection for assigned MX/Z hardware. WAN writes are intentionally not enabled yet; the read/verify path is being kept separate before adding ISP changes.
- **Compliance** — defaults to **This Network** with **This Organization** as the alternate scope. Fleet-wide Multi-Org Compliance remains under More Tools.

The Alerts verification report now uses **ACTIONS PERFORMED** after Apply rather than the future-tense “WHAT APPLY + VERIFY WILL DO.”

Every Wireless or Switch write requires its own preview and typed confirmation and is re-read from Meraki after the update for verification.



## v0.1.19 VLAN dialog layout fix

- Fixed the VLAN/IP Plan bottom action row collapsing into thin horizontal lines when the dialog height was constrained.
- The VLAN table is now the only vertically expanding row, so the bottom controls remain reserved and visible.
- Increased the dialog minimum height and made the action buttons full-size.
- Renamed the blue action to **Apply VLAN Plan** for clarity.


## v0.1.17 completed-build lockout

- A successful Network Builder run now enters a **COMPLETED** state.
- **Preview / Dry Run** and **CREATE** are disabled after success, and CREATE changes to **COMPLETED**.
- A new **New Build / Reset** button is enabled only after success and must be clicked before another build can be prepared.
- Reset is UI-only: it clears the builder form and never deletes or changes the organization/network that was already created.
- Failed/partial builds do **not** enter the completed lock; the existing partial-success safety behavior remains available for correction and review.

## v0.1.16 RFC1918 LAN safety guard

The Network Builder now blocks public/non-RFC1918 address space in Single-LAN and VLAN plans by default. Normal LAN plans must be wholly inside one of the three RFC1918 ranges:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

This catches common mistakes such as `192.178.1.0/24` or `192.188.1.0/24` before Preview/Create.

An **Advanced non-RFC1918 override** is available for legitimate special cases. When the final plan actually contains non-RFC1918 LAN space, the dry-run report prints a prominent warning and CREATE requires the stronger typed confirmation `CREATE PUBLIC`.

## v0.1.15 LAN subnet / mask input fix

The LAN/VLAN addressing dialogs now make the LAN/WAN distinction explicit and accept any of these subnet forms:

- `192.168.10.0/24`
- `192.168.10.1/24` (normalized to the network)
- `/24` or `24` (derived from the Appliance IP)
- `255.255.255.0` (derived from the Appliance IP)

`/31` and `/32` are rejected for normal LAN/VLAN plans with a message explaining that WAN/ISP addressing belongs elsewhere.

## v0.1.14 Network addressing / VLAN builder

The **Network Builder** now requires an explicit addressing choice whenever a No-Clone network includes an appliance product:

- **VLANs** — build an exact VLAN plan before creating the network.
- **Single LAN** — enter the LAN subnet and appliance IP.
- **Skip for now** — consciously leave Meraki default addressing in place for later work.
- **Clone Existing** — addressing is copied from the selected source network and is not separately rewritten.

The VLAN planner supports:

- VLAN ID and name
- IPv4 subnet/CIDR
- appliance/MX IP
- DHCP server, DHCP relay, or no DHCP response
- optional DHCP start/end pool
- lease duration
- DNS selection/custom value
- relay server IPs
- duplicate VLAN-ID checks
- overlapping-subnet checks
- appliance-IP and DHCP-pool validation

For a new No-Clone appliance network, the apply sequence is now:

1. Create the organization/admins when requested.
2. Create the network.
3. Apply the selected LAN/VLAN addressing plan.
4. For VLAN mode, create/update every planned VLAN, then remove only Meraki-created default VLANs that are not in the explicit plan.
5. Re-read Meraki and verify the final addressing state.
6. Save TXT and JSON verification reports under `Reports\NetworkBuilder`.
7. Continue to **Post-Build** for alert destinations/baseline verification, then **Hardware Holding** to move devices.

If network creation succeeds but addressing fails, the toolkit **does not delete or roll back the network**. It stops and reports the partial result so it can be inspected safely.

## v0.1.13 Short confirmations

Typed confirmations are now short and consistent while the exact target remains visible in the confirmation dialog:

- Create organization/network: `CREATE`
- Apply alert changes: `APPLY`
- Move hardware to customer: `MOVE`
- Return hardware to Holding: `RETURN`
- Delete network: `DELETE`
- Remove extra organization admins: `REMOVE`
- Delete organization: `DELETE ORG`

The toolkit still re-validates the selected object immediately before each destructive action.

Video 9 build of the Meraki MSP Toolkit.

## Launch
Double-click:

`Launch-Meraki-MSP-Toolkit.bat`

The launcher detaches immediately, so no CMD or PowerShell windows remain open behind the GUI. Launcher and crash logs are stored under `Logs\` when needed.

The Meraki API key is held in memory only and is not written to disk.

## Native tools
- Device Search
- Licensing Audit
- SSID Security Audit
- Alert Baseline dry run / apply / verify
- Network Builder: existing org or new org, No Clone or Clone Existing, with guarded LAN/VLAN addressing
- Optional additional admins during new-organization creation
- Post-Build workspace: Alerts, Site / Location, Wireless SSID setup, Switch management settings, Appliance WAN inspection, and scoped Compliance
- Post-Build Compliance defaults to the selected network, with selected-organization scope available
- Full multi-org compliance audit launcher
- Delete Network with exact-ID verification and three hardware-disposition paths: return to Hardware Holding, keep in customer inventory, or unclaim from customer organization
- Hardware / Inventory: Move from Holding, Return to Holding, bulk Claim New Hardware, and Client Offboarding unclaim with preflight + per-device verification
- Organization Cleanup: audit blockers, remove extra admins safely, delete org only when clear


## v0.1.23 Delete Network hardware disposition
The Delete Network tab now requires a hardware disposition plan before deletion:

1. **Return to Hardware Holding** — removes assigned devices from the customer network, releases them from the customer organization, claims them into Hardware Holding, maps/creates appropriate holding networks, verifies the final holding state, then deletes the empty network.
2. **Keep in Customer Organization Inventory** — removes assigned devices from the network, verifies they remain claimed but unassigned in the same customer organization, then deletes the empty network.
3. **Unclaim from Customer Organization** — removes assigned devices from the network, releases them from the customer organization, verifies the serials are absent from customer inventory, then deletes the empty network.

Preview locks the exact organization ID, network ID, selected disposition, and assigned serial list. If any of those change before Apply, deletion is aborted and a new preview is required.

## v0.1.12 Post-Build workflow
After a network is created, the Network Builder marks it `POST-BUILD PENDING`.

Open the **Post-Build** tab and select the network. The workflow is:

1. Enter one or more default alert destination email addresses.
2. Choose whether to apply the approved alert baseline.
3. Optionally require the Dashboard Settings Changed alert.
4. Set the expected offline-alert timeout (default 5 minutes).
5. Run **Preview / Dry Run**.
6. Review the proposed alert destination and baseline changes.
7. Run **APPLY + VERIFY** and type `APPLY`.
8. The toolkit re-reads the network alert settings, verifies the requested email destinations and baseline, checks enabled SSIDs for security review items, and saves a TXT verification report.

Existing default alert email destinations are preserved; requested addresses are merged into the existing list.

The **Alerts** section does not modify SSIDs, firmware, administrators, VLANs, firewall rules, VPN, or routing settings. Wireless and Switch changes are isolated in their own Post-Build sections and have separate previews/confirmations.

Reports are saved under:

`Reports\PostBuild`

## Safety model
Write/destructive actions remain guarded by dry-run/preview and typed confirmation. Network deletion and organization deletion are separate workflows. The toolkit does not silently roll back partially successful organization/network creation.


## v0.1.18
- Post-Build compliance scope now defaults to the selected network, with an option to audit the selected organization.
- The standalone Multi-Org Compliance tool remains fleet-wide.
- Compliance CLI now supports exact organization/network IDs and multiple required alert emails.


## v0.1.29 - Switch Apply + Verify hardening
- Switch Apply now writes only settings that actually changed in the Dry Run. A name-only change no longer rewrites the management interface.
- Result output always includes WRITE RESULT, Verification PASS/FAIL, and FINAL STATE.
- Device and management-interface read-backs are isolated so an unexpected API response cannot silently truncate the result.
- DNS read-back is normalized before comparison.
- Report-save failures are shown as warnings without hiding the verification result.
