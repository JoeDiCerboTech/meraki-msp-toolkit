# Meraki MSP Toolkit v0.2.1 - Regression Checklist

This is a short smoke/regression pass for the final package. Do not add new features during this pass.

1. Launch with `Launch-Meraki-MSP-Toolkit.bat`; confirm v0.2.1 and no persistent console window.
2. Connect / Refresh; confirm organization and selected-org network counts.
3. Network Builder dry run; verify `MERAKI BUILD PLAN`, addressing, physical site, and completed-build lock behavior.
4. Hardware / Inventory: verify exact source org, target org/network, serial, and stored site address. For Claim New Hardware, reject non-Meraki/hash-like serials before write; with a freshly unclaimed device verify organization inventory claim, propagation retry if needed, target-network assignment, and final inventory + network read-back.
5. Post-Build Alerts/Wireless/Switches/Appliance: Preview before write and explicit verification after write.
6. Site / Location: load stored site, apply/verify address, confirm blank names render as `(blank)` and configured MX/Z name is readable.
7. Compliance - This Network: confirm network findings are separate from organization context.
8. Admin Access: dry run add/remove; confirm no network/hardware changes are implied.
9. Delete Network: dry run exact org/network IDs and hardware disposition.
10. Org Cleanup: audit blockers; permanent delete only when READY FOR DELETE REVIEW.

Release acceptance: no unexpected write, no raw JSON in user-facing Post-Build reports, no `ERAKI` headings, no stale RC/version strings in executable/launcher UI, Claim New Hardware survives transient post-claim propagation delays, and no ZIP integrity errors.
