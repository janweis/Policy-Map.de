# Policy Map

**Visual firewall policy analysis for FortiGate, FortiManager & Sophos.**
PowerShell export scripts, documentation and issue tracker for the browser-based **Policy Map** tool.
**100 % local — no firewall data ever leaves your browser.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
&nbsp;·&nbsp; 🌐 **[Open the tool](https://policy-map.it-explorations.de)**
&nbsp;·&nbsp; 🇩🇪 **[Deutsch](README.de.md)**

---

## What is this?

**Policy Map** turns a firewall rule base into an interactive map you can actually read: zones, objects,
allowed/blocked flows, risk highlighting and rule-quality findings — all rendered in your browser.

This repository holds the **PowerShell export scripts** that pull your rule base off the firewall and the
project's **documentation, issue tracker and feature requests**. The visualization tool itself runs at
**[policy-map.it-explorations.de](https://policy-map.it-explorations.de)** and is fully client-side.

> 🔒 **Privacy:** The scripts run on your machine and write a local JSON file. You load that file into the
> tool in your browser. Nothing is uploaded — your firewall configuration stays with you.

## Supported firewalls

| Vendor | Source | Export script |
|---|---|---|
| **FortiGate** (FortiOS REST API) | single device | `Export-FortiGateFirewallData.ps1` |
| **FortiManager** (JSON-RPC) | central manager, per ADOM/package | `Export-FortiManagerFirewallData.ps1` |
| **Sophos XGS** (XML API) | single device | `Export-SophosFirewallData.ps1` |

## How it works — 3 steps

1. **Export** — right-click the matching script in [`Export-Skripte/`](Export-Skripte/) →
   *Run with PowerShell*, and answer the prompts (firewall address, credentials). It writes
   `firewall-rohdaten-<vendor>.json` next to the script.
2. **Open** the tool at **[policy-map.it-explorations.de](https://policy-map.it-explorations.de)**.
3. **Import** → *Import file* and pick the JSON. The map renders instantly — entirely in your browser.

No Python, no installation, no account. Details and parameters: [`Export-Skripte/README.md`](Export-Skripte/README.md).

## Requirements

- **Windows PowerShell 5.1+** (or PowerShell 7+).
- Network access to the firewall / manager management API.
- Read access (an API token or a read-only account is enough).

## Issues & feature requests

Bugs and ideas belong here: **[open an issue](https://github.com/janweis/Policy-Map.de/issues/new/choose)**.
Questions and discussion: **[Discussions](https://github.com/janweis/Policy-Map.de/discussions)**.
Security reports: see **[SECURITY.md](SECURITY.md)** (private vulnerability reporting via GitHub).

## License

[MIT](LICENSE) © 2026 IT-Explorations
