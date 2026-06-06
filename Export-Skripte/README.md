# Export-Skripte / Export scripts

**DE —** Jedes Skript ruft die Management-API einer Firewall lesend ab und schreibt eine vendor-getaggte
ROH-JSON neben das Skript. Diese Datei lädst du im Tool über **Importieren → Datei importieren**.
Fehlende Pflichtangaben werden **interaktiv abgefragt** — ein einfacher Rechtsklick → *Mit PowerShell
ausführen* genügt.

**EN —** Each script reads a firewall's management API and writes a vendor-tagged raw JSON next to the
script. Load that file in the tool via **Import → Import file**. Missing required values are **prompted
interactively** — a simple right-click → *Run with PowerShell* is enough.

## Parameter / parameters

| Skript / Script | Pflicht / Required | Optional | Auth | Ausgabe / Output |
|---|---|---|---|---|
| `Export-FortiGateFirewallData.ps1` | `-FwHost` | `-User` · `-Vdom` (root) · `-Insecure` · `-NoOpen` | `-User` leer ⇒ API-Token, sonst Session-Login | `firewall-rohdaten-fortigate.json` |
| `Export-FortiManagerFirewallData.ps1` | `-FwHost` · `-User` · `-Adom` | `-Package` · `-Device` · `-Vdom` (root) · `-Insecure` · `-NoOpen` | Session-Login | `firewall-rohdaten-fortimanager.json` |
| `Export-SophosFirewallData.ps1` | `-FwHost` · `-User` | `-Insecure` · `-NoOpen` | Session-Login | `firewall-rohdaten-sophos.json` |

- **`-FwHost`** — IP or FQDN of the firewall / manager.
- **`-Password`** — accepted as `SecureString`; if omitted you are prompted (hidden input).
- **`-NoOpen`** — do not open the output folder afterwards.
- **`-Insecure`** — disables TLS certificate validation. **Lab only** — see [`../SECURITY.md`](../SECURITY.md).

## Beispiele / examples

```powershell
# FortiGate — API token (user left empty), prompted for the token
.\Export-FortiGateFirewallData.ps1 -FwHost 192.168.1.99 -Vdom root

# FortiGate — session login
.\Export-FortiGateFirewallData.ps1 -FwHost 192.168.1.99 -User admin

# FortiManager — choose ADOM
.\Export-FortiManagerFirewallData.ps1 -FwHost 192.168.1.1 -User admin -Adom root

# Sophos XGS
.\Export-SophosFirewallData.ps1 -FwHost 192.168.1.1 -User admin
```

> Die Ausgabedatei enthält dein **Regelwerk** — wie eine Konfigurationssicherung behandeln und nicht an
> öffentliche Issues anhängen. / The output file contains your **rule base** — treat it like a config
> backup and never attach it to public issues.
