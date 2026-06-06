<!-- TODO vor Veröffentlichung: jedes <OWNER> durch das echte GitHub-Konto/die Org ersetzen. -->

# Policy Map

**Visuelle Firewall-Regelwerk-Analyse für FortiGate, FortiManager & Sophos.**
PowerShell-Export-Skripte, Dokumentation und Issue-Tracker zum browserbasierten **Policy-Map**-Tool.
**100 % lokal — deine Firewall-Daten verlassen den Browser nie.**

[![Lizenz: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
&nbsp;·&nbsp; 🌐 **[Tool öffnen](https://policy-map.it-explorations.de)**
&nbsp;·&nbsp; 🇬🇧 **[English](README.md)**

---

## Worum geht es?

**Policy Map** macht aus einem Firewall-Regelwerk eine interaktive, lesbare Karte: Zonen, Objekte,
erlaubte/blockierte Verbindungen, Risiko-Hervorhebung und Regelwerkqualitäts-Befunde — alles im Browser
gerendert.

Dieses Repository enthält die **PowerShell-Export-Skripte**, die das Regelwerk von der Firewall abrufen,
sowie die **Dokumentation, den Issue-Tracker und die Feature-Requests** des Projekts. Das
Visualisierungs-Tool selbst läuft unter **[policy-map.it-explorations.de](https://policy-map.it-explorations.de)**
und arbeitet vollständig clientseitig.

> 🔒 **Datenschutz:** Die Skripte laufen auf deinem Rechner und schreiben eine lokale JSON-Datei. Diese lädst
> du im Browser ins Tool. Es wird nichts hochgeladen — deine Firewall-Konfiguration bleibt bei dir.

## Unterstützte Firewalls

| Hersteller | Quelle | Export-Skript |
|---|---|---|
| **FortiGate** (FortiOS REST API) | einzelnes Gerät | `Export-FortiGateFirewallData.ps1` |
| **FortiManager** (JSON-RPC) | zentraler Manager, je ADOM/Package | `Export-FortiManagerFirewallData.ps1` |
| **Sophos XGS** (XML-API) | einzelnes Gerät | `Export-SophosFirewallData.ps1` |

## So funktioniert's — 3 Schritte

1. **Exportieren** — passendes Skript in [`Export-Skripte/`](Export-Skripte/) per Rechtsklick →
   *Mit PowerShell ausführen*, dann die Fragen beantworten (Firewall-Adresse, Zugangsdaten). Es entsteht
   `firewall-rohdaten-<hersteller>.json` neben dem Skript.
2. **Tool öffnen** unter **[policy-map.it-explorations.de](https://policy-map.it-explorations.de)**.
3. **Importieren** → *Datei importieren* und die JSON wählen. Die Karte wird sofort gerendert — komplett im Browser.

Kein Python, keine Installation, kein Konto. Details und Parameter: [`Export-Skripte/README.md`](Export-Skripte/README.md).

## Voraussetzungen

- **Windows PowerShell 5.1+** (oder PowerShell 7+).
- Netzwerkzugriff auf die Management-API der Firewall / des Managers.
- Lesezugriff (ein API-Token oder ein Read-only-Konto genügt).

## Issues & Feature-Requests

Fehler und Ideen gehören hierher: **[Issue anlegen](https://github.com/<OWNER>/PolicyMap/issues/new/choose)**.
Fragen und Austausch: **[Discussions](https://github.com/<OWNER>/PolicyMap/discussions)**.
Sicherheitsmeldungen: siehe **[SECURITY.md](SECURITY.md)** (private Meldung über GitHub).

## Lizenz

[MIT](LICENSE) © 2026 IT-Explorations
