# Security Policy / Sicherheitsrichtlinie

## Reporting a vulnerability / Schwachstellen melden

**EN —** Please report security issues **privately** via GitHub:
*Security → Report a vulnerability* (GitHub Private Vulnerability Reporting). Do **not** open a public
issue for security problems. There is intentionally **no email contact** — reporting runs through GitHub.

**DE —** Bitte melde Sicherheitsprobleme **privat** über GitHub:
*Security → Report a vulnerability* (private Schwachstellenmeldung). Bitte **kein** öffentliches Issue für
Sicherheitsthemen anlegen. Es gibt bewusst **keinen E-Mail-Kontakt** — die Meldung läuft über GitHub.

> Maintainers: enable *Settings → Code security → Private vulnerability reporting* for this repository.

## Scope — what these scripts do / Was die Skripte tun

The export scripts (`Export-Skripte/*.ps1`) are **read-only data extractors**:

- They connect to the firewall / manager **management API over HTTPS** and **read** the rule base only —
  they never write or change configuration.
- Credentials are requested as a **`SecureString`** and used only for the single API session. **Nothing is
  stored**: no passwords, tokens or configuration are written to disk except the rule-base export you asked for.
- The output file `firewall-rohdaten-<vendor>.json` **contains your firewall rule base** — treat it as
  sensitive. Do not attach it to public issues; share only redacted/example data.
- `-Insecure` disables TLS certificate validation and is meant for **lab use only**. Never combine it with
  production or untrusted networks.

## Out of scope

The browser visualization tool and any server-side hosting are **not** part of this repository. This repo
covers the export scripts and project documentation only.
