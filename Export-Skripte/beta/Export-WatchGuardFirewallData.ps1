<#
.SYNOPSIS
  Bereitet einen WatchGuard-Firebox/XTM-Konfigurationsexport (Policy-Manager-XML) für die
  Firewall Policy Map auf: entfernt Geheimnisse und schreibt eine ladbare, secret-freie XML-Datei.

.BESCHREIBUNG (für Anwender ohne Vorkenntnisse)
  WatchGuard bietet — anders als FortiGate/Sophos — KEINE Management-API, die das Regelwerk
  liefert. Die Konfiguration wird als XML exportiert:
    * WatchGuard Policy Manager:  Datei > Speichern > "In XML-Datei" (File > Save > To XML File), ODER
    * Fireware Web UI:            System > Konfigurationsdatei > herunterladen.

  So nutzt du dieses Skript:
    1. Konfiguration wie oben als XML exportieren.
    2. Rechtsklick auf diese Datei -> "Mit PowerShell ausführen".
    3. Die exportierte XML auswählen (Dateidialog) bzw. den Pfad eingeben.
    4. Es entsteht "firewall-rohdaten-watchguard.xml" — OHNE Passwörter/Schlüssel.
    5. firewall_viz.html im Browser öffnen -> "Importieren -> Datei importieren" -> diese Datei.

  Es wird KEIN Python und KEIN Geräte-Login benötigt — die Aufbereitung passiert lokal,
  die Konvertierung im Browser.

.EXAMPLE
  .\Export-WatchGuardFirewallData.ps1
  .\Export-WatchGuardFirewallData.ps1 -InFile .\firebox.xml
  .\Export-WatchGuardFirewallData.ps1 -InFile .\firebox.xml -KeepSecrets -NoOpen
#>
[CmdletBinding()]
param(
    [string]$InFile,
    [string]$OutFile,
    [switch]$KeepSecrets,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

# ── Eingabedatei bestimmen (Dateidialog -> Read-Host-Fallback) ────────────────
if (-not $InFile) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $dlg = [System.Windows.Forms.OpenFileDialog]::new()
        $dlg.Title  = 'WatchGuard-Konfiguration (Policy-Manager-XML) auswählen'
        $dlg.Filter = 'WatchGuard-XML (*.xml)|*.xml|Alle Dateien (*.*)|*.*'
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $InFile = $dlg.FileName }
    } catch { }
    if (-not $InFile) { $InFile = Read-Host 'Pfad zur exportierten WatchGuard-XML (<profile>...)' }
}
if (-not $InFile)             { throw 'Keine Eingabedatei angegeben.' }
if (-not (Test-Path $InFile)) { throw "Datei nicht gefunden: $InFile" }
if (-not $OutFile)            { $OutFile = Join-Path $PSScriptRoot 'firewall-rohdaten-watchguard.xml' }

# ── Sicheres XML-Laden: DTD verbieten, keinen externen Resolver zulassen ──────
# Schützt vor XXE und Entity-Expansion-DoS (Billion-Laughs) durch eine bösartige/
# manipulierte Konfigurationsdatei. (Pendant zu defusedxml / dem Sophos-Skript.)
function ConvertTo-SafeXmlFile ([string]$Path) {
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver   = $null
    $reader = [System.Xml.XmlReader]::Create($Path, $settings)
    try {
        $doc = [System.Xml.XmlDocument]::new()
        $doc.PreserveWhitespace = $true
        $doc.Load($reader)
        return $doc
    } finally { $reader.Dispose() }
}

Write-Host "[INFO] Lese WatchGuard-XML: $InFile" -ForegroundColor Cyan
$doc = ConvertTo-SafeXmlFile $InFile

# ── Validierung: echte WatchGuard-Policy-Manager-XML? ────────────────────────
# Muss der Browser-Erkennung entsprechen (parseImportText): <profile> mit
# <policy-list> UND <from-alias-list>.
$root = $doc.DocumentElement
$hasPolicyList = $doc.SelectNodes('//*[local-name()="policy-list"]').Count -gt 0
$hasFromAlias  = $doc.SelectNodes('//*[local-name()="from-alias-list"]').Count -gt 0
if (-not $root -or $root.LocalName -ne 'profile' -or -not $hasPolicyList -or -not $hasFromAlias) {
    throw 'Keine gültige WatchGuard-Policy-Manager-XML (erwartet <profile> mit <policy-list> und <from-alias-list>). Bitte die per "Datei > Speichern > In XML-Datei" exportierte Konfiguration angeben.'
}

# ── Geheimnisse entfernen (secret-freies Import-Artefakt) ─────────────────────
# Leert den Text von Blatt-Elementen, deren Tag-Name auf ein Geheimnis hindeutet.
# Die Denylist ist bewusst eng gefasst und kollidiert mit KEINEM vom Konverter
# gelesenen Struktur-Tag (interface-list/address-group-list/service-list/alias-list/
# policy-list). Struktur bleibt vollständig erhalten -> Konvertierung unverändert.
$secretRe  = '(?i)password|passwd|passphrase|secret|psk|pre-?shared|priv(ate)?-?key|shared-?key|key-?str|comm-?string|community|auth-?key|api-?key|api-?token|token|credential|wpa|wep'
# Metadaten mit secret-ähnlichem Namen, aber ohne Geheimnis-Inhalt NICHT leeren
# (z.B. min-password-length, auth-key-length, feature-key-url, *-expiration).
$excludeRe = '(?i)length|expiration|url$|enabled?$|-list$|-id$|count$|timeout|interval|version|size$|-len$|method|mode$|type$'
$stripped = 0
if (-not $KeepSecrets) {
    foreach ($el in $doc.SelectNodes('//*')) {
        if ($el.LocalName -match $secretRe -and $el.LocalName -notmatch $excludeRe -and -not $el.SelectSingleNode('*') -and $el.InnerText.Trim()) {
            $el.InnerText = ''
            $stripped++
        }
    }
    Write-Host "[INFO] Geheimnisse entfernt: $stripped Element(e)" -ForegroundColor Cyan
} else {
    Write-Warning 'Secret-Bereinigung deaktiviert (-KeepSecrets) — die Ausgabedatei enthält Klartext-Geheimnisse.'
}

# ── Schreiben (UTF-8 ohne BOM, Struktur/Deklaration erhalten) ────────────────
$xws = [System.Xml.XmlWriterSettings]::new()
$xws.Encoding = [System.Text.UTF8Encoding]::new($false)
$writer = [System.Xml.XmlWriter]::Create($OutFile, $xws)
try { $doc.Save($writer) } finally { $writer.Dispose() }

# Nur die direkten <profile>-Kindlisten zählen (wie der Konverter; nicht die in
# <abs-policy> verschachtelten <policy-list>).
$polCount   = $root.SelectNodes('*[local-name()="policy-list"]/*[local-name()="policy"]').Count
$aliasCount = $root.SelectNodes('*[local-name()="alias-list"]/*[local-name()="alias"]').Count
Write-Host "[OK] Geschrieben: $OutFile" -ForegroundColor Green
Write-Host ("     $polCount Policies, $aliasCount Aliase, $stripped Geheimnis-Feld(er) geleert") -ForegroundColor Green
Write-Host '     Nächster Schritt: Policy Map -> "Importieren -> Datei importieren" -> diese Datei.' -ForegroundColor Cyan

$htmlPath = Join-Path $PSScriptRoot 'firewall_viz.html'
if (-not $NoOpen -and (Test-Path $htmlPath)) {
    if ((Read-Host 'Visualisierung jetzt im Browser öffnen? (j/n)') -match '^[jJyY]') {
        Start-Process $htmlPath
        Write-Host '   -> dort: "Importieren -> Datei importieren" und die erzeugte XML-Datei wählen.' -ForegroundColor Cyan
    }
}
