<#
.SYNOPSIS
  Exportiert NUR die visualisierungs-relevanten Teile einer Palo Alto (PAN-OS) Firewall
  über die XML-API als minimale, SECRET-FREIE config.xml für die Firewall Policy Map.

.DESCRIPTION
  Sicherheit & Transparenz: Statt des vollen Backups ("Export named configuration", enthaelt
  Admin-Hashes, Zertifikate mit Private Keys, IKE-PSKs ...) zieht dieses Skript per READ-ONLY
  XML-API NUR eine explizite xpath-Allowlist:
    - Zonen, Adress-/Dienst-Objekte und -Gruppen (vsys + shared)
    - Security- und NAT-Regelwerk
  Es werden KEINE Passwoerter, Zertifikate, Schluessel, deviceconfig oder mgt-config exportiert.
  Das Ergebnis ist eine kleine, im Texteditor pruefbare config.xml.

  Ablauf:
    1. Rechtsklick auf diese Datei -> "Mit PowerShell ausfuehren".
    2. Host und Zugang angeben:
         - Bevorzugt einen vorhandenen API-Key (-ApiKey).
         - Sonst Benutzer + Passwort -> das Skript holt einen API-Key (keygen).
    3. Es entsteht "firewall-rohdaten-panos.xml".
    4. Policy Map im Browser oeffnen -> "Importieren -> Datei importieren" -> diese Datei waehlen
       (oder per Drag and Drop). Die Aufbereitung passiert vollstaendig im Browser; es wird
       nichts hochgeladen.

.EXAMPLE
  .\Export-PaloAltoFirewallData.ps1 -FwHost 192.0.2.1 -ApiKey <KEY>
  .\Export-PaloAltoFirewallData.ps1 -FwHost 192.0.2.1 -User admin -Password <secure>   # keygen
  .\Export-PaloAltoFirewallData.ps1 -FwHost 192.0.2.1 -ApiKey <KEY> -Vsys vsys2 -Insecure
#>
[CmdletBinding(DefaultParameterSetName = 'Key')]
param(
    [Parameter(Mandatory, HelpMessage = 'PAN-OS-Host (IP oder FQDN, Management-Schnittstelle)')]
    [string]$FwHost,

    [Parameter(Mandatory, ParameterSetName = 'Key')]
    [string]$ApiKey,

    [Parameter(Mandatory, ParameterSetName = 'UserPw')]
    [string]$User,
    [Parameter(Mandatory, ParameterSetName = 'UserPw')]
    [SecureString]$Password,

    [string]$Vsys = 'vsys1',
    [string]$OutFile = (Join-Path $PSScriptRoot 'firewall-rohdaten-panos.xml'),
    [switch]$Insecure,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

$SkipCert = $Insecure.IsPresent
if ($SkipCert) { Write-Warning 'SSL-Zertifikatsvalidierung deaktiviert (-Insecure)!' }

# Windows PowerShell 5.1 kennt -SkipCertificateCheck nicht -> TLS 1.2 erzwingen und
# die Zertifikatspruefung bei -Insecure prozessweit abschalten.
$PS5 = $PSVersionTable.PSVersion.Major -lt 6
if ($PS5) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ($SkipCert -and -not ('TrustAllCertsPolicy' -as [type])) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
    }
    if ($SkipCert) { [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy }
}

# Sicheres XML-Parsing: DTD-Verarbeitung verbieten und keinen externen Resolver
# zulassen → schützt vor XXE und Entity-Expansion-DoS (Billion-Laughs) durch eine
# bösartige/kompromittierte Gegenstelle.
function ConvertTo-SafeXml ([string]$Content) {
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver   = $null
    $sr = [System.IO.StringReader]::new($Content)
    try {
        $reader = [System.Xml.XmlReader]::Create($sr, $settings)
        try {
            $doc = [System.Xml.XmlDocument]::new()
            $doc.Load($reader)
            return $doc
        } finally { $reader.Dispose() }
    } finally { $sr.Dispose() }
}

# Ein API-Aufruf -> sicher eingelesenes [xml]-Response (Status geprueft).
# Parameter gehen per POST-Body (NICHT in die URL), der API-Key als X-PAN-KEY-Header —
# so landen Key/Passwort nicht in der URL und damit nicht in Transcript-/Proxy-Logs
# oder in Exception-Meldungen (die sonst die Request-URL samt Secret enthalten).
function Invoke-PanApi ([hashtable]$Query) {
    $body = @{}
    foreach ($kv in $Query.GetEnumerator()) { $body[[string]$kv.Key] = [string]$kv.Value }
    $headers = @{}
    if ($body.ContainsKey('key')) { $headers['X-PAN-KEY'] = $body['key']; [void]$body.Remove('key') }
    $p = @{ Uri = "https://$FwHost/api/"; Method = 'Post'; Body = $body; UseBasicParsing = $true }
    if ($headers.Count) { $p.Headers = $headers }
    if (-not $script:PS5 -and $script:SkipCert) { $p.SkipCertificateCheck = $true }
    $resp = Invoke-WebRequest @p
    $xml = ConvertTo-SafeXml $resp.Content
    if ($xml.response.status -ne 'success') {
        $msg = $xml.response.result.msg
        if (-not $msg) { $msg = $xml.response.msg }
        throw "PAN-OS-API-Fehler: $msg"
    }
    return $xml
}

# Running-Config an einem xpath holen -> InnerXml des <result> (oder '' wenn leer/Fehler)
function Get-PanNode ([string]$Xpath) {
    try {
        $xml = Invoke-PanApi @{ type = 'config'; action = 'show'; xpath = $Xpath; key = $script:ApiKey }
        $r = $xml.response.result
        if ($r) { return [string]$r.InnerXml } else { return '' }
    }
    catch {
        Write-Host "[INFO] $Xpath nicht verfuegbar - uebersprungen ($($_.Exception.Message))" -ForegroundColor DarkGray
        return ''
    }
}

#
# Authentifizierung
#
if ($PSCmdlet.ParameterSetName -eq 'UserPw') {
    Write-Host "[INFO] Hole API-Key (keygen) von $FwHost ..." -ForegroundColor Cyan
    $pw = [System.Net.NetworkCredential]::new('', $Password).Password
    $kx = Invoke-PanApi @{ type = 'keygen'; user = $User; password = $pw }
    $ApiKey = [string]$kx.response.result.key
    if (-not $ApiKey) { throw 'Kein API-Key erhalten.' }
}

#
# Daten holen (READ-ONLY, explizite Allowlist - KEINE Secrets)
#
$base = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$Vsys']"

Write-Host "[INFO] Lade Zonen / Objekte / Regelwerk (vsys=$Vsys) ..." -ForegroundColor Cyan
$zone      = Get-PanNode "$base/zone"
$addr      = Get-PanNode "$base/address"
$addrGrp   = Get-PanNode "$base/address-group"
$svc       = Get-PanNode "$base/service"
$svcGrp    = Get-PanNode "$base/service-group"
$security  = Get-PanNode "$base/rulebase/security"
$nat       = Get-PanNode "$base/rulebase/nat"

Write-Host '[INFO] Lade gemeinsame Objekte (<shared>) ...' -ForegroundColor Cyan
$shAddr    = Get-PanNode "/config/shared/address"
$shAddrGrp = Get-PanNode "/config/shared/address-group"
$shSvc     = Get-PanNode "/config/shared/service"
$shSvcGrp  = Get-PanNode "/config/shared/service-group"

#
# Minimale, secret-freie config.xml zusammensetzen (vom Browser-Konverter konsumiert)
#
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('<?xml version="1.0"?>')
[void]$sb.AppendLine('<!-- Firewall Policy Map: minimaler PAN-OS-Export (nur Regelwerk/Objekte, KEINE Secrets). Erzeugt von Export-PaloAltoFirewallData.ps1 -->')
[void]$sb.AppendLine('<config version="exported">')
[void]$sb.AppendLine('  <shared>' + $shAddr + $shAddrGrp + $shSvc + $shSvcGrp + '</shared>')
[void]$sb.AppendLine('  <devices><entry name="localhost.localdomain"><vsys><entry name="' + $Vsys + '">')
[void]$sb.AppendLine('    ' + $zone + $addr + $addrGrp + $svc + $svcGrp)
[void]$sb.AppendLine('    <rulebase>' + $security + $nat + '</rulebase>')
[void]$sb.AppendLine('  </entry></vsys></entry></devices>')
[void]$sb.AppendLine('</config>')

$sb.ToString() | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "[OK] Geschrieben: $OutFile" -ForegroundColor Green
Write-Host '     Enthaelt NUR Zonen/Objekte/Regelwerk - keine Passwoerter, Zertifikate oder Keys.' -ForegroundColor Green

if (-not $NoOpen) {
    Write-Host '     Naechster Schritt: Policy Map oeffnen -> "Importieren -> Datei importieren" -> diese Datei.' -ForegroundColor Cyan
}
