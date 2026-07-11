<#
.SYNOPSIS
  Exportiert NUR das Regelwerk + die Objekte einer SonicWall (SonicOS API) als ROH-JSON
  (vendor-getaggt, secret-frei) für die Firewall Policy Map.

.DESCRIPTION
  Sicherheit & Transparenz: Statt des (verschlüsselten/voll-umfänglichen) .exp-Backups zieht
  dieses Skript per READ-ONLY SonicOS-API NUR eine explizite Endpunkt-Allowlist:
    Zonen, Adress-Objekte/-Gruppen, Dienste/-Gruppen, IPv4-Access-Rules, IPv4-NAT-Policies.
  Es werden KEINE Passwörter, Zertifikate oder Schlüssel exportiert. Das Ergebnis ist eine kleine,
  im Texteditor prüfbare JSON-Datei "firewall-rohdaten-sonicwall.json".

  HINWEIS: Die SonicOS-API-Feldnamen variieren je Version (6.5 / 7.x). Das Skript mappt defensiv
  auf das STABILE Roh-Schema, das der Browser-Konverter (convertSonicwall) erwartet. Bei einer
  abweichenden Firmware ggf. die Zuordnungen unten anpassen — der Konverter bleibt unverändert.
  Voraussetzung: "SonicOS API" + "RFC-7616 Digest/Basic" am Gerät aktiviert (Manage → Appliance → Base Settings).

  Ablauf: Rechtsklick → "Mit PowerShell ausführen", Host/Zugang angeben → JSON entsteht →
  Policy Map → "Importieren → Datei importieren" (oder Drag and Drop). Konvertierung im Browser.

.EXAMPLE
  .\Export-SonicWallFirewallData.ps1 -FwHost 192.0.2.1 -User admin -Password <secure> -Insecure
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage = 'SonicWall-Host (IP oder FQDN, Management)')]
    [string]$FwHost,
    [Parameter(Mandatory)][string]$User,
    [Parameter(Mandatory)][SecureString]$Password,
    [string]$OutFile = (Join-Path $PSScriptRoot 'firewall-rohdaten-sonicwall.json'),
    [switch]$Insecure,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'
$SkipCert = $Insecure.IsPresent
if ($SkipCert) { Write-Warning 'SSL-Zertifikatsvalidierung deaktiviert (-Insecure)!' }

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

$base = "https://$FwHost/api/sonicos"
$pw = [System.Net.NetworkCredential]::new('', $Password).Password
$b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$User`:$pw"))
$script:sess = $null

function ToArray($x) { if ($null -eq $x) { @() } else { @($x) } }

function MaskToPrefix($mask) {
    if (-not $mask) { return 32 }
    if ("$mask" -match '^\d+$') { return [int]$mask }
    $bits = 0; foreach ($o in "$mask".Split('.')) { $b = [int]$o; while ($b) { $bits += ($b -band 1); $b = $b -shr 1 } }
    return $bits
}

# READ-ONLY GET (mit Session); leeres Objekt bei Nichtverfügbarkeit
function Get-Sonic ([string]$Path) {
    try {
        $p = @{ Uri = "$base$Path"; Method = 'Get'; Headers = @{ Accept = 'application/json' }; WebSession = $script:sess; UseBasicParsing = $true }
        if (-not $script:PS5 -and $script:SkipCert) { $p.SkipCertificateCheck = $true }
        return Invoke-RestMethod @p
    }
    catch {
        Write-Host "[INFO] $Path nicht verfügbar - übersprungen ($($_.Exception.Message))" -ForegroundColor DarkGray
        return $null
    }
}

# Wrapper-tolerant: liefert die Objekt-Liste unabhängig von der Verschachtelung
function PickList($resp, [string[]]$keys) {
    foreach ($k in $keys) {
        $cur = $resp
        $ok = $true
        foreach ($seg in $k.Split('.')) { if ($null -ne $cur -and $null -ne $cur.$seg) { $cur = $cur.$seg } else { $ok = $false; break } }
        if ($ok -and $null -ne $cur) { return ToArray $cur }
    }
    return @()
}

# Single-Address-Referenz (SonicOS source/destination/service) → Namensliste
function RefNames($ref) {
    if ($null -eq $ref) { return @('any') }
    if ($ref.any) { return @('any') }
    $out = @()
    foreach ($v in (ToArray $ref.name)) { if ($v) { $out += [string]$v } }
    foreach ($v in (ToArray $ref.group)) { if ($v) { $out += [string]$v } }
    if (-not $out.Count) { return @('any') }
    return $out
}

#
# Authentifizierung (Basic) + READ-ONLY Abrufe
#
Write-Host "[INFO] Anmeldung an SonicOS-API $FwHost ..." -ForegroundColor Cyan
$ap = @{ Uri = "$base/auth"; Method = 'Post'; Headers = @{ Authorization = "Basic $b64"; Accept = 'application/json' }
    SessionVariable = 'sess'; UseBasicParsing = $true }
if (-not $PS5 -and $SkipCert) { $ap.SkipCertificateCheck = $true }
Invoke-WebRequest @ap | Out-Null
$script:sess = $sess

Write-Host '[INFO] Lade Zonen / Objekte / Regeln (read-only) ...' -ForegroundColor Cyan
$zResp  = Get-Sonic '/zone'
$aResp  = Get-Sonic '/address-object/ipv4'
$agResp = Get-Sonic '/address-group/ipv4'
$sResp  = Get-Sonic '/service-object'
$sgResp = Get-Sonic '/service-group'
$rResp  = Get-Sonic '/access-rule/ipv4'
$nResp  = Get-Sonic '/nat-policy/ipv4'

# ── In das stabile Roh-Schema normalisieren ─────────────────────────────────────
$zones = foreach ($z in (PickList $zResp @('zone'))) { [string]$z.name }

$addresses = foreach ($a in (PickList $aResp @('address_object.ipv4', 'address_objects', 'address_object'))) {
    $type = 'host'; $value = ''
    if ($a.host) { $type = 'host'; $value = [string]$a.host.ip }
    elseif ($a.network) { $type = 'network'; $value = "$($a.network.subnet)/$(MaskToPrefix $a.network.mask)" }
    elseif ($a.range) { $type = 'range'; $value = "$($a.range.begin)-$($a.range.end)" }
    [ordered]@{ name = [string]$a.name; zone = [string]$a.zone; type = $type; value = $value }
}

$addrgroups = foreach ($g in (PickList $agResp @('address_group.ipv4', 'address_groups', 'address_group'))) {
    $mem = @()
    foreach ($m in (ToArray $g.address_object.ipv4)) { if ($m.name) { $mem += [string]$m.name } }
    foreach ($m in (ToArray $g.address_group.ipv4)) { if ($m.name) { $mem += [string]$m.name } }
    [ordered]@{ name = [string]$g.name; member = @($mem) }
}

$services = foreach ($s in (PickList $sResp @('service_object', 'service_objects'))) {
    $proto = ''; $port = ''
    if ($s.tcp) { $proto = 'TCP'; $port = if ($s.tcp.begin) { "$($s.tcp.begin)" } else { "$($s.tcp.port)" } }
    elseif ($s.udp) { $proto = 'UDP'; $port = if ($s.udp.begin) { "$($s.udp.begin)" } else { "$($s.udp.port)" } }
    [ordered]@{ name = [string]$s.name; proto = $proto; port = $port }
}

$servicegroups = foreach ($g in (PickList $sgResp @('service_group', 'service_groups'))) {
    $mem = @()
    foreach ($m in (ToArray $g.service_object)) { if ($m.name) { $mem += [string]$m.name } }
    foreach ($m in (ToArray $g.service_group)) { if ($m.name) { $mem += [string]$m.name } }
    [ordered]@{ name = [string]$g.name; member = @($mem) }
}

$policies = foreach ($r in (PickList $rResp @('access_rule.ipv4', 'access_rules', 'access_rule'))) {
    [ordered]@{
        name        = [string]$r.name
        uuid        = [string]$r.uuid
        from        = [string]$r.from
        to          = [string]$r.to
        source      = @(RefNames $r.source.address)
        destination = @(RefNames $r.destination.address)
        service     = @(RefNames $r.service)
        action      = [string]$r.action
        enabled     = -not ($r.enable -eq $false)
        comment     = [string]$r.comment
    }
}

# Inbound-DNAT: original destination -> translated destination (best effort; Feldnamen je Version)
$nat = foreach ($n in (PickList $nResp @('nat_policy.ipv4', 'nat_policies', 'nat_policy'))) {
    $td = [string]($n.translated_destination.name); if (-not $td) { $td = [string]$n.translated_destination }
    if (-not $td -or $td -eq 'original') { continue }
    $od = [string]($n.original_destination.name); if (-not $od) { $od = [string]$n.original_destination }
    $tp = [string]($n.translated_service.name); if (-not $tp) { $tp = '' }
    [ordered]@{ name = [string]$n.name; origDest = $od; transDest = $td; transPort = $tp; proto = '' }
}

$output = [ordered]@{
    vendor        = 'sonicwall'
    zones         = @($zones)
    addresses     = @($addresses)
    addrgroups    = @($addrgroups)
    services      = @($services)
    servicegroups = @($servicegroups)
    policies      = @($policies)
    nat           = @($nat)
}

$output | ConvertTo-Json -Depth 30 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "[OK] Geschrieben: $OutFile" -ForegroundColor Green
Write-Host ("     $(@($zones).Count) Zonen, $(@($addresses).Count) Adressen, $(@($policies).Count) Regeln - keine Secrets.") -ForegroundColor Green
if (-not $NoOpen) { Write-Host '     Naechster Schritt: Policy Map -> "Importieren -> Datei importieren" -> diese Datei.' -ForegroundColor Cyan }
