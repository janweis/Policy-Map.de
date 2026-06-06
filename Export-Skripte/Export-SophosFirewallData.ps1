<#
.SYNOPSIS
  Exportiert Sophos-XGS-Firewall-Daten als ROH-JSON (vendor-getaggt) für die Firewall Policy Map.

.BESCHREIBUNG (für Anwender ohne Vorkenntnisse)
  1. Rechtsklick auf diese Datei → "Mit PowerShell ausführen".
  2. Die Fragen beantworten (Sophos-Adresse, Benutzer, Passwort).
  3. Es entsteht eine Datei "firewall-rohdaten-sophos.json".
  4. firewall_viz.html im Browser öffnen → "Importieren → Datei importieren" → diese Datei wählen.

  Es wird KEIN Python benötigt — die Aufbereitung passiert direkt im Browser.

.EXAMPLE
  .\Export-SophosFirewallData.ps1
  .\Export-SophosFirewallData.ps1 -FwHost 192.168.1.1 -User admin
#>
[CmdletBinding()]
param(
    [string]$FwHost,
    [string]$User,
    [SecureString]$Password,
    [string]$OutFile,
    [switch]$Insecure,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

if (-not $FwHost)   { $FwHost   = Read-Host 'Sophos-XGS-Host (IP oder FQDN)' }
if (-not $User)     { $User     = Read-Host 'Benutzer' }
if (-not $Password) { $Password = Read-Host 'Passwort' -AsSecureString }
if (-not $OutFile)  { $OutFile  = Join-Path $PSScriptRoot 'firewall-rohdaten-sophos.json' }

$SkipCert = $Insecure.IsPresent
if ($SkipCert) { Write-Warning 'SSL-Zertifikatsvalidierung deaktiviert (-Insecure)!' }

$BaseUrl = "https://${FwHost}:4444/webconsole/APIController"
Add-Type -AssemblyName System.Web

function Invoke-SophosAPI {
    param([string]$ReqXml)
    $body = "reqxml=$([System.Web.HttpUtility]::UrlEncode($ReqXml))"
    $resp = Invoke-WebRequest -Uri $BaseUrl -Method POST -Body $body `
        -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -SkipCertificateCheck:$script:SkipCert
    return [xml]$resp.Content
}

function Get-SophosEntities {
    param([string]$EntityType)
    $resp = Invoke-SophosAPI -ReqXml "<Request><Get><$EntityType/></Get></Request>"
    return $resp.Response.$EntityType
}

# Sicheres Array auch bei 0/1 Elementen
function ToArray($x) { if ($null -eq $x) { @() } else { @($x) } }

# ── Login (Credentials XML-escapen) ──────────────────────────────────────────
$UserEsc = [System.Security.SecurityElement]::Escape($User)
$PassEsc = [System.Security.SecurityElement]::Escape([System.Net.NetworkCredential]::new('', $Password).Password)
$loginResp = Invoke-SophosAPI -ReqXml "<Request><Login><Username>$UserEsc</Username><Password>$PassEsc</Password></Login></Request>"
if ($loginResp.Response.Login.status -ne '200') {
    throw "Sophos-Login fehlgeschlagen: $($loginResp.Response.Login.Message)"
}
Write-Host "[INFO] Sophos-XGS-Login erfolgreich: $FwHost" -ForegroundColor Green

Write-Host '[INFO] Lade Firewall-Regeln ...' -ForegroundColor Cyan
$rules = Get-SophosEntities -EntityType 'FirewallRule'
Write-Host '[INFO] Lade IP-Hosts ...' -ForegroundColor Cyan
$hosts = Get-SophosEntities -EntityType 'IPHost'
Write-Host '[INFO] Lade Zonen ...' -ForegroundColor Cyan
$zones = Get-SophosEntities -EntityType 'Zone'
Write-Host '[INFO] Lade NAT-Regeln ...' -ForegroundColor Cyan
$natRules = Get-SophosEntities -EntityType 'NATRule'
Write-Host '[INFO] Lade Services / Service-Gruppen ...' -ForegroundColor Cyan
$services  = Get-SophosEntities -EntityType 'Services'
$svcGroups = Get-SophosEntities -EntityType 'ServiceGroup'

try { Invoke-SophosAPI -ReqXml '<Request><Logout/></Request>' | Out-Null } catch {}

# ── Auf die normalisierte JSON-Form bringen (passend zum Browser-Konverter) ──
$rulesOut = foreach ($r in (ToArray $rules)) {
    [ordered]@{
        Name                = [string]$r.Name
        Action              = if ($r.Action) { [string]$r.Action } else { 'accept' }
        Status              = if ($r.Status) { [string]$r.Status } else { 'enable' }
        SourceZone          = [string](@(ToArray $r.SourceZones.Zone)[0])
        DestinationZone     = [string](@(ToArray $r.DestinationZones.Zone)[0])
        SourceNetworks      = @(ToArray $r.SourceNetworks.Network      | ForEach-Object { [string]$_ })
        DestinationNetworks = @(ToArray $r.DestinationNetworks.Network | ForEach-Object { [string]$_ })
        Services            = @(ToArray $r.Services.Service            | ForEach-Object { [string]$_ })
        Description         = [string]$r.Description
        # Schedule + Security-Profile (best-effort, Tag-Namen doku-basiert)
        Schedule            = if ($r.Schedule) { [string]$r.Schedule } else { 'AlwaysOn' }
        IPS                 = [string]$r.IntrusionPrevention
        WebFilter           = [string]$r.WebFilter
        AppControl          = [string]$r.ApplicationControl
        AntiVirus           = [string]$r.ScanVirus
    }
}
$hostsOut = foreach ($h in (ToArray $hosts)) {
    [ordered]@{ Name = [string]$h.Name; IPAddress = [string]$h.IPAddress; Subnet = [string]$h.Subnet; Description = [string]$h.Description; IPFamily = [string]$h.IPFamily; IPv6Address = [string]$h.IPv6Address }
}
$zonesOut = foreach ($z in (ToArray $zones)) { [ordered]@{ Name = [string]$z.Name } }
$natRulesOut = foreach ($n in (ToArray $natRules)) {
    [ordered]@{
        Name                  = [string]$n.Name
        Status                = if ($n.Status) { [string]$n.Status } else { 'Enable' }
        OriginalSource        = @(ToArray $n.OriginalSourceNetworks.Network      | ForEach-Object { [string]$_ })
        OriginalDestination   = @(ToArray $n.OriginalDestinationNetworks.Network | ForEach-Object { [string]$_ })
        OriginalService       = @(ToArray $n.OriginalServices.Service            | ForEach-Object { [string]$_ })
        TranslatedDestination = [string]$n.TranslatedDestination
        TranslatedService     = [string]$n.TranslatedService
        InboundInterface      = @(ToArray $n.InboundInterfaces.Interface         | ForEach-Object { [string]$_ })
        OutboundInterface     = @(ToArray $n.OutboundInterfaces.Interface        | ForEach-Object { [string]$_ })
    }
}
$servicesOut = foreach ($s in (ToArray $services)) {
    $det   = @(ToArray $s.ServiceDetails.ServiceDetail)[0]
    $proto = if ($det -and $det.Protocol) { ([string]$det.Protocol).ToUpper() } else { '' }
    $dport = if ($det) { [string]$det.DestinationPort } else { '' }
    [ordered]@{
        name          = [string]$s.Name
        protocol      = $proto.ToLower()
        tcp_portrange = if ($proto -eq 'TCP') { $dport } else { '' }
        udp_portrange = if ($proto -eq 'UDP') { $dport } else { '' }
    }
}
$serviceGroupsOut = foreach ($g in (ToArray $svcGroups)) {
    $mem = @(ToArray $g.ServiceList.Service | ForEach-Object { [string]$_ })
    if (-not $mem.Count) { $mem = @(ToArray $g.ServiceGroupMember.Service | ForEach-Object { [string]$_ }) }
    [ordered]@{ name = [string]$g.Name; member = @($mem) }
}

$output = [ordered]@{
    vendor         = 'sophos'
    rules          = @($rulesOut)
    hosts          = @($hostsOut)
    zones          = @($zonesOut)
    nat_rules      = @($natRulesOut)
    services       = @($servicesOut)
    service_groups = @($serviceGroupsOut)
}

$output | ConvertTo-Json -Depth 30 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "[OK] Geschrieben: $OutFile" -ForegroundColor Green
Write-Host ("     $(@($rulesOut).Count) Regeln, $(@($hostsOut).Count) Hosts, $(@($zonesOut).Count) Zonen") -ForegroundColor Green

$htmlPath = Join-Path $PSScriptRoot 'firewall_viz.html'
if (-not $NoOpen -and (Test-Path $htmlPath)) {
    if ((Read-Host 'Visualisierung jetzt im Browser öffnen? (j/n)') -match '^[jJyY]') {
        Start-Process $htmlPath
        Write-Host '   → dort: "Importieren → Datei importieren" und die erzeugte JSON-Datei wählen.' -ForegroundColor Cyan
    }
}
