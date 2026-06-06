<#
.SYNOPSIS
  Exportiert die Regeln einer einzelnen FortiGate (FortiOS REST API) als ROH-JSON
  (vendor-getaggt) für die Firewall Policy Map.

.BESCHREIBUNG (für Anwender ohne Vorkenntnisse)
  1. Rechtsklick auf diese Datei → "Mit PowerShell ausführen".
  2. Die Fragen beantworten:
       - Benutzer LEER lassen  → API-Token (im nächsten Feld eingeben).
       - Benutzer angeben       → Anmeldung mit Passwort (Session).
  3. Es entsteht eine Datei "firewall-rohdaten-fortigate.json".
  4. firewall_viz.html im Browser öffnen → "Importieren → Datei importieren" → diese Datei wählen.

  Es wird KEIN Python benötigt — die Aufbereitung passiert direkt im Browser.

.EXAMPLE
  .\Export-FortiGateFirewallData.ps1
  .\Export-FortiGateFirewallData.ps1 -FwHost 192.168.1.99 -Vdom root        # Token-Modus (interaktiv)
  .\Export-FortiGateFirewallData.ps1 -FwHost 192.168.1.99 -User admin       # Session-Modus
#>
[CmdletBinding()]
param(
    [string]$FwHost,
    [string]$User = "",
    [SecureString]$Password,
    [string]$Vdom = "root",
    [string]$OutFile,
    [switch]$Insecure,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

if (-not $FwHost) { $FwHost = Read-Host 'FortiGate-Host (IP oder FQDN)' }
if (-not $PSBoundParameters.ContainsKey('User')) { $User = Read-Host 'Benutzer (leer lassen für API-Token)' }
if (-not $Password) {
    $Password = if ($User) { Read-Host 'Passwort' -AsSecureString } else { Read-Host 'API-Token' -AsSecureString }
}
if (-not $Vdom)    { $Vdom = 'root' }
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'firewall-rohdaten-fortigate.json' }

$SkipCert = $Insecure.IsPresent
if ($SkipCert) { Write-Warning 'SSL-Zertifikatsvalidierung deaktiviert (-Insecure)!' }

$secret  = [System.Net.NetworkCredential]::new('', $Password).Password
$headers = @{}
$sess    = $null

function ToArray($x) { if ($null -eq $x) { @() } else { @($x) } }
# FortiOS liefert srcaddr/srcintf/service als [{name=…}] → auf Namen reduzieren.
function Names($seq) {
    @(ToArray $seq | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.name) { [string]$_.name } } | Where-Object { $_ })
}
# FortiOS VIP-mappedip ist eine Tabelle [{range=x.x.x.x}, …] → ersten Range als String.
function MappedIp($v) {
    foreach ($m in (ToArray $v)) { if ($m -is [string]) { return $m } elseif ($m.range) { return [string]$m.range } }
    return ''
}

function Get-Cmdb {
    param([string]$Path)
    $url = "https://$FwHost/api/v2$Path`?vdom=$([uri]::EscapeDataString($Vdom))"
    $p = @{ Uri = $url; Headers = $headers; SkipCertificateCheck = $script:SkipCert }
    if ($script:sess) { $p.WebSession = $script:sess }
    return Invoke-RestMethod @p
}

# ── Authentifizierung ────────────────────────────────────────────────────────
if ($User) {
    Write-Host "[INFO] Session-Login an FortiGate $FwHost ..." -ForegroundColor Cyan
    $form = @{ username = $User; secretkey = $secret; ajax = 1 }
    Invoke-WebRequest -Uri "https://$FwHost/logincheck" -Method Post -Body $form `
        -SessionVariable sess -SkipCertificateCheck:$SkipCert -UseBasicParsing | Out-Null
} else {
    Write-Host "[INFO] Token-Modus (Bearer) gegen FortiGate $FwHost ..." -ForegroundColor Cyan
    $headers['Authorization'] = "Bearer $secret"
}

Write-Host '[INFO] Lade Adress-Objekte (IPv4 + IPv6) ...' -ForegroundColor Cyan
$addrs   = Get-Cmdb -Path '/cmdb/firewall/address'
$addrs6  = Get-Cmdb -Path '/cmdb/firewall/address6'
Write-Host '[INFO] Lade Adressgruppen (IPv4 + IPv6) ...' -ForegroundColor Cyan
$grps    = Get-Cmdb -Path '/cmdb/firewall/addrgrp'
$grps6   = Get-Cmdb -Path '/cmdb/firewall/addrgrp6'
Write-Host '[INFO] Lade Policies (IPv4 + IPv6) ...' -ForegroundColor Cyan
$pols    = Get-Cmdb -Path '/cmdb/firewall/policy'
$pols6   = Get-Cmdb -Path '/cmdb/firewall/policy6'
Write-Host '[INFO] Lade VIPs / NAT-Ziele ...' -ForegroundColor Cyan
$vips    = Get-Cmdb -Path '/cmdb/firewall/vip'
Write-Host '[INFO] Lade Services / Service-Gruppen ...' -ForegroundColor Cyan
$svcs    = Get-Cmdb -Path '/cmdb/firewall/service/custom'
$svcGrps = Get-Cmdb -Path '/cmdb/firewall/service/group'

# ── Normalisieren (gemeinsames Roh-Schema, vom Browser-Konverter konsumiert) ─
# IPv4 + IPv6 in dieselben Listen mergen
$addressesAll = @(ToArray $addrs.results) + @(ToArray $addrs6.results)
$addrgroupsOut = foreach ($g in (@(ToArray $grps.results) + @(ToArray $grps6.results))) {
    [ordered]@{ name = [string]$g.name; member = @(Names $g.member) }
}
$policiesOut = foreach ($p in (@(ToArray $pols.results) + @(ToArray $pols6.results))) {
    [ordered]@{
        policyid = $p.policyid
        name     = [string]$p.name
        srcintf  = @(Names $p.srcintf)
        dstintf  = @(Names $p.dstintf)
        srcaddr  = @(Names $p.srcaddr)
        dstaddr  = @(Names $p.dstaddr)
        service  = @(Names $p.service)
        action   = [string]$p.action
        nat      = if ("$($p.nat)".ToLower() -eq 'enable') { 1 } else { 0 }
        status   = [string]$p.status
        schedule = if ($p.schedule) { [string]$p.schedule } else { 'always' }
        'ips-sensor'        = [string]$p.'ips-sensor'
        'av-profile'        = [string]$p.'av-profile'
        'webfilter-profile' = [string]$p.'webfilter-profile'
        'application-list'  = [string]$p.'application-list'
        'ssl-ssh-profile'   = [string]$p.'ssl-ssh-profile'
        uuid                = [string]$p.uuid
        logtraffic          = [string]$p.logtraffic
        comments            = [string]$p.comments
        'global-label'      = [string]$p.'global-label'
    }
}
$servicesOut = foreach ($s in (ToArray $svcs.results)) {
    [ordered]@{
        name          = [string]$s.name
        protocol      = [string]$s.protocol
        tcp_portrange = [string]$s.'tcp-portrange'
        udp_portrange = [string]$s.'udp-portrange'
    }
}
$serviceGroupsOut = foreach ($g in (ToArray $svcGrps.results)) {
    [ordered]@{ name = [string]$g.name; member = @(Names $g.member) }
}

$vipsOut = foreach ($v in (ToArray $vips.results)) {
    [ordered]@{
        name        = [string]$v.name
        extip       = [string]$v.extip
        mappedip    = MappedIp $v.mappedip
        extport     = [string]$v.extport
        mappedport  = [string]$v.mappedport
        portforward = if ("$($v.portforward)".ToLower() -eq 'enable') { 1 } else { 0 }
        protocol    = [string]$v.protocol
    }
}

$output = [ordered]@{
    vendor         = 'fortigate'
    vdom           = $Vdom
    addresses      = @($addressesAll)
    addrgroups     = @($addrgroupsOut)
    policies       = @($policiesOut)
    vips           = @($vipsOut)
    services       = @($servicesOut)
    service_groups = @($serviceGroupsOut)
}

$output | ConvertTo-Json -Depth 30 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "[OK] Geschrieben: $OutFile" -ForegroundColor Green
Write-Host ("     $(@($addrs.results).Count) Adressen, $(@($addrgroupsOut).Count) Gruppen, $(@($policiesOut).Count) Policies") -ForegroundColor Green

$htmlPath = Join-Path $PSScriptRoot 'firewall_viz.html'
if (-not $NoOpen -and (Test-Path $htmlPath)) {
    if ((Read-Host 'Visualisierung jetzt im Browser öffnen? (j/n)') -match '^[jJyY]') {
        Start-Process $htmlPath
        Write-Host '   → dort: "Importieren → Datei importieren" und die erzeugte JSON-Datei wählen.' -ForegroundColor Cyan
    }
}
