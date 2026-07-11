<#
.SYNOPSIS
  Exportiert die Regeln einer einzelnen FortiGate (FortiOS REST API) als ROH-JSON
  (vendor-getaggt) für die Firewall Policy Map.

.DESCRIPTION
  1. Rechtsklick auf diese Datei → "Mit PowerShell ausführen".
  2. Die Fragen beantworten:
       - Benutzer LEER lassen  → API-Token (im nächsten Feld eingeben).
       - Benutzer angeben       → Anmeldung mit Passwort (Session).
  3. Es entsteht eine Datei "firewall-rohdaten-fortigate.json".
  4. firewall_viz.html im Browser öffnen → "Importieren → Datei importieren" → diese Datei wählen.

  Es wird KEIN Python benötigt — die Aufbereitung passiert direkt im Browser.

.EXAMPLE
  .\Export-FortiGateFirewallData.ps1
  .\Export-FortiGateFirewallData.ps1 -FwHost 192.168.1.99 -Password <meinToken>         # Token-Modus (interaktiv)
  .\Export-FortiGateFirewallData.ps1 -FwHost 192.168.1.99 -User admin -Password <xyz>   # Session-Modus
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage = 'FortiGate-Host (IP oder FQDN)')]
    [string]$FwHost,
    
    [Parameter(Mandatory, ParameterSetName = "UP-Login")]
    [string]$User = "",
    
    [Parameter(Mandatory, ParameterSetName = "UP-Login")]
    [Parameter(Mandatory, ParameterSetName = "Token-Login")]
    [SecureString]$Password,
    
    # Options
    [string]$Vdom = "root",
    [string]$OutFile = (Join-Path $PSScriptRoot 'firewall-rohdaten-fortigate.json'),
    [switch]$Insecure,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

$SkipCert = $Insecure.IsPresent
if ($SkipCert) { Write-Warning 'SSL-Zertifikatsvalidierung deaktiviert (-Insecure)!' }

# Windows PowerShell 5.1 kennt -SkipCertificateCheck nicht → TLS 1.2 erzwingen und
# die Zertifikatsprüfung bei -Insecure prozessweit abschalten.
$PS5 = $PSVersionTable.PSVersion.Major -lt 6
if ($PS5) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ($SkipCert) {
        if (-not ('TrustAllCertsPolicy' -as [type])) {
            Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
        }
        [Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
}

$secret = [System.Net.NetworkCredential]::new('', $Password).Password
$headers = @{}
$sess = $null


#
# Funktionen
#

# 
function ToArray($x) { 
    if ($null -eq $x) {
        @() 
    } 
    else { 
        @($x) 
    } 
}

# FortiOS liefert srcaddr/srcintf/service als [{name=…}] → auf Namen reduzieren.
function Names($seq) {
    @(ToArray $seq | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.name) { [string]$_.name } } | Where-Object { $_ })
}

# Wie Names, akzeptiert aber auch {id=N}-Mitglieder (FortiOS internet-service-id-Tabellen).
function NamesOrIds($seq) {
    @(ToArray $seq | ForEach-Object {
        if ($_ -is [string] -or $_ -is [int] -or $_ -is [long]) { [string]$_ }
        elseif ($_.name) { [string]$_.name }
        elseif ($null -ne $_.id) { [string]$_.id }
    } | Where-Object { $_ })
}

# FortiOS VIP-mappedip ist eine Tabelle [{range=x.x.x.x}, …] → ersten Range als String.
function MappedIp($v) {
    foreach ($m in (ToArray $v)) {
        if ($m -is [string]) {
            return $m 
        }
        elseif ($m.range) {
            return [string]$m.range 
        } 
    }
    return ''
}

# Baue den Abrufpfad
function Get-Cmdb ([string]$Path) {
    
    $url = "https://$FwHost/api/v2$Path`?vdom=$([uri]::EscapeDataString($Vdom))"
    $p = @{ Uri = $url; Headers = $headers }
    
    if (-not $script:PS5 -and $script:SkipCert) { $p.SkipCertificateCheck = $true }
    if ($script:sess) { $p.WebSession = $script:sess }
    
    return Invoke-RestMethod @p
}

# FortiOS >= 7.0 kennt firewall/policy6 nicht mehr (in firewall/policy aufgegangen) → Fehler tolerieren.
function Get-CmdbOptional ([string]$Path) {
    try { 
        Get-Cmdb -Path $Path 
    }
    catch {
        Write-Host "[INFO] $Path nicht verfügbar (FortiOS >= 7.0?) — übersprungen." -ForegroundColor DarkGray
        @{ results = @() }
    }
}


#
# Skript
#

# Authentifizierung
if ($User) {
    Write-Host "[INFO] Session-Login an FortiGate $FwHost ..." -ForegroundColor Cyan
    
    $form = @{ username = $User; secretkey = $secret; ajax = 1 }
    $lp = @{ Uri = "https://$FwHost/logincheck"; Method = 'Post'; Body = $form
        SessionVariable = 'sess'; UseBasicParsing = $true 
    }
    if (-not $PS5 -and $SkipCert) { $lp.SkipCertificateCheck = $true }
    
    Invoke-WebRequest @lp | Out-Null
}
else {
    Write-Host "[INFO] Token-Modus (Bearer) gegen FortiGate $FwHost ..." -ForegroundColor Cyan
    $headers['Authorization'] = "Bearer $secret"
}


# Abholen der Daten
Write-Host '[INFO] Lade Adress-Objekte (IPv4 + IPv6) ...' -ForegroundColor Cyan
$addrs = Get-Cmdb -Path '/cmdb/firewall/address'
$addrs6 = Get-Cmdb -Path '/cmdb/firewall/address6'

Write-Host '[INFO] Lade Adressgruppen (IPv4 + IPv6) ...' -ForegroundColor Cyan
$grps = Get-Cmdb -Path '/cmdb/firewall/addrgrp'
$grps6 = Get-Cmdb -Path '/cmdb/firewall/addrgrp6'

Write-Host '[INFO] Lade Policies (IPv4 + IPv6) ...' -ForegroundColor Cyan
$pols = Get-Cmdb -Path '/cmdb/firewall/policy'
$pols6 = Get-CmdbOptional -Path '/cmdb/firewall/policy6'

Write-Host '[INFO] Lade VIPs / NAT-Ziele ...' -ForegroundColor Cyan
$vips = Get-Cmdb -Path '/cmdb/firewall/vip'

# CLI-Zweiwort-Kategorie "firewall service" → im FortiOS-REST-Pfad mit Punkt (firewall.service)
Write-Host '[INFO] Lade Services / Service-Gruppen ...' -ForegroundColor Cyan
$svcs = Get-Cmdb -Path '/cmdb/firewall.service/custom'
$svcGrps = Get-Cmdb -Path '/cmdb/firewall.service/group'

# Zeitplan-Definitionen (CLI "firewall schedule" → REST-Pfad firewall.schedule) - tolerant abrufen
Write-Host '[INFO] Lade Zeitplaene (onetime + recurring) ...' -ForegroundColor Cyan
$schedOne = Get-CmdbOptional -Path '/cmdb/firewall.schedule/onetime'
$schedRec = Get-CmdbOptional -Path '/cmdb/firewall.schedule/recurring'

# ── Normalisieren (gemeinsames Roh-Schema, vom Browser-Konverter konsumiert) ─
# IPv4 + IPv6 in dieselben Listen mergen
$addressesAll = @(ToArray $addrs.results) + @(ToArray $addrs6.results)
$addrgroupsOut = foreach ($g in (@(ToArray $grps.results) + @(ToArray $grps6.results))) {
    [ordered]@{ name = [string]$g.name; member = @(Names $g.member) }
}

$policiesOut = foreach ($p in (@(ToArray $pols.results) + @(ToArray $pols6.results))) {
    [ordered]@{
        policyid            = $p.policyid
        name                = [string]$p.name
        srcintf             = @(Names $p.srcintf)
        dstintf             = @(Names $p.dstintf)
        srcaddr             = @(Names $p.srcaddr)
        dstaddr             = @(Names $p.dstaddr)
        service             = @(Names $p.service)
        action              = [string]$p.action
        nat                 = if ("$($p.nat)".ToLower() -eq 'enable') { 1 } else { 0 }
        status              = [string]$p.status
        schedule            = if ($p.schedule) { [string]$p.schedule } else { 'always' }
        'ips-sensor'        = [string]$p.'ips-sensor'
        'av-profile'        = [string]$p.'av-profile'
        'webfilter-profile' = [string]$p.'webfilter-profile'
        'application-list'  = [string]$p.'application-list'
        'ssl-ssh-profile'   = [string]$p.'ssl-ssh-profile'
        uuid                = [string]$p.uuid
        logtraffic          = [string]$p.logtraffic
        comments            = [string]$p.comments
        'global-label'      = [string]$p.'global-label'
        # Erweiterte Felder (Gap-Kategorie A): ISDB-Ziele, Negation, Identitaet, NAT-Pool
        'internet-service'          = [string]$p.'internet-service'
        'internet-service-name'     = @(Names $p.'internet-service-name')
        'internet-service-id'       = @(NamesOrIds $p.'internet-service-id')
        'internet-service-src'      = [string]$p.'internet-service-src'
        'internet-service-src-name' = @(Names $p.'internet-service-src-name')
        'internet-service-src-id'   = @(NamesOrIds $p.'internet-service-src-id')
        'srcaddr-negate'            = [string]$p.'srcaddr-negate'
        'dstaddr-negate'            = [string]$p.'dstaddr-negate'
        'service-negate'            = [string]$p.'service-negate'
        users                       = @(Names $p.users)
        groups                      = @(Names $p.groups)
        ippool                      = [string]$p.ippool
        poolname                    = @(Names $p.poolname)
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

# Gemeinsame Schedule-Form: name/type/start/end/day (recurring: day als Leerzeichen-Liste)
$schedulesOut = @(
    foreach ($s in (ToArray $schedOne.results)) {
        [ordered]@{ name = [string]$s.name; type = 'onetime'; start = [string]$s.start; end = [string]$s.end; day = '' }
    }
) + @(
    foreach ($s in (ToArray $schedRec.results)) {
        [ordered]@{ name = [string]$s.name; type = 'recurring'; start = [string]$s.start; end = [string]$s.end; day = [string]$s.day }
    }
)

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
    schedules      = @($schedulesOut)
}

$output | ConvertTo-Json -Depth 30 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "[OK] Geschrieben: $OutFile" -ForegroundColor Green

Write-Host ("     $(@($addrs.results).Count) Adressen, $(@($addrgroupsOut).Count) Gruppen, $(@($policiesOut).Count) Policies") -ForegroundColor Green