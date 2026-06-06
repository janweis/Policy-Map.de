<#
.SYNOPSIS
  Exportiert FortiManager-Firewall-Daten als ROH-JSON (vendor-getaggt) für die Firewall Policy Map.

.BESCHREIBUNG (für Anwender ohne Vorkenntnisse)
  1. Rechtsklick auf diese Datei → "Mit PowerShell ausführen".
  2. Die Fragen beantworten (FortiManager-Adresse, Benutzer, Passwort, ADOM).
  3. Es entsteht eine Datei "firewall-rohdaten-fortimanager.json".
  4. firewall_viz.html im Browser öffnen → "Importieren → Datei importieren" → diese Datei wählen.

  Es wird KEIN Python benötigt — die Aufbereitung passiert direkt im Browser.

.EXAMPLE
  .\Export-FortiManagerFirewallData.ps1
  .\Export-FortiManagerFirewallData.ps1 -FwHost 192.168.1.1 -User admin -Adom root
#>
[CmdletBinding()]
param(
    [string]$FwHost,
    [string]$User,
    [SecureString]$Password,
    [string]$Adom,
    [string]$Package = "",
    [string]$Device  = "",
    [string]$Vdom    = "root",
    [string]$OutFile,
    [switch]$Insecure,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

# ── Fehlende Pflichtangaben interaktiv abfragen ──────────────────────────────
if (-not $FwHost)   { $FwHost   = Read-Host 'FortiManager-Host (IP oder FQDN)' }
if (-not $User)     { $User     = Read-Host 'Benutzer' }
if (-not $Password) { $Password = Read-Host 'Passwort' -AsSecureString }
if (-not $Adom)     { $Adom     = Read-Host 'ADOM (z. B. root)' }
if (-not $OutFile)  { $OutFile  = Join-Path $PSScriptRoot 'firewall-rohdaten-fortimanager.json' }

if ($Device -and $Package) { throw "-Device und -Package schließen sich gegenseitig aus." }

$SkipCert = $Insecure.IsPresent
if ($SkipCert) { Write-Warning 'SSL-Zertifikatsvalidierung deaktiviert (-Insecure)!' }

$BaseUrl = "https://$FwHost/jsonrpc"
$Session = $null
$ReqId   = 1

function Invoke-FMG {
    param([string]$Method, [string]$Url, [hashtable]$Data = $null, [string[]]$Options = $null)
    $params = @{ url = $Url }
    if ($Data)    { $params.data   = $Data }
    if ($Options) { $params.option = $Options }
    $body = @{ id = $script:ReqId++; method = $Method; params = @($params) }
    if ($script:Session) { $body.session = $script:Session }
    $resp = Invoke-RestMethod -Uri $BaseUrl -Method Post -ContentType 'application/json' `
        -Body ($body | ConvertTo-Json -Depth 15 -Compress) -SkipCertificateCheck:$script:SkipCert
    $status = $resp.result[0].status
    if ($status.code -ne 0) { throw "API-Fehler ($Url): [$($status.code)] $($status.message)" }
    return $resp
}

try {
    Write-Host "[INFO] Verbinde mit FortiManager $FwHost ..." -ForegroundColor Cyan
    $loginResp = Invoke-FMG -Method 'exec' -Url '/sys/login/user' -Data @{
        user   = $User
        passwd = [System.Net.NetworkCredential]::new('', $Password).Password
    }
    $Session = $loginResp.session

    Write-Host '[INFO] Lade Adress-Objekte (IPv4 + IPv6) ...' -ForegroundColor Cyan
    $addresses   = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/address" -Options @('object member')).result[0].data
    $addresses6  = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/address6" -Options @('object member')).result[0].data
    Write-Host '[INFO] Lade Adressgruppen (IPv4 + IPv6) ...' -ForegroundColor Cyan
    $addrGroups  = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/addrgrp" -Options @('object member')).result[0].data
    $addrGroups6 = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/addrgrp6" -Options @('object member')).result[0].data
    Write-Host '[INFO] Lade VIPs / NAT-Ziele ...' -ForegroundColor Cyan
    $vips        = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/vip" -Options @('object member')).result[0].data
    Write-Host '[INFO] Lade Services / Service-Gruppen ...' -ForegroundColor Cyan
    $svcs        = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/service/custom" -Options @('object member')).result[0].data
    $svcGroups   = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/service/group" -Options @('object member')).result[0].data

    if ($Device) {
        Write-Host "[INFO] Lade Policies von Gerät '$Device' (VDOM $Vdom, IPv4 + IPv6) ..." -ForegroundColor Cyan
        $policies  = @((Invoke-FMG -Method 'get' -Url "/pm/config/device/$Device/vdom/$Vdom/firewall/policy").result[0].data)
        $policies += @((Invoke-FMG -Method 'get' -Url "/pm/config/device/$Device/vdom/$Vdom/firewall/policy6").result[0].data)
    } else {
        if (-not $Package) {
            $pkgResp  = Invoke-FMG -Method 'get' -Url "/pm/pkg/adom/$Adom"
            $packages = @($pkgResp.result[0].data | Where-Object { $_.type -eq 'pkg' })
            if ($packages.Count -eq 0) { throw "Keine Policy-Packages vom Typ 'pkg' in ADOM '$Adom' gefunden." }
            $Package = $packages[0].name
            Write-Host "[INFO] Verwende Policy-Package '$Package'." -ForegroundColor Cyan
        }
        Write-Host "[INFO] Lade Policies aus Package '$Package' (IPv4 + IPv6) ..." -ForegroundColor Cyan
        $policies  = @((Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/pkg/$Package/firewall/policy").result[0].data)
        $policies += @((Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/pkg/$Package/firewall/policy6").result[0].data)
    }

    # ── Vendor-getaggte Rohdaten (vom Browser-Konverter konsumiert) ──────────
    $output = [ordered]@{
        vendor         = 'fortimanager'
        adom           = $Adom
        addresses      = @($addresses) + @($addresses6)
        addrgroups     = @($addrGroups) + @($addrGroups6)
        policies       = @($policies)
        vips           = @($vips)
        services       = @($svcs)
        service_groups = @($svcGroups)
    }
    if ($Device)  { $output.device = $Device; $output.vdom = $Vdom }
    if ($Package) { $output.package = $Package }

    $output | ConvertTo-Json -Depth 30 | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "[OK] Geschrieben: $OutFile" -ForegroundColor Green
    Write-Host ("     $(@($addresses).Count) Adressen, $(@($addrGroups).Count) Gruppen, $(@($policies).Count) Policies") -ForegroundColor Green
}
finally {
    try { Invoke-FMG -Method 'exec' -Url '/sys/logout' | Out-Null } catch {}
}

# ── Visualisierung anbieten ──────────────────────────────────────────────────
$htmlPath = Join-Path $PSScriptRoot 'firewall_viz.html'
if (-not $NoOpen -and (Test-Path $htmlPath)) {
    if ((Read-Host 'Visualisierung jetzt im Browser öffnen? (j/n)') -match '^[jJyY]') {
        Start-Process $htmlPath
        Write-Host '   → dort: "Importieren → Datei importieren" und die erzeugte JSON-Datei wählen.' -ForegroundColor Cyan
    }
}
