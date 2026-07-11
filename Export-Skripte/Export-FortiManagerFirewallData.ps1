<#
    .SYNOPSIS
    Exportiert FortiManager-Firewall-Daten als ROH-JSON (vendor-getaggt) für die Firewall Policy Map.

    .DESCRIPTION
    1. Rechtsklick auf diese Datei → "Mit PowerShell ausführen".
    2. Die Fragen beantworten (FortiManager-Adresse, Benutzer, Passwort, ADOM).
    3. Es entsteht eine Datei "firewall-rohdaten-fortimanager.json".
    4. firewall_viz.html im Browser öffnen → "Importieren → Datei importieren" → diese Datei wählen.

    .EXAMPLE
    .\Export-FortiManagerFirewallData.ps1
    .\Export-FortiManagerFirewallData.ps1 -FwHost 192.168.1.1 -User admin -Adom root
#>
[CmdletBinding()]
param(
    [Parameter(mandatory)]
    [string]$FwHost,
  
    [Parameter(mandatory)]
    [string]$User,
  
    [Parameter(mandatory)]
    [SecureString]$Password,
  
    [Parameter(mandatory)]
    [string]$Adom,

    # Optional
    [Parameter(ParameterSetName = 'Package')]
    [string]$Package = '',
    
    [Parameter(ParameterSetName = 'Device')]
    [string]$Device = '',

    # System
    [string]$Vdom = 'root',
    [string]$OutFile = (Join-Path -Path $PSScriptRoot -ChildPath 'firewall-rohdaten-fortimanager.json'),
    [switch]$Insecure,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'


#
# Checks
#

if ($Device -and $Package) {
    throw '-Device und -Package schließen sich gegenseitig aus.' 
}

$SkipCert = $Insecure.IsPresent
if ($SkipCert) {
    Write-Warning -Message 'SSL-Zertifikatsvalidierung deaktiviert (-Insecure)!' 
}

# Windows PowerShell 5.1 kennt -SkipCertificateCheck nicht → TLS 1.2 erzwingen und
# die Zertifikatsprüfung bei -Insecure prozessweit abschalten.
$PS5 = $PSVersionTable.PSVersion.Major -lt 6
if ($PS5) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ($SkipCert) {
        if (-not ('TrustAllCertsPolicy' -as [type])) {
            Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
        }
        [Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
    }
}


#
# Functions
#

function Invoke-FMG {
    param(
        [string]$Method, 
        [string]$Url, 
        [hashtable]$Data = $null, 
        [string[]]$Options = $null
    )

    $params = @{        url = $Url }
    
    if ($Data) { $params.data = $Data }
    if ($Options) { $params.option = $Options }

    $body = @{
        id     = $script:ReqId++
        method = $Method
        params = @($params)
    }

    if ($script:Session) {
        $body.session = $script:Session 
    }

    $iwr = @{
        Uri         = $BaseUrl
        Method      = 'Post'
        ContentType = 'application/json'
        Body        = ($body | ConvertTo-Json -Depth 15 -Compress)
    }

    if (-not $script:PS5 -and $script:SkipCert) {
        $iwr.SkipCertificateCheck = $true 
    }

    $resp = Invoke-RestMethod @iwr
    $status = $resp.result[0].status

    if ($status.code -ne 0) {
        throw "API-Fehler ($Url): [$($status.code)] $($status.message)" 
    }


    return $resp
}


#
# Script Main
#

# INIT
$BaseUrl = "https://$FwHost/jsonrpc"
$Session = $null
$ReqId = 1


Write-Host "[INFO] Verbinde mit FortiManager $FwHost ..." -ForegroundColor Cyan

try {
    $loginResp = Invoke-FMG -Method 'exec' -Url '/sys/login/user' -Data @{
        user   = $User
        passwd = [System.Net.NetworkCredential]::new('', $Password).Password
    }
    
    # Session Daten abholen
    $Session = $loginResp.session

    Write-Host '[INFO] Lade Adress-Objekte (IPv4 + IPv6) ...' -ForegroundColor Cyan
    $addresses = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/address" -Options @('object member')).result[0].data
    $addresses6 = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/address6" -Options @('object member')).result[0].data
    
    Write-Host '[INFO] Lade Adressgruppen (IPv4 + IPv6) ...' -ForegroundColor Cyan
    $addrGroups = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/addrgrp" -Options @('object member')).result[0].data
    $addrGroups6 = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/addrgrp6" -Options @('object member')).result[0].data
    
    Write-Host '[INFO] Lade VIPs / NAT-Ziele ...' -ForegroundColor Cyan
    $vips = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/vip" -Options @('object member')).result[0].data
    
    Write-Host '[INFO] Lade Services / Service-Gruppen ...' -ForegroundColor Cyan
    $svcs = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/service/custom" -Options @('object member')).result[0].data
    $svcGroups = (Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/service/group" -Options @('object member')).result[0].data

    # Zeitplan-Definitionen (gemeinsame Form name/type/start/end/day) - tolerant abrufen
    Write-Host '[INFO] Lade Zeitplaene (onetime + recurring) ...' -ForegroundColor Cyan
    $schedules = @()
    try {
        foreach ($s in @((Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/schedule/onetime").result[0].data)) {
            if ($s) { $schedules += [ordered]@{ name = [string]$s.name; type = 'onetime'; start = [string]$s.start; end = [string]$s.end; day = '' } }
        }
        foreach ($s in @((Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/obj/firewall/schedule/recurring").result[0].data)) {
            if ($s) { $schedules += [ordered]@{ name = [string]$s.name; type = 'recurring'; start = [string]$s.start; end = [string]$s.end; day = [string]($s.day -join ' ') } }
        }
    }
    catch {
        Write-Host '[INFO] Zeitplaene nicht abrufbar - uebersprungen.' -ForegroundColor DarkGray
    }

    if ($Device) {
        Write-Host "[INFO] Lade Policies von Gerät '$Device' (VDOM $Vdom, IPv4 + IPv6) ..." -ForegroundColor Cyan
        $policies = @((Invoke-FMG -Method 'get' -Url "/pm/config/device/$Device/vdom/$Vdom/firewall/policy").result[0].data)
        # FortiOS >= 7.0 kennt firewall/policy6 nicht mehr (in firewall/policy aufgegangen) → tolerieren.
        try {
            $policies += @((Invoke-FMG -Method 'get' -Url "/pm/config/device/$Device/vdom/$Vdom/firewall/policy6").result[0].data) 
        }
        catch {
            Write-Host '[INFO] firewall/policy6 nicht verfügbar (FortiOS >= 7.0?) - übersprungen.' -ForegroundColor DarkGray 
        }
    }
    else {
        if (-not $Package) {
            $pkgResp = Invoke-FMG -Method 'get' -Url "/pm/pkg/adom/$Adom"
            $packages = @($pkgResp.result[0].data | Where-Object {
                    $_.type -eq 'pkg' 
                })
            if ($packages.Count -eq 0) {
                throw "Keine Policy-Packages vom Typ 'pkg' in ADOM '$Adom' gefunden." 
            }
            $Package = $packages[0].name
            
            Write-Host "[INFO] Verwende Policy-Package '$Package'." -ForegroundColor Cyan
        }
        
        Write-Host "[INFO] Lade Policies aus Package '$Package' (IPv4 + IPv6) ..." -ForegroundColor Cyan
        $policies = @((Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/pkg/$Package/firewall/policy").result[0].data)
        
        try {
            # FortiOS >= 7.0 kennt firewall/policy6 nicht mehr (in firewall/policy aufgegangen) → tolerieren.
            $policies += @((Invoke-FMG -Method 'get' -Url "/pm/config/adom/$Adom/pkg/$Package/firewall/policy6").result[0].data) 
        }
        catch {
            Write-Host '[INFO] firewall/policy6 nicht verfügbar (FortiOS >= 7.0?) - übersprungen.' -ForegroundColor DarkGray 
        }
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
        schedules      = @($schedules)
    }
    if ($Device) {
        $output.device = $Device
        $output.vdom = $Vdom
    }
    if ($Package) {
        $output.package = $Package 
    }

    # Schreibe Daten raus
    $output | ConvertTo-Json -Depth 30 | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "[OK] Geschrieben: $OutFile" -ForegroundColor Green

    Write-Host ("     $(@($addresses).Count) Adressen, $(@($addrGroups).Count) Gruppen, $(@($policies).Count) Policies") -ForegroundColor Green
}
finally {
    try {
        $null = Invoke-FMG -Method 'exec' -Url '/sys/logout' 
    }
    catch {
    }
}