<#
.SYNOPSIS
  Exportiert das Access-Regelwerk + die Objekte eines Check Point Management Servers (R80+ Web-API)
  als ROH-JSON (vendor-getaggt, secret-frei) für die Firewall Policy Map.

.DESCRIPTION
  Sicherheit & Transparenz: READ-ONLY-Zugriff (nur `show-*`-Kommandos) auf die Management-API.
  Es wird NUR das Regelwerk + das object-dictionary (Netz-/Dienst-Objekte) gezogen — keine Passwörter,
  Zertifikate oder Schlüssel. Ergebnis: kleine, prüfbare JSON-Datei "firewall-rohdaten-checkpoint.json".

  Check-Point-Regeln haben KEINE Zonen — der Browser-Konverter leitet sie heuristisch aus den
  Objekt-Adressen ab (RFC1918→Intern, öffentlich→Extern, Name „dmz"→DMZ) und kennzeichnet jede Regel
  als „abgeleitet". UID-Referenzen werden hier über das object-dictionary in Namen aufgelöst.

  Voraussetzung: Management-API aktiviert (SmartConsole → Manage & Settings → Blades → Management API),
  Lesezugriff. Layer-/Package-Name ggf. anpassen (-Layer / -Package).

  Ablauf: Rechtsklick → "Mit PowerShell ausführen", Host/Zugang/Layer angeben → JSON entsteht →
  Policy Map → "Importieren → Datei importieren" (oder Drag and Drop). Konvertierung im Browser.

.EXAMPLE
  .\Export-CheckPointFirewallData.ps1 -MgmtHost 192.0.2.1 -User admin -Password <secure> -Layer "Network" -Insecure
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage = 'Check Point Management Server (IP/FQDN, ggf. :Port)')]
    [string]$MgmtHost,
    [Parameter(Mandatory)][string]$User,
    [Parameter(Mandatory)][SecureString]$Password,
    [string]$Layer = 'Network',
    [string]$Package = 'Standard',
    [string]$OutFile = (Join-Path $PSScriptRoot 'firewall-rohdaten-checkpoint.json'),
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

$baseUrl = "https://$MgmtHost/web_api"
$script:sid = $null

function ToArray($x) { if ($null -eq $x) { @() } else { @($x) } }

# READ-ONLY Web-API-Aufruf (POST mit JSON-Body); X-chkp-sid nach Login
function Invoke-Cp ([string]$Command, [hashtable]$Body) {
    $h = @{ 'Content-Type' = 'application/json' }
    if ($script:sid) { $h['X-chkp-sid'] = $script:sid }
    $p = @{ Uri = "$baseUrl/$Command"; Method = 'Post'; Headers = $h
        Body = (($Body | ConvertTo-Json -Depth 10)); UseBasicParsing = $true }
    if (-not $script:PS5 -and $script:SkipCert) { $p.SkipCertificateCheck = $true }
    return Invoke-RestMethod @p
}

# CIDR aus subnet4 + mask-length4
function Cidr($o) {
    if ($o.subnet4 -and ($null -ne $o.'mask-length4')) { return "$($o.subnet4)/$($o.'mask-length4')" }
    if ($o.subnet4 -and $o.'subnet-mask') { return "$($o.subnet4)/$($o.'subnet-mask')" }
    return [string]$o.subnet4
}

#
# Login
#
$pw = [System.Net.NetworkCredential]::new('', $Password).Password
Write-Host "[INFO] Login an Check Point Management $MgmtHost ..." -ForegroundColor Cyan
$login = Invoke-Cp 'login' @{ user = $User; password = $pw; 'read-only' = $true }
$script:sid = [string]$login.sid
if (-not $script:sid) { throw 'Kein Session-Token (sid) erhalten.' }

try {
    #
    # Access-Rulebase (paginiert) + object-dictionary einsammeln
    #
    $dict = @{}            # uid -> object
    $ruleItems = @()
    $offset = 0
    do {
        Write-Host "[INFO] Lade Access-Rulebase '$Layer' (offset $offset) ..." -ForegroundColor Cyan
        $rb = Invoke-Cp 'show-access-rulebase' @{ name = $Layer; 'details-level' = 'full'; 'use-object-dictionary' = $true; limit = 100; offset = $offset }
        foreach ($o in (ToArray $rb.'objects-dictionary')) { if ($o.uid) { $dict[$o.uid] = $o } }
        # Rulebase kann Sections (mit verschachteltem 'rulebase') enthalten → flach sammeln
        $stack = New-Object System.Collections.Stack
        foreach ($it in (ToArray $rb.rulebase)) { $stack.Push($it) }
        while ($stack.Count) {
            $it = $stack.Pop()
            if ($it.rulebase) { foreach ($c in (ToArray $it.rulebase)) { $stack.Push($c) } }
            elseif ($it.type -eq 'access-rule') { $ruleItems += $it }
        }
        $total = [int]$rb.total; $offset += [int]$rb.to - [int]$rb.from + 1
        if ([int]$rb.to -le 0) { break }
    } while ($offset -lt $total)

    # NAT-Rulebase (best effort)
    $natItems = @()
    try {
        $nb = Invoke-Cp 'show-nat-rulebase' @{ package = $Package; 'details-level' = 'full'; 'use-object-dictionary' = $true; limit = 100; offset = 0 }
        foreach ($o in (ToArray $nb.'objects-dictionary')) { if ($o.uid) { $dict[$o.uid] = $o } }
        foreach ($it in (ToArray $nb.rulebase)) { if ($it.rulebase) { $natItems += (ToArray $it.rulebase) } elseif ($it.type -eq 'nat-rule') { $natItems += $it } }
    } catch { Write-Host '[INFO] NAT-Rulebase nicht verfügbar — übersprungen.' -ForegroundColor DarkGray }

    #
    # Auflösen: UID -> Name; Objekte ins stabile Roh-Schema normalisieren
    #
    function NameOf($uid) { $o = $dict[$uid]; if ($o) { if ($o.name) { return [string]$o.name } else { return [string]$o.type } } return [string]$uid }
    # UID-Liste -> Namen ('Any' -> 'any')
    function RefNames($uids) {
        $out = @()
        foreach ($u in (ToArray $uids)) {
            $o = $dict[$u]
            $nm = if ($o -and $o.name) { [string]$o.name } else { [string]$u }
            if ($o -and ($o.type -eq 'CpmiAnyObject' -or $nm -eq 'Any')) { $nm = 'any' }
            $out += $nm
        }
        if (-not $out.Count) { return @('any') }
        return $out
    }

    $hosts = @(); $groups = @(); $services = @(); $servicegroups = @()
    foreach ($o in $dict.Values) {
        switch ($o.type) {
            'host'          { $hosts += [ordered]@{ name = [string]$o.name; value = [string]$o.'ipv4-address'; type = 'host' } }
            'network'       { $hosts += [ordered]@{ name = [string]$o.name; value = (Cidr $o); type = 'network' } }
            'address-range' { $hosts += [ordered]@{ name = [string]$o.name; value = "$($o.'ipv4-address-first')-$($o.'ipv4-address-last')"; type = 'range' } }
            'group'         { $groups += [ordered]@{ name = [string]$o.name; member = @(foreach ($m in (ToArray $o.members)) { if ($m.name) { [string]$m.name } else { NameOf $m } }) } }
            'service-tcp'   { $services += [ordered]@{ name = [string]$o.name; proto = 'TCP'; port = [string]$o.port } }
            'service-udp'   { $services += [ordered]@{ name = [string]$o.name; proto = 'UDP'; port = [string]$o.port } }
            'service-group' { $servicegroups += [ordered]@{ name = [string]$o.name; member = @(foreach ($m in (ToArray $o.members)) { if ($m.name) { [string]$m.name } else { NameOf $m } }) } }
        }
    }

    $policies = foreach ($r in $ruleItems) {
        [ordered]@{
            name        = [string]$r.name
            uuid        = [string]$r.uid
            source      = @(RefNames $r.source)
            destination = @(RefNames $r.destination)
            service     = @(RefNames $r.service)
            action      = (NameOf $r.action)
            enabled     = -not ($r.enabled -eq $false)
            srcNegate   = [bool]$r.'source-negate'
            dstNegate   = [bool]$r.'destination-negate'
            comment     = [string]$r.comments
        }
    }

    # Inbound-DNAT: original-destination -> translated-destination (best effort)
    $nat = foreach ($n in $natItems) {
        $td = NameOf $n.'translated-destination'
        $od = NameOf $n.'original-destination'
        if (-not $td -or $td -eq 'Original' -or $td -eq $od) { continue }
        [ordered]@{ name = [string]$n.uid; origDest = $od; transDest = $td; transPort = ''; proto = '' }
    }

    $output = [ordered]@{
        vendor        = 'checkpoint'
        hosts         = @($hosts)
        groups        = @($groups)
        services      = @($services)
        servicegroups = @($servicegroups)
        policies      = @($policies)
        nat           = @($nat)
    }
    $output | ConvertTo-Json -Depth 30 | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "[OK] Geschrieben: $OutFile" -ForegroundColor Green
    Write-Host ("     $(@($hosts).Count) Objekte, $(@($policies).Count) Regeln - keine Secrets.") -ForegroundColor Green
    if (-not $NoOpen) { Write-Host '     Naechster Schritt: Policy Map -> "Importieren -> Datei importieren" -> diese Datei.' -ForegroundColor Cyan }
}
finally {
    try { Invoke-Cp 'logout' @{} | Out-Null } catch {}
}
