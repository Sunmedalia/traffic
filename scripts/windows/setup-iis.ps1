param([string]$Root = 'C:\traffic-lab', [switch]$Resume)
$ErrorActionPreference = 'Stop'
$features = @('WAS-WindowsActivationService','WAS-ProcessModel','WAS-ConfigurationAPI','IIS-WebServerRole','IIS-WebServer','IIS-CommonHttpFeatures','IIS-StaticContent','IIS-DefaultDocument','IIS-HttpErrors','IIS-ApplicationDevelopment','IIS-NetFxExtensibility45','IIS-ASPNET45','IIS-ISAPIExtensions','IIS-ISAPIFilter','IIS-ManagementScriptingTools')
function Save-LabState {
    $state | ConvertTo-Json -Depth 5 | Set-Content "$Root\installation.tmp" -Encoding UTF8
    Move-Item "$Root\installation.tmp" "$Root\installation.json" -Force
}
if (!$Resume) {
    if (Test-Path $Root) { throw "Destination already exists: $Root" }
    foreach ($port in @(8080,8443)) {
        if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) { throw "Port $port is occupied" }
    }
    New-Item -ItemType Directory -Path $Root | Out-Null
    $previous = @(Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -match '^(IIS-|WAS-)' } | ForEach-Object {
        @{ FeatureName=$_.FeatureName; State=[string]$_.State }
    })
    $state = [pscustomobject]@{ root=$Root; features=$previous; certificate=$null; site_created=$false; pool_created=$false; firewall_created=$false }
    Save-LabState
} else {
    $state = Get-Content "$Root\installation.json" -Raw | ConvertFrom-Json
    if ($state.root -ne $Root) { throw 'Installation root does not match saved state' }
}
foreach ($property in @('site_created','pool_created','firewall_created')) {
    if (!$state.PSObject.Properties[$property]) { $state | Add-Member -NotePropertyName $property -NotePropertyValue $false }
}
$components = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp\Components' -ErrorAction SilentlyContinue
$required = @('W3SVC','ProcessModel','ASPNET45','ManagementScriptingTools','StaticContent','ISAPIExtensions','ISAPIFilter','HttpErrors','DefaultDocument','NetFxExtensibility45')
$unregistered = @($required | Where-Object { $components.$_ -ne 1 })
if ($unregistered.Count) {
    $featureState = @(Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -in $features })
    foreach ($feature in $featureState) {
        if ($state.features.FeatureName -notcontains $feature.FeatureName) {
            $state.features += [pscustomobject]@{ FeatureName=$feature.FeatureName; State=[string]$feature.State }
        }
    }
    Save-LabState
    $missing = @($featureState | Where-Object { $_.State -eq 'Disabled' } | ForEach-Object { $_.FeatureName })
    if ($missing.Count) {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName $missing -All -NoRestart
        if (@($result | Where-Object RestartNeeded).Count) { throw 'Windows requires a reboot to finish IIS installation. Resume with -Resume after reboot.' }
    }
    $pending = @(Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -in $features -and $_.State -ne 'Enabled' })
    if ($pending.Count) { throw 'IIS features are still pending. Resume with -Resume after the Windows installation reboot.' }
}
Import-Module WebAdministration
if ((Test-Path IIS:\Sites\TrafficLab) -or (Test-Path IIS:\AppPools\TrafficLab)) { throw 'TrafficLab IIS objects already exist' }
New-Item -ItemType Directory "$Root\site" | Out-Null
New-WebAppPool -Name TrafficLab | Out-Null
$state.pool_created = $true
Save-LabState
Set-ItemProperty IIS:\AppPools\TrafficLab -Name managedRuntimeVersion -Value v4.0
New-Website -Name TrafficLab -Port 8080 -PhysicalPath "$Root\site" -ApplicationPool TrafficLab | Out-Null
$state.site_created = $true
Save-LabState
$cert = New-SelfSignedCertificate -DnsName 'traffic-lab','localhost','192.168.1.11' -CertStoreLocation Cert:\LocalMachine\My
$state.certificate = $cert.Thumbprint
Save-LabState
New-WebBinding -Name TrafficLab -Protocol https -Port 8443 -IPAddress '*'
(Get-WebBinding -Name TrafficLab -Protocol https).AddSslCertificate($cert.Thumbprint, 'My')
@'
<configuration>
  <system.webServer>
    <handlers><add name="TrafficLab" path="*" verb="*" type="TrafficLab" resourceType="Unspecified" /></handlers>
    <httpProtocol><customHeaders><add name="X-Traffic-Lab" value="1" /></customHeaders></httpProtocol>
  </system.webServer>
</configuration>
'@ | Set-Content "$Root\site\web.config" -Encoding UTF8
New-Item -ItemType Directory "$Root\site\App_Code" | Out-Null
@'
using System;
using System.IO;
using System.Web;
public class TrafficLab : IHttpHandler {
    public bool IsReusable { get { return true; } }
    public void ProcessRequest(HttpContext c) {
        c.Response.ContentType = "text/plain; charset=utf-8";
        string path = c.Request.Path;
        if (path == "/api/health") { c.Response.Write("healthy"); }
        else if (path == "/api/echo") { c.Request.InputStream.CopyTo(c.Response.OutputStream); }
        else if (path == "/search") { c.Response.Write(c.Request.QueryString["q"] ?? ""); }
        else if (path == "/large") { c.Response.Write(new string('x', 131072)); }
        else if (path == "/chunked") {
            c.Response.BufferOutput = false;
            for (int i=0; i<4; i++) { c.Response.Write("chunk-" + i + "\n"); c.Response.Flush(); }
        }
        else if (path == "/static.txt") { c.Response.TransmitFile(c.Server.MapPath("~/static.txt")); }
        else { c.Response.StatusCode = 404; c.Response.TrySkipIisCustomErrors = true; c.Response.Write("not found"); }
    }
}
'@ | Set-Content "$Root\site\App_Code\TrafficLab.cs" -Encoding UTF8
'traffic static response' | Set-Content "$Root\site\static.txt" -Encoding UTF8
icacls "$Root\site" /grant 'IIS_IUSRS:(OI)(CI)RX' /T | Out-Null
New-Item -ItemType Directory -Force "$Root\probe-runtime" | Out-Null
icacls "$Root\probe-runtime" /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 'IIS AppPool\TrafficLab:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE) { throw 'Cannot grant the test worker read access to the probe runtime directory' }
New-NetFirewallRule -Name TrafficLab-HTTP -DisplayName TrafficLab-HTTP -Direction Inbound -Protocol TCP -LocalPort 8080,8443 -Action Allow | Out-Null
$state.firewall_created = $true
Save-LabState
Start-Website TrafficLab
Invoke-WebRequest -UseBasicParsing http://localhost:8080/api/health | Select-Object StatusCode,Content
Get-Website TrafficLab | Select-Object Name,State,PhysicalPath
