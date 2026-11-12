param([string]$Root = 'C:\traffic-lab', [switch]$RemoveInstalledFeatures)
$ErrorActionPreference = 'Stop'
$state = Get-Content "$Root\installation.json" -Raw | ConvertFrom-Json
if (Get-Module -ListAvailable WebAdministration) {
    Import-Module WebAdministration
    if ($state.site_created -and (Test-Path IIS:\Sites\TrafficLab)) { Remove-Website TrafficLab }
    if ($state.pool_created -and (Test-Path IIS:\AppPools\TrafficLab)) { Remove-WebAppPool TrafficLab }
}
if ($state.firewall_created) { Get-NetFirewallRule -Name TrafficLab-HTTP -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
if ($state.certificate) { Remove-Item "Cert:\LocalMachine\My\$($state.certificate)" -ErrorAction SilentlyContinue }
if ($RemoveInstalledFeatures) {
    $features = @($state.features | Where-Object { $_.State -eq 'Disabled' -or $_.State -eq 0 } | ForEach-Object { $_.FeatureName })
    if ($features.Count) { Disable-WindowsOptionalFeature -Online -FeatureName $features -NoRestart }
}
Write-Output "Removed TrafficLab site, pool, firewall rule and certificate. Files and feature history remain in $Root."
