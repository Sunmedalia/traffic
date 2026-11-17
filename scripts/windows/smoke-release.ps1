param([Parameter(Mandatory=$true)][string]$App, [Parameter(Mandatory=$true)][string]$Console)
$ErrorActionPreference = 'Stop'
$App = (Resolve-Path $App).Path
$Console = (Resolve-Path $Console).Path
function Check-Exit { if ($LASTEXITCODE) { throw "Command failed: $LASTEXITCODE" } }
# This test runs on a clean hosted runner with no Npcap installation.
& "$App/traffic.exe" doctor | Tee-Object -FilePath "$App/doctor.json"
Check-Exit
$doctor = Get-Content "$App/doctor.json" -Raw | ConvertFrom-Json
if ($doctor.packet_backend -ne 'windivert-sniff') { throw 'Bundled capture backend was not selected' }
& "$App/deps/python/python.exe" -c "import frida; assert frida.__version__ == '17.5.1'"
Check-Exit
& "$App/deps/python/python.exe" "$App/deps/probes/probe-iis.py" --help
Check-Exit
& "$App/deps/python/python.exe" "$App/deps/probes/probe-openssl.py" --help
Check-Exit
& "$App/traffic.exe" doctor --cn-help
Check-Exit
& "$App/traffic.exe" capture --cn-help
Check-Exit
& "$Console/traffic-console.exe" --help
Check-Exit
$server = $null
$capture = $null
try {
    $server = Start-Process -FilePath "$App/deps/python/python.exe" -ArgumentList '-m http.server 18763 --bind 127.0.0.1' -WorkingDirectory $App -PassThru -RedirectStandardOutput "$App/http.out" -RedirectStandardError "$App/http.err"
    $capture = Start-Process -FilePath "$App/traffic.exe" -ArgumentList 'capture --no-tls --ports 18763 --duration 10s --name portable-smoke' -WorkingDirectory $env:TEMP -PassThru -RedirectStandardOutput "$App/capture.out" -RedirectStandardError "$App/capture.err"
    Start-Sleep -Seconds 3
    if ($capture.HasExited) { throw (Get-Content "$App/capture.err" -Raw) }
    1..4 | ForEach-Object { Invoke-WebRequest 'http://127.0.0.1:18763/?portable-smoke=verified' | Out-Null }
    $capture.WaitForExit(30000) | Out-Null
    if (!$capture.HasExited) { throw 'Capture did not stop after duration' }
    if ($capture.ExitCode -ne 0) { throw (Get-Content "$App/capture.err" -Raw) }
    $index = Get-ChildItem "$App/sessions" -Filter index.sqlite -Recurse | Select-Object -First 1
    $session = if ($index) { $index.Directory } else { $null }
    if (!$session) { throw 'No session saved' }
    & "$Console/traffic-console.exe" status --session $session.FullName
    Check-Exit
    # Verify actual parsed requests in SQLite, not just driver startup.
    & "$App/deps/python/python.exe" -c "import pathlib,sqlite3,sys; p=next(pathlib.Path(sys.argv[1]).rglob('*.sqlite')); db=sqlite3.connect(p); assert db.execute('select count(*) from requests').fetchone()[0] >= 4" $session.FullName
    Check-Exit
} finally {
    if ($capture -and !$capture.HasExited) { Stop-Process -Id $capture.Id -Force }
    if ($server -and !$server.HasExited) { Stop-Process -Id $server.Id -Force }
    Get-Content "$App/capture.out", "$App/capture.err" -ErrorAction SilentlyContinue
}
