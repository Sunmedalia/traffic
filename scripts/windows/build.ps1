$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '../..')
if (!(Get-Command gcc -ErrorAction SilentlyContinue)) { throw 'Install an x64 MinGW GCC toolchain and put gcc on PATH for SQLite CGO.' }
$env:CGO_ENABLED = '1'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
go mod download
if ($LASTEXITCODE) { throw 'go mod download failed' }
go test ./...
if ($LASTEXITCODE) { throw 'Tests failed' }
go vet ./...
if ($LASTEXITCODE) { throw 'go vet failed' }
New-Item -ItemType Directory -Force bin/windows | Out-Null
go build -trimpath -o bin/windows/traffic.exe ./cmd/traffic
if ($LASTEXITCODE) { throw 'Collector build failed' }
go build -trimpath -o bin/windows/traffic-tui.exe ./cmd/traffic-tui
if ($LASTEXITCODE) { throw 'Analysis build failed' }
Get-FileHash bin/windows/traffic.exe,bin/windows/traffic-tui.exe -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash.ToLower())  $([IO.Path]::GetFileName($_.Path))" } |
    Set-Content bin/windows/SHA256SUMS -Encoding ASCII
