# Builds the Windows binaries into dist\<arch>\ on a Windows machine.
#   .\scripts\build.ps1              version from `git describe`
#   .\scripts\build.ps1 -Version 1.0.0
param([string]$Version = "")
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (-not $Version) { $Version = (git describe --tags --always 2>$null); if (-not $Version) { $Version = "dev" } }
$Version = $Version.TrimStart("v")
$ldflags = "-s -w -X main.version_=$Version -buildid="
Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue
foreach ($arch in "amd64", "arm64") {
  New-Item -ItemType Directory -Force "dist\$arch" | Out-Null
  $env:GOOS = "windows"; $env:GOARCH = $arch; $env:CGO_ENABLED = "0"
  go build -trimpath -ldflags "$ldflags" -o "dist\$arch\zsp.exe" .
  go build -trimpath -ldflags "$ldflags -H=windowsgui" -o "dist\$arch\zspw.exe" .
}
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
Get-ChildItem dist\*\*.exe | Get-FileHash -Algorithm SHA256 |
  ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), (Resolve-Path -Relative $_.Path).TrimStart(".\").Replace("dist\", "").Replace("\", "/") } |
  Tee-Object dist\SHA256SUMS.txt
