# Puts the SHA-256 of the published release zips into the winget manifest and the Homebrew cask.
# Run from the repo root, after GitHub Actions has published the release for VERSION in n8mouse.py:
#     powershell -ExecutionPolicy Bypass -File packaging\update-hashes.ps1
# Changes two files and commits nothing.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"            # PS 5.1 downloads crawl with the progress bar
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$v = (Select-String -Path n8mouse.py -Pattern '^VERSION = "(.+)"').Matches[0].Groups[1].Value
$wy = "packaging\winget\n8dog.n8mouse.installer.yaml"
$rb = "packaging\homebrew\n8mouse.rb"
$url = (Select-String -Path $wy -Pattern 'InstallerUrl: (\S+)').Matches[0].Groups[1].Value
if ($url -notlike "*/v$v/*") { throw "$wy points at $url, not at v$v. Bump the version first." }
$base = $url.Substring(0, $url.LastIndexOf("/"))
$tmp = Join-Path $env:TEMP "n8mouse-hashes"
New-Item -ItemType Directory -Force $tmp | Out-Null
$hash = @{}
foreach ($z in "n8mouse-windows-x64.zip", "n8mouse-macos-arm64.zip") {
    Invoke-WebRequest "$base/$z" -OutFile "$tmp\$z" -UseBasicParsing
    Invoke-WebRequest "$base/$z.sha256" -OutFile "$tmp\$z.sha256" -UseBasicParsing
    $said = (Get-Content "$tmp\$z.sha256" -Raw).Trim().ToLower()
    $got = (Get-FileHash "$tmp\$z" -Algorithm SHA256).Hash.ToLower()
    if ($said -notmatch '^[0-9a-f]{64}$' -or $said -ne $got) { throw "$z does not match its .sha256 file" }
    $hash[$z] = $got
    Write-Host ("{0,-26} {1}" -f $z, $got)
}
Remove-Item $tmp -Recurse -Force
$t = [IO.File]::ReadAllText((Resolve-Path $wy))
$t = $t -replace 'InstallerSha256: .*', ("InstallerSha256: " + $hash["n8mouse-windows-x64.zip"].ToUpper())
[IO.File]::WriteAllText((Resolve-Path $wy), $t)
$t = [IO.File]::ReadAllText((Resolve-Path $rb))
$t = $t -replace 'sha256 ".*"', ('sha256 "' + $hash["n8mouse-macos-arm64.zip"] + '"')
[IO.File]::WriteAllText((Resolve-Path $rb), $t)
Write-Host "updated $wy and $rb for v$v" -ForegroundColor Green
