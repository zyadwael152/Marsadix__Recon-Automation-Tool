<#
  Marsadix - installs the external tools on Windows (amd64).

  Usage (PowerShell):
    powershell -ExecutionPolicy Bypass -File scripts\install-tools.ps1
    powershell -ExecutionPolicy Bypass -File scripts\install-tools.ps1 -InstallDir D:\tools\bin -NoAddToPath

  -InstallDir   where to put the .exe files (default: %USERPROFILE%\marsadix-tools\bin)
  -NoAddToPath  skip adding that folder to YOUR user PATH (it is added by default now)

  naabu may ask for Npcap on Windows (https://npcap.com).

  assetfinder / amass / chaos / alterx / massdns / puredns are Go tools installed via `go install`
  (needs Go: winget install GoLang.Go) instead of guessing a release
  filename. findomain is Rust, not Go, so it's downloaded directly from
  its GitHub release instead.
#>
param(
  [string]$InstallDir = (Join-Path $env:USERPROFILE "marsadix-tools\bin"),
  [switch]$NoAddToPath
)

$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Tmp = Join-Path $env:TEMP "marsadix-tools-tmp"
New-Item -ItemType Directory -Force $InstallDir, $Tmp | Out-Null

$tools = @(
  @{ Name = "subfinder"; Owner = "projectdiscovery" },
  @{ Name = "dnsx";      Owner = "projectdiscovery" },
  @{ Name = "httpx";     Owner = "projectdiscovery" },
  @{ Name = "naabu";     Owner = "projectdiscovery" },
  @{ Name = "katana";    Owner = "projectdiscovery" },
  @{ Name = "nuclei";    Owner = "projectdiscovery" },
  @{ Name = "gau";       Owner = "lc" },
  @{ Name = "ffuf";      Owner = "ffuf" }
)

function Get-LatestTag($owner, $repo) {
  try {
    $req = [System.Net.HttpWebRequest]::Create("https://github.com/$owner/$repo/releases/latest")
    $req.AllowAutoRedirect = $false
    $resp = $req.GetResponse()
    $loc = $resp.Headers["Location"]
    $resp.Close()
    if (-not $loc) { throw "no redirect returned - repo may have no releases" }
    return ($loc -split "/")[-1]
  } catch {
    throw "could not resolve latest release for $owner/$repo : $($_.Exception.Message)"
  }
}

$ok = @()
$failed = @()

foreach ($tool in $tools) {
  $t = $tool.Name; $owner = $tool.Owner
  $exePath = Join-Path $InstallDir "$t.exe"
  if (Test-Path $exePath) {
    Write-Host "[$t] already there" -ForegroundColor Yellow
    $ok += $t
    continue
  }
  try {
    $tag = Get-LatestTag $owner $t
    $ver = $tag.TrimStart("v")
    $downloaded = $null
    $usedName = $null
    foreach ($ext in "zip", "tar.gz") {
      $name = "$($t)_$($ver)_windows_amd64.$ext"
      $file = Join-Path $Tmp $name
      try {
        Invoke-WebRequest "https://github.com/$owner/$t/releases/download/$tag/$name" -OutFile $file -ErrorAction Stop
        $downloaded = $file; $usedName = $name; break
      } catch { Write-Host "[$t] $name not found, trying next..." -ForegroundColor DarkGray }
    }
    if (-not $downloaded) { throw "no windows_amd64 asset found for $tag" }

    $dir = Join-Path $Tmp $t
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $dir | Out-Null
    if ($downloaded.EndsWith(".zip")) { Expand-Archive $downloaded $dir -Force }
    else { tar -xzf $downloaded -C $dir }

    $exe = Get-ChildItem $dir -Recurse -Filter "$t.exe" | Select-Object -First 1
    if (-not $exe) { throw "downloaded ($usedName) but $t.exe was not found inside the archive" }

    Move-Item $exe.FullName $exePath -Force

    # Verify the binary actually runs before declaring success, instead of
    # trusting that "file exists" means "tool works".
    $works = $false
    foreach ($flag in "-version", "--version", "-h") {
      try {
        & $exePath $flag *>$null
        $works = $true
        break
      } catch { }
    }
    if (-not $works) {
      Write-Host "[$t] installed ($usedName) but could not be executed - verify manually" -ForegroundColor Yellow
    } else {
      Write-Host "[$t] installed and verified: $usedName" -ForegroundColor Green
    }

    $ok += $t
    Remove-Item $downloaded, $dir -Recurse -Force -ErrorAction SilentlyContinue
  } catch {
    Write-Host "[$t] FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $failed += $t
  }
}

# --- assetfinder, amass, chaos, alterx, puredns: Go tools, installed with `go install` so we
#     never have to guess a release-asset filename for them. Needs Go.
$goTools = @(
  @{ Name = "assetfinder"; Module = "github.com/tomnomnom/assetfinder@latest" },
  @{ Name = "amass";       Module = "github.com/owasp-amass/amass/v4/...@master" },
  @{ Name = "chaos";       Module = "github.com/projectdiscovery/chaos-client/cmd/chaos@latest" },
  @{ Name = "alterx";      Module = "github.com/projectdiscovery/alterx/cmd/alterx@latest" },
  @{ Name = "puredns";     Module = "github.com/d3mondev/puredns/v2@latest" }
)

$goAvailable = [bool](Get-Command go -ErrorAction SilentlyContinue)
if (-not $goAvailable) {
  Write-Host "[go] not found - Go-based tools need it: winget install GoLang.Go" -ForegroundColor Yellow
}

foreach ($gt in $goTools) {
  $t = $gt.Name
  $exePath = Join-Path $InstallDir "$t.exe"
  if (Test-Path $exePath) {
    Write-Host "[$t] already there" -ForegroundColor Yellow
    $ok += $t
    continue
  }
  if (-not $goAvailable) {
    Write-Host "[$t] SKIPPED: go is not installed" -ForegroundColor Yellow
    $failed += $t
    continue
  }
  try {
    $prevGobin = $env:GOBIN
    $env:GOBIN = $InstallDir
    $goOutput = & go install $gt.Module 2>&1
    $env:GOBIN = $prevGobin
    if (Test-Path $exePath) {
      Write-Host "[$t] installed via go install" -ForegroundColor Green
      $ok += $t
    } else {
      throw "go install finished but $t.exe was not produced. go output: $goOutput"
    }
  } catch {
    Write-Host "[$t] FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $failed += $t
  }
}

# --- massdns: a C program, NOT a Go module (`go install` can never produce it), and the
#     project ships no official Windows binary. puredns (DNS bruteforce) needs it.
#     So this script does not try to build it. Options:
#       1. WSL / Linux:  bash scripts/install-tools.sh     (builds massdns from source)
#       2. Docker:       docker build -t marsadix .         (massdns is built inside the image)
#       3. If you already built massdns.exe yourself (Cygwin/MSYS2), put it in $InstallDir or PATH.
#     Without massdns, Marsadix simply skips the DNS bruteforce step.
$massdnsExe = Join-Path $InstallDir "massdns.exe"
if ((Test-Path $massdnsExe) -or (Get-Command massdns -ErrorAction SilentlyContinue)) {
  Write-Host "[massdns] already there" -ForegroundColor Yellow
  $ok += "massdns"
} else {
  Write-Host "[massdns] SKIPPED: C program with no official Windows build - use WSL or Docker (see comment in this script)" -ForegroundColor Yellow
  $failed += "massdns"
}

# --- findomain: not a Go tool (it's Rust), so it can't use `go install`.
$findomainExe = Join-Path $InstallDir "findomain.exe"
if (Test-Path $findomainExe) {
  Write-Host "[findomain] already there" -ForegroundColor Yellow
  $ok += "findomain"
} else {
  try {
    $tag = Get-LatestTag "Findomain" "findomain"
    $file = Join-Path $Tmp "findomain-windows.zip"
    Invoke-WebRequest "https://github.com/Findomain/findomain/releases/download/$tag/findomain-windows.zip" -OutFile $file -ErrorAction Stop
    $dir = Join-Path $Tmp "findomain"
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $dir | Out-Null
    Expand-Archive $file $dir -Force
    $exe = Get-ChildItem $dir -Recurse -Filter "findomain.exe" | Select-Object -First 1
    if (-not $exe) { throw "findomain.exe not found inside the downloaded archive" }
    Move-Item $exe.FullName $findomainExe -Force
    Write-Host "[findomain] installed: $tag" -ForegroundColor Green
    $ok += "findomain"
    Remove-Item $file, $dir -Recurse -Force -ErrorAction SilentlyContinue
  } catch {
    Write-Host "[findomain] FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  -> download manually from https://github.com/Findomain/findomain/releases" -ForegroundColor Red
    $failed += "findomain"
  }
}

# nmap: install it automatically via winget instead of only printing a hint
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "[nmap] not found, installing via winget..." -ForegroundColor Blue
    try {
      winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements | Out-Null
      Write-Host "[nmap] installed via winget." -ForegroundColor Green
    } catch {
      Write-Host "[nmap] winget install failed: $($_.Exception.Message)" -ForegroundColor Red
      $failed += "nmap"
    }
  } else {
    Write-Host "[nmap] winget not available - install manually: https://nmap.org/download.html" -ForegroundColor Yellow
    $failed += "nmap"
  }
} else {
  Write-Host "[nmap] already installed" -ForegroundColor Yellow
}

# PATH is now added by default (opt out with -NoAddToPath)
if (-not $NoAddToPath) {
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if (-not $userPath) { $userPath = "" }
  if (($userPath -split ";") -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $InstallDir), "User")
    Write-Host "Added $InstallDir to your user PATH. Open a NEW terminal for it to take effect." -ForegroundColor Cyan
  }
}

Write-Host ""
Write-Host "=== Installation report ===" -ForegroundColor Blue
Get-ChildItem $InstallDir -Filter *.exe | Select-Object Name, Length | Format-Table

if ($failed.Count -gt 0) {
  Write-Host ("Failed: " + ($failed -join ", ")) -ForegroundColor Red
} else {
  Write-Host "All tools installed successfully!" -ForegroundColor Green
}

Write-Host "Next: make sure $InstallDir is in PATH, then run:  marsadix doctor"
