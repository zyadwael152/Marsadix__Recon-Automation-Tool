<#
  Marsadix - installs the external tools on Windows (amd64).

  Usage (PowerShell):
    powershell -ExecutionPolicy Bypass -File scripts\install-tools.ps1
    powershell -ExecutionPolicy Bypass -File scripts\install-tools.ps1 -InstallDir D:\tools\bin -NoAddToPath

  -InstallDir   where to put the .exe files (default: %USERPROFILE%\marsadix-tools\bin)
  -NoAddToPath  skip adding that folder to YOUR user PATH (it is added by default now)

  naabu may ask for Npcap on Windows (https://npcap.com).

  NOTE: assetfinder / chaos / amass / findomain are installed by the Linux/macOS
  script (install-tools.sh) but NOT by this script, because their release asset
  names don't follow the same "<tool>_<ver>_windows_amd64.zip" pattern used by
  the tools below, and guessing wrong filenames would silently ship a broken
  installer. For full tool parity on Windows, either run the project under WSL,
  or install Go for Windows and run `go install <pkg>@latest` for those four.
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

# PATH is now added by default (opt out with -NoAddToPath), since tools
# that download fine but never run from any shell defeat the point.
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

Write-Host "Note: assetfinder / chaos / amass / findomain aren't covered here (see header comment) - use WSL for full parity with install-tools.sh." -ForegroundColor DarkYellow
Write-Host "Next: make sure $InstallDir is in PATH, then run:  marsadix doctor"
