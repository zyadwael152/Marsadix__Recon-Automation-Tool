<#
  Marsadix - installs the external tools on Windows (amd64).

  Usage (PowerShell):
    powershell -ExecutionPolicy Bypass -File scripts\install-tools.ps1
    powershell -ExecutionPolicy Bypass -File scripts\install-tools.ps1 -InstallDir D:\tools\bin -AddToPath

  -InstallDir  where to put the .exe files (default: %USERPROFILE%\marsadix-tools\bin)
  -AddToPath   also add that folder to YOUR user PATH (open a NEW terminal afterwards)

  nmap is not included: run   winget install Insecure.Nmap   (or use the installer from nmap.org).
  naabu may ask for Npcap on Windows (https://npcap.com).
#>
param(
  [string]$InstallDir = (Join-Path $env:USERPROFILE "marsadix-tools\bin"),
  [switch]$AddToPath
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
  $req = [System.Net.HttpWebRequest]::Create("https://github.com/$owner/$repo/releases/latest")
  $req.AllowAutoRedirect = $false
  $resp = $req.GetResponse()
  $loc = $resp.Headers["Location"]
  $resp.Close()
  ($loc -split "/")[-1]
}

$failed = @()
foreach ($tool in $tools) {
  $t = $tool.Name; $owner = $tool.Owner
  $exePath = Join-Path $InstallDir "$t.exe"
  if (Test-Path $exePath) { Write-Host "[$t] already there" -ForegroundColor Yellow; continue }
  try {
    $tag = Get-LatestTag $owner $t
    $ver = $tag.TrimStart("v")
    $downloaded = $null
    foreach ($ext in "zip", "tar.gz") {
      $name = "$($t)_$($ver)_windows_amd64.$ext"
      $file = Join-Path $Tmp $name
      try {
        Invoke-WebRequest "https://github.com/$owner/$t/releases/download/$tag/$name" -OutFile $file -ErrorAction Stop
        $downloaded = $file; break
      } catch { Write-Host "[$t] $name not found, trying next..." -ForegroundColor DarkGray }
    }
    if (-not $downloaded) { throw "no windows_amd64 asset found for $tag" }

    $dir = Join-Path $Tmp $t
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $dir | Out-Null
    if ($downloaded.EndsWith(".zip")) { Expand-Archive $downloaded $dir -Force }
    else { tar -xzf $downloaded -C $dir }

    $exe = Get-ChildItem $dir -Recurse -Filter "$t.exe" | Select-Object -First 1
    if ($exe) {
      Move-Item $exe.FullName $exePath -Force
      Write-Host "[$t] installed: $name" -ForegroundColor Green
    } else {
      Write-Host "[$t] downloaded but $t.exe not found" -ForegroundColor Red
      $failed += $t
    }
    Remove-Item $downloaded, $dir -Recurse -Force -ErrorAction SilentlyContinue
  } catch {
    Write-Host "[$t] FAILED: $($_.Exception.Message)" -ForegroundColor Red
    $failed += $t
  }
}

if ($AddToPath) {
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if (-not $userPath) { $userPath = "" }
  if (($userPath -split ";") -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $InstallDir), "User")
    Write-Host "Added $InstallDir to your user PATH. Open a NEW terminal for it to take effect." -ForegroundColor Cyan
  }
}

Write-Host ""
Get-ChildItem $InstallDir -Filter *.exe | Select-Object Name, Length | Format-Table
if ($failed.Count -gt 0) { Write-Host ("Failed: " + ($failed -join ", ")) -ForegroundColor Red }
Write-Host "Next: install nmap (winget install Insecure.Nmap), make sure $InstallDir is in PATH, then run:  marsadix doctor"
