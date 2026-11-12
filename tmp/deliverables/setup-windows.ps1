param(
  [string]$Root = (Split-Path -Parent $MyInvocation.MyCommand.Path),
  [string]$Workspace = '',
  [switch]$SkipVerify
)
# ============================================================
# 금융권 모의해킹 패키지 - Windows 일괄 구성 스크립트
# 용도: 이 스크립트가 있는 폴더의 preferred-vulnerability-tools-windows.zip을
#       해제하고, 전제 유틸을 설치하고, 도구를 카테고리별로 정리한 뒤
#       대표 도구를 확인한다. 조직 보안 정책은 변경하거나 우회하지 않는다.
# 사용: PowerShell에서  .\setup-windows.ps1          (전체 진행)
#       .\setup-windows.ps1 -SkipVerify             (검증 생략)
# 관리자 권한이 없어도 진행된다(사용자 디렉터리 설치). 다만 vc_redist,
# Perl, Ruby 같은 시스템 설치는 관리자 권한이 있을 때만 성공한다.
# ============================================================
$ErrorActionPreference = 'Continue'
$Root = (Resolve-Path $Root).Path
if (-not $Workspace) { $Workspace = Join-Path $Root 'workspace' }
$Workspace = [IO.Path]::GetFullPath($Workspace)
$winZip = Join-Path $Root 'preferred-vulnerability-tools-windows.zip'
$cheatZip = Join-Path $Root 'cheatsheets-final.zip'
$warnings = New-Object System.Collections.Generic.List[string]

function Add-Warning {
  param([string]$Message)
  $warnings.Add($Message) | Out-Null
  Write-Output "WARN $Message"
}

function Write-Step { param($m) Write-Output ''; Write-Output "== $m ==" }
function Test-Admin {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Find-7z {
  $c = Get-Command '7z' -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  foreach ($p in @("$env:ProgramFiles\7-Zip\7z.exe", "$env:LOCALAPPDATA\7-Zip\7z.exe")) {
    if (Test-Path $p) { return $p }
  }
  return $null
}
function Invoke-SilentInstall {
  param([string]$Exe, [string[]]$InstallArgs, [string]$Label)
  if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { Add-Warning "$Label 설치 파일 없음; 관련 도구는 수동 설치가 필요할 수 있다: $Exe"; return }
  if (-not (Test-Admin)) { Add-Warning "$Label 설치를 건너뜀; 관리자 권한이 필요하다"; return }
  try {
    if ([IO.Path]::GetExtension($Exe) -ieq '.msi') {
      $argLine = '/i "' + $Exe + '" ' + ($InstallArgs -join ' ')
      $p = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" -ArgumentList $argLine -Wait -PassThru
    } else {
      $p = Start-Process -FilePath $Exe -ArgumentList $InstallArgs -Wait -PassThru
    }
    Write-Output "INSTALL $Label exit=$($p.ExitCode)"
    if ($p.ExitCode -notin @(0, 3010, 1641)) { Add-Warning "$Label 설치기 종료 코드 $($p.ExitCode)"; return }
  } catch {
    Add-Warning "$Label 설치기가 보안 정책 또는 시스템 조건으로 실행되지 않았다: $($_.Exception.Message)"
  }
}
function Find-Py {
  $pyCmd = Get-Command py -ErrorAction SilentlyContinue
  if ($pyCmd) {
    try {
      $v = & $pyCmd.Source -3.13 --version 2>&1
      if ($LASTEXITCODE -eq 0 -and ($v -join ' ') -match 'Python 3\.13') { return @{ Exe = $pyCmd.Source; Args = @('-3.13') } }
    } catch { }
  }
  $pyCmd = Get-Command python -ErrorAction SilentlyContinue
  if ($pyCmd) {
    try {
      $v = & $pyCmd.Source --version 2>$null
      if ($LASTEXITCODE -eq 0 -and "$v" -match '3\.13') { return @{ Exe = $pyCmd.Source; Args = @() } }
    } catch { }
  }
  # PATH에 없어도 등록된 Python이 있으면 쓴다 (설치기가 TargetDir 설치를 생략하는 경우 대비)
  foreach ($k in @('HKCU:\Software\Python\PythonCore\3.13\InstallPath', 'HKLM:\Software\Python\PythonCore\3.13\InstallPath')) {
    if (Test-Path $k) {
      $ip = (Get-ItemProperty $k).'(default)'
      if ($ip -and (Test-Path (Join-Path $ip 'python.exe'))) { return @{ Exe = Join-Path $ip 'python.exe'; Args = @() } }
    }
  }
  return $null
}

Write-Step '0. 준비 확인'
if (-not (Test-Path $winZip)) { Write-Output "오류: $winZip 이 없다. 이 스크립트는 최종 ZIP을 푼 폴더에서 실행한다."; exit 1 }
if (-not [Environment]::Is64BitOperatingSystem) { Write-Output '오류: Windows 도구 ZIP은 x64 운영체제용이다.'; exit 1 }
$osVersion = [Environment]::OSVersion.Version
if ($osVersion.Major -lt 10) { Add-Warning "검증 범위 밖 Windows 버전: $osVersion (Windows 10/11 x64 권장)" }
$driveRoot = [IO.Path]::GetPathRoot($Workspace)
try {
  $drive = [IO.DriveInfo]::new($driveRoot)
  if ($drive.AvailableFreeSpace -lt 20GB) { Write-Output "오류: 설치 공간 부족. 20 GiB 이상 필요, 남은 공간 $([math]::Round($drive.AvailableFreeSpace / 1GB, 1)) GiB"; exit 1 }
} catch { Add-Warning "대상 드라이브의 여유 공간을 확인하지 못했다: $($_.Exception.Message)" }
$isAdmin = Test-Admin
Write-Output "관리자 권한: $isAdmin"
try { New-Item -ItemType Directory -Force -Path $Workspace -ErrorAction Stop | Out-Null }
catch { Write-Output "오류: 작업 폴더를 만들 수 없다: $($_.Exception.Message)"; exit 1 }

Write-Step '1. 7-Zip 확보'
$extractDir = Join-Path $Root 'extract'
$winDir = Join-Path $extractDir 'windows'
$7z = Find-7z
if (-not $7z) {
  $inst7z = Join-Path $winDir 'installers\7z2606-x64.exe'
  if (-not (Test-Path $inst7z)) {
    # ZIP을 풀어야 7z 설치 파일이 나온다. .NET으로 7z 설치 파일만 먼저 꺼낸다.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $za = [System.IO.Compression.ZipFile]::OpenRead($winZip)
    $want = $za.Entries | Where-Object { $_.FullName -like '*installers/7z2606-x64.exe' }
    foreach ($e in $want) {
      $destFile = Join-Path $extractDir $e.FullName.Replace('/', '\')
      New-Item -ItemType Directory -Force -Path (Split-Path $destFile) | Out-Null
      [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $destFile, $true)
    }
    $za.Dispose()
  }
  if (Test-Path $inst7z) {
    try {
      $p = Start-Process -FilePath $inst7z -ArgumentList '/S', "/D=$env:LOCALAPPDATA\7-Zip" -Wait -PassThru
      Write-Output "7-Zip 사용자 디렉터리 설치 exit=$($p.ExitCode)"
      $7z = "$env:LOCALAPPDATA\7-Zip\7z.exe"
    } catch { Write-Output "오류: 7-Zip 설치기가 실행되지 않았다: $($_.Exception.Message)" }
  }
}
if (-not ($7z -and (Test-Path $7z))) { Write-Output '오류: 7-Zip을 확보하지 못했다. installers\7z2606-x64.exe를 수동 설치 후 재실행.'; exit 1 }
Write-Output "7z: $7z"

Write-Step '2. windows ZIP 무결성 검사'
& $7z t $winZip | Select-Object -Last 2
if ($LASTEXITCODE -ne 0) { Write-Output '오류: ZIP 무결성 검사 실패. 파일이 손상됐다.'; exit 1 }

Write-Step '3. windows ZIP 해제'
if (-not (Test-Path (Join-Path $winDir 'INSTALL.md'))) {
  & $7z x $winZip -o"$extractDir" -y -snl- | Select-Object -Last 1
  if ($LASTEXITCODE -ne 0) { throw "Windows ZIP extraction failed (exit $LASTEXITCODE)" }
}
Write-Output "해제 위치: $winDir"
Write-Step '3a. windows payload SHA256 검증'
$sumsFile = Join-Path $extractDir 'SHA256SUMS.txt'
if (-not (Test-Path $sumsFile)) { throw "SHA256SUMS.txt missing: $sumsFile" }
$sumRows = [IO.File]::ReadAllLines($sumsFile, [Text.Encoding]::UTF8)
$sumCount = 0
foreach ($row in $sumRows) {
  if ([string]::IsNullOrWhiteSpace($row)) { continue }
  if ($row -notmatch '^([0-9a-fA-F]{64})\s+(.+)$') { throw "Invalid hash row: $row" }
  $expected = $Matches[1].ToLowerInvariant()
  $relative = $Matches[2].TrimStart('*').Replace('/', '\')
  if ([IO.Path]::IsPathRooted($relative) -or $relative.Split('\') -contains '..') { throw "Unsafe hash path: $relative" }
  $target = Join-Path $winDir $relative
  if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw "Missing payload file: $relative" }
  $actual = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "SHA256 mismatch: $relative" }
  $sumCount++
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$za = [IO.Compression.ZipFile]::OpenRead($winZip)
try { $expectedCount = @($za.Entries | Where-Object { -not $_.FullName.EndsWith('/') -and $_.FullName -notin @('SHA256SUMS.txt', 'MANIFEST.md') }).Count } finally { $za.Dispose() }
if ($sumCount -ne $expectedCount) { throw "SHA256 rows ($sumCount) != payload files ($expectedCount)" }
Write-Output "SHA256 PASS: $sumCount files"

Write-Step '4. 치트시트 해제'
if (Test-Path $cheatZip) {
  $cheatDir = Join-Path $Root 'cheatsheets'
  if (-not (Test-Path $cheatDir)) { & $7z x $cheatZip -o"$Root" -y -snl- | Select-Object -Last 1
    if ($LASTEXITCODE -ne 0) { throw "Cheatsheet ZIP extraction failed (exit $LASTEXITCODE)" } }
  Write-Output "치트시트: $cheatDir"
} else { Write-Output 'cheatsheets-final.zip이 없어 생략' }

Write-Step '5. 전제 유틸 설치 (있으면 건너뜀)'
$inst = Join-Path $winDir 'installers'
$needVC64 = -not (Test-Path "$env:SystemRoot\System32\vcruntime140.dll")
$needVC86 = -not (Test-Path "$env:SystemRoot\SysWOW64\vcruntime140.dll")
if ($needVC64) { Invoke-SilentInstall "$inst\vc_redist.x64.exe" @('/install', '/quiet', '/norestart') 'vc_redist.x64 (postgresql, mariadb 전제)' } else { Write-Output 'SKIP vc_redist.x64 (이미 있음)' }
if ($needVC86) { Invoke-SilentInstall "$inst\VC_redist.x86.exe" @('/install', '/quiet', '/norestart') 'VC_redist.x86 (feroxbuster 32bit 전제)' } else { Write-Output 'SKIP VC_redist.x86 (이미 있음)' }

$py = Find-Py
if (-not $py) {
  $pyTarget = Join-Path $Workspace 'runtime\py313'
  try {
    $p = Start-Process -FilePath "$inst\python-3.13.7-amd64.exe" -ArgumentList '/quiet', 'InstallAllUsers=0', "TargetDir=$pyTarget", 'Include_launcher=0', 'InstallLauncherAllUsers=0', 'PrependPath=0' -Wait -PassThru
    Write-Output "INSTALL python 3.13.7 (사용자 디렉터리 $pyTarget) exit=$($p.ExitCode)"
    if ($p.ExitCode -notin @(0, 3010, 1641)) { Add-Warning "Python 설치기 종료 코드 $($p.ExitCode)" }
  } catch { Add-Warning "Python 설치기가 보안 정책 또는 시스템 조건으로 실행되지 않았다: $($_.Exception.Message)" }
  if (Test-Path (Join-Path $pyTarget 'python.exe')) {
    $py = @{ Exe = Join-Path $pyTarget 'python.exe'; Args = @() }
  } else {
    # 같은 버전이 이미 등록돼 있으면 설치기가 TargetDir 설치를 생략한다. 등록 위치를 찾아 쓴다.
    foreach ($k in @('HKCU:\Software\Python\PythonCore\3.13\InstallPath', 'HKLM:\Software\Python\PythonCore\3.13\InstallPath')) {
      if (Test-Path $k) {
        $ip = (Get-ItemProperty $k).'(default)'
        if ($ip -and (Test-Path (Join-Path $ip 'python.exe'))) { $py = @{ Exe = Join-Path $ip 'python.exe'; Args = @() }; break }
      }
    }
    if ($py) { Write-Output "등록된 Python 사용: $($py.Exe)" } else { Add-Warning 'Python을 확보하지 못해 Python 기반 도구 설치와 검증을 건너뛴다.' }
  }
} else { Write-Output "SKIP python (이미 있음: $($py.Exe) $($py.Args))" }

$jdkHome = $null
foreach ($d in @("$env:ProgramFiles\Eclipse Adoptium", "$env:ProgramFiles\Java", (Join-Path $Workspace 'runtime'))) {
  if (-not (Test-Path $d)) { continue }
  $j = Get-ChildItem $d -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'bin\java.exe') } | Select-Object -First 1
  if ($j) { $jdkHome = $j.FullName; break }
}
if (-not $jdkHome) {
  $runtimeDir = Join-Path $Workspace 'runtime'
  & $7z x "$winDir\portable\OpenJDK21U-jdk_x64_windows_hotspot_21.0.13_9.zip" -o"$runtimeDir" -y -snl- | Out-Null
  if ($LASTEXITCODE -ne 0) { Add-Warning "JDK 압축 해제 실패 (exit $LASTEXITCODE)" }
  $j = Get-ChildItem $runtimeDir -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'bin\java.exe') } | Select-Object -First 1
  if ($j) { $jdkHome = $j.FullName }
  Write-Output "INSTALL JDK 21 -> $jdkHome"
} else { Write-Output "SKIP JDK (이미 있음: $jdkHome)" }
if ($jdkHome) { $env:JAVA_HOME = $jdkHome; $env:Path = "$jdkHome\bin;$env:Path" }

if (-not (Get-Command perl -ErrorAction SilentlyContinue)) { Invoke-SilentInstall "$inst\strawberry-perl-5.42.3.1-64bit.msi" @('/quiet', '/norestart') 'Strawberry Perl (nikto 전제)' } else { Write-Output 'SKIP perl (이미 있음)' }
if (-not (Get-Command ruby -ErrorAction SilentlyContinue)) { Invoke-SilentInstall "$inst\rubyinstaller-4.0.9-1-x64.exe" @('/verysilent', '/norestart') 'RubyInstaller (whatweb 전제)' } else { Write-Output 'SKIP ruby (이미 있음)' }

Write-Step '6. 도구 카테고리별 정리'
$portable = Join-Path $winDir 'portable'
$cat = [ordered]@{
  'recon'            = @('ffuf', 'gobuster', 'subfinder', 'dnsx', 'httpx_', 'katana', 'naabu', 'feroxbuster', 'rustscan', 'nuclei_', 'nuclei-templates', 'amass', 'trufflehog', 'gitleaks', 'dirsearch', 'Sublist3r', 'dnsrecon', 'WhatWeb', 'nikto', 'Arjun')
  'web'              = @('sqlmap', 'commix', 'jwt_tool', 'php_filter_chain', 'dalfox', 'weevely')
  'active-directory' = @('SharpCollection', 'SharpHound', 'BloodHound', 'Certipy', 'Coercer', 'PetitPotam', 'NetExec', 'impacket', 'mimikatz', 'GodPotato', 'JuicyPotato', 'RoguePotato', 'PrintSpoofer', 'Snaffler', 'nishang', 'PowerSploit', 'ysoserial')
  'cracking'         = @('hashcat', 'john-', 'hashID')
  'mobile'           = @('jadx', 'apktool', 'MobSF', 'platform-tools')
  'forensics'        = @('rizin', 'ghidra')
  'services'         = @('postgresql', 'mariadb', 'redis', 'mongosh', 'HeidiSQL', 'sqlcmd')
  'pivoting'         = @('chisel', 'ligolo', 'socat', 'putty')
  'windows'          = @('SysinternalsSuite', 'SystemInformer', 'winPEAS', 'Greenshot', 'dnSpy', 'trivy')
  'util'             = @('jq', 'CyberChef', 'exiftool', 'GTFOBins', 'sonarqube')
}
function Get-Category {
  param([string]$Name)
  foreach ($k in $cat.Keys) { foreach ($pat in $cat[$k]) { if ($Name -like "*$pat*") { return $k } } }
  return 'misc'
}
$archives = Get-ChildItem $portable -File | Where-Object { $_.Extension -in '.zip', '.7z', '.gz', '.tgz' -and $_.BaseName -notlike 'OpenJDK*' }
foreach ($a in $archives) {
  $c = Get-Category $a.BaseName
  $dest = Join-Path $Workspace (Join-Path $c $a.BaseName)
  if (-not (Test-Path $dest)) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    & $7z x $a.FullName -o"$dest" -y -snl- | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Archive extraction failed: $($a.Name) (exit $LASTEXITCODE)" }
    $inner = Get-ChildItem $dest -Filter '*.tar' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($inner) { & $7z x $inner.FullName -o"$dest" -y -snl- | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Nested archive extraction failed: $($inner.Name) (exit $LASTEXITCODE)" }
      Remove-Item $inner.FullName -Force }
  }
}
foreach ($e in (Get-ChildItem $portable -File | Where-Object { $_.Extension -in '.exe', '.jar' })) {
  $c = Get-Category $e.BaseName
  $dest = Join-Path $Workspace $c
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  if (-not (Test-Path (Join-Path $dest $e.Name))) { Copy-Item $e.FullName $dest }
}
foreach ($pair in @(@('wordlists', 'wordlists'), @('extensions', 'burp-extensions'))) {
  $srcSub = Join-Path $winDir $pair[0]
  if (Test-Path $srcSub) {
    $dest = Join-Path $Workspace $pair[1]
    if (-not (Test-Path $dest)) { Copy-Item $srcSub $dest -Recurse }
  }
}
Write-Output "정리 위치: $Workspace"
Get-ChildItem $Workspace -Directory | ForEach-Object { '{0,-18} {1}개 항목' -f $_.Name, @(Get-ChildItem $_.FullName).Count }

Write-Step '7. Python 도구 오프라인 설치 (wheel)'
$venv = Join-Path $Workspace 'py-venv'
$vp = Join-Path $venv 'Scripts\python.exe'
if ($py) {
  if (-not (Test-Path $venv)) { & $py.Exe @($py.Args + '-m') venv $venv }
  if (Test-Path $vp) {
    & $vp -m pip install -q --no-index --find-links "$winDir\pip-wheels" --no-build-isolation httpie wfuzz wafw00f impacket pypykatz certipy-ad coercer objection frida-tools semgrep bandit bloodhound volatility3 pyjwt hashID ratelimit termcolor 2>&1 | Select-Object -Last 2
    $wheelExit = $LASTEXITCODE
    Write-Output "wheel installation exit code: $wheelExit (venv: $venv)"
    if ($wheelExit -ne 0) { Write-Output "ERROR: offline wheel installation failed"; exit $wheelExit }
  } else { Write-Output "ERROR: venv python missing ($vp)."; exit 1 }
  # DNSRecon is isolated because its dnspython constraint conflicts with Certipy.
  $sourceToolSpecs = @(
    @{ Name='dnsrecon'; Dir=(Join-Path $Workspace 'recon\src-darkoperator-dnsrecon-master\dnsrecon-master'); Packages=@('dnspython','netaddr','httpx','loguru','fastapi','uvicorn[standard]','slowapi','stamina','ujson') }
  )
  foreach ($spec in $sourceToolSpecs) {
    $sourceVenv = Join-Path $Workspace ("py-venv-" + $spec.Name)
    if (-not (Test-Path $sourceVenv)) { & $py.Exe @($py.Args + '-m') venv $sourceVenv }
    $sourcePython = Join-Path $sourceVenv 'Scripts\python.exe'
    if (-not (Test-Path $spec.Dir)) { Add-Warning "Python 소스 누락: $($spec.Name)"; continue }
    & $sourcePython -m pip install -q --no-index --find-links "$winDir\pip-wheels" setuptools wheel @($spec.Packages) 2>&1 | Select-Object -Last 2
    $sourceExit = $LASTEXITCODE
    if ($sourceExit -eq 0) { & $sourcePython -m pip install -q --no-index --find-links "$winDir\pip-wheels" --no-build-isolation --no-deps $spec.Dir 2>&1 | Select-Object -Last 2; $sourceExit = $LASTEXITCODE }
    Write-Output "$($spec.Name) offline venv install exit code: $sourceExit"
    if ($sourceExit -ne 0) { Write-Output "ERROR: offline source install failed ($($spec.Name))"; exit $sourceExit }
  }
} else {
  Add-Warning 'Python이 준비되지 않아 Python 기반 도구 설치와 검증을 건너뛴다.'
}
if ($SkipVerify) { Write-Output ''; if ($warnings.Count) { Write-Output "SETUP_DONE_WITH_WARNINGS ($($warnings.Count)); 검증 생략됨" } else { Write-Output 'SETUP_DONE (검증 생략됨)' }; exit 0 }

Write-Step '8. 전 도구 실행 검증'
$results = New-Object System.Collections.Generic.List[string]
function Find-One {
  param([string]$Dir, [string]$Filter)
  # 주의: 이 환경의 PowerShell 5.1은 와일드카드 경로 + -Recurse 조합에서 결과가 0개가 된다.
  # 먼저 와일드카드를 해석한 뒤 재귀 탐색한다.
  $f = Get-ChildItem -Path $Dir -ErrorAction SilentlyContinue |
       Get-ChildItem -Recurse -Filter $Filter -File -ErrorAction SilentlyContinue |
       Select-Object -First 1
  if ($f) { return $f.FullName }
  return $null
}
function Invoke-ToolCapture {
  param([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds = 15)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FilePath
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.Arguments = [string]::Join(' ', @($Arguments | ForEach-Object { if ($_ -match '[\s"]') { '"' + $_.Replace('"', '\"') + '"' } else { $_ } }))
  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  try {
    if (-not $proc.Start()) { return [pscustomobject]@{ ExitCode = -999; Output = ''; TimedOut = $false } }
    $stdout = $proc.StandardOutput.ReadToEndAsync()
    $stderr = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
      $proc.Kill(); $proc.WaitForExit()
      return [pscustomobject]@{ ExitCode = -999; Output = 'TIMEOUT'; TimedOut = $true }
    }
    $proc.WaitForExit()
    return [pscustomobject]@{ ExitCode = $proc.ExitCode; Output = ($stdout.Result + [Environment]::NewLine + $stderr.Result); TimedOut = $false }
  } catch {
    return [pscustomobject]@{ ExitCode = -999; Output = $_.Exception.Message; TimedOut = $false }
  } finally { $proc.Dispose() }
}
function Test-Tool {
  param([string]$Name, [string]$Exe, [string[]]$ToolArgs = @('--version'))
  if (-not ($Exe -and (Test-Path -LiteralPath $Exe -PathType Leaf))) { $results.Add("WARN $Name (파일 없음; 보안 제품 격리 또는 선택 구성일 수 있음)"); return }
  $r = Invoke-ToolCapture $Exe $ToolArgs
  $out = ($r.Output -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
  if ($r.TimedOut) { $results.Add("WARN $Name (15초 안에 smoke test가 끝나지 않음)") }
  elseif ($r.Output -match '(?i)Application Control|WDAC|blocked this file|CodeIntegrity|policy has blocked|Operation not permitted') { $results.Add("BLOCKED $Name (호스트 보안 정책이 실행을 차단함: $out)") }
  elseif ($r.Output -match '(?i)Traceback|ModuleNotFoundError|ImportError|No module named|DLL load failed|Cannot load module') { $results.Add("FAIL $Name (의존성 또는 런타임 오류: $out)") }
  elseif ($r.ExitCode -eq 0) { $results.Add(("PASS {0} {1}" -f $Name, $out)) }
  elseif (($ToolArgs -contains '--help' -or $ToolArgs -contains '-h') -and $r.Output -match '(?i)usage|options|name:') { $results.Add(("PASS {0} {1}" -f $Name, $out)) }
  elseif ([string]::IsNullOrWhiteSpace($r.Output)) { $results.Add("WARN $Name (exit=$($r.ExitCode), 출력 없음; 보안 정책 또는 런처 호환성 확인 필요)") }
  else { $results.Add("FAIL $Name (exit=$($r.ExitCode); $out)") }
}
$W = $Workspace
function Test-PyScript {
  param([string]$Name, [string]$Script, [string[]]$ToolArgs = @('--version'), [string]$PythonExe = $vp)
  if (-not ($Script -and (Test-Path -LiteralPath $Script -PathType Leaf))) { $results.Add("WARN $Name (소스 파일 없음; 보안 제품 격리 또는 선택 구성일 수 있음)"); return }
  if (-not ($PythonExe -and (Test-Path -LiteralPath $PythonExe -PathType Leaf))) { $results.Add("WARN $Name (Python 런타임 없음)"); return }
  $r = Invoke-ToolCapture $PythonExe (@($Script) + $ToolArgs)
  $out = ($r.Output -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
  if ($r.TimedOut) { $results.Add("WARN $Name (15초 안에 smoke test가 끝나지 않음)") }
  elseif ($r.Output -match '(?i)Application Control|WDAC|blocked this file|CodeIntegrity|policy has blocked|Operation not permitted') { $results.Add("BLOCKED $Name (호스트 보안 정책이 실행을 차단함: $out)") }
  elseif ($r.Output -match '(?i)Traceback|ModuleNotFoundError|ImportError|No module named|NativeCommandFailed') { $results.Add("FAIL $Name (Python dependency/runtime error: $out)") }
  elseif ($r.ExitCode -eq 0) { $results.Add(("PASS {0} {1}" -f $Name, $out)) }
  elseif (($ToolArgs -contains '--help' -or $ToolArgs -contains '-h') -and $r.Output -match '(?i)usage|options') { $results.Add(("PASS {0} {1}" -f $Name, $out)) }
  else { $results.Add("FAIL $Name (exit=$($r.ExitCode); $out)") }
}
Test-Tool 'ffuf'        (Find-One "$W\recon\ffuf*" 'ffuf.exe')        @('-V')
Test-Tool 'gobuster'    (Find-One "$W\recon\gobuster*" 'gobuster.exe') @('--help')
Test-Tool 'nuclei'      (Find-One "$W\recon\nuclei_3*" 'nuclei.exe')   @('-version')
Test-Tool 'subfinder'   (Find-One "$W\recon\subfinder*" 'subfinder.exe') @('-version')
Test-Tool 'dnsx'        (Find-One "$W\recon\dnsx*" 'dnsx.exe')        @('-version')
Test-Tool 'httpx'       (Find-One "$W\recon\httpx_*" 'httpx.exe')     @('-version')
Test-Tool 'katana'      (Find-One "$W\recon\katana*" 'katana.exe')    @('-version')
Test-Tool 'naabu'       (Find-One "$W\recon\naabu*" 'naabu.exe')      @('-version')
Test-Tool 'feroxbuster' (Find-One "$W\recon\feroxbuster*" 'feroxbuster.exe') @('--version')
Test-Tool 'gitleaks'    (Find-One "$W\recon\gitleaks*" 'gitleaks.exe') @('version')
Test-Tool 'amass'       (Find-One "$W\recon\amass*" 'amass.exe')      @('-version')
Test-Tool 'trufflehog'  (Find-One "$W\recon\trufflehog*" 'trufflehog.exe') @('--version', 'version')
Test-Tool 'rustscan'    (Find-One "$W\recon\*rustscan*" '*.exe')      @('--version')
Test-PyScript 'sqlmap'      (Find-One "$W\web\*sqlmap*" 'sqlmap.py')      @('--version')
Test-PyScript 'commix'      (Find-One "$W\web\*commix*" 'commix.py')
Test-PyScript 'jwt_tool'    (Find-One "$W\web\*jwt_tool*" 'jwt_tool.py') @('--help')
Test-Tool 'dalfox'      (Find-One "$W\web\dalfox*" 'dalfox.exe')      @('--help')
Test-Tool 'hashcat'     (Find-One "$W\cracking\hashcat*" 'hashcat.exe') @('-V')
Test-Tool 'john'        (Find-One "$W\cracking\john-*" 'john.exe')    @('--list=build-info')
Test-Tool 'chisel'      (Find-One "$W\pivoting\chisel*" '*.exe')      @('--help')
Test-Tool 'ligolo'      (Find-One "$W\pivoting\ligolo*agent*" '*.exe') @('--help')
Test-Tool 'plink'       (Find-One "$W\pivoting\putty*" 'plink.exe')   @('-V')
Test-Tool 'jq'          (Find-One "$W\util" 'jq-windows-amd64.exe')   @('--version')
Test-Tool 'exiftool'    (Find-One "$W\util\exiftool*" 'exiftool(-k).exe') @('-ver')
Test-Tool 'rizin'       (Find-One "$W\forensics\rizin*" 'rizin.exe')  @('-v')
Test-Tool 'trivy'       (Find-One "$W\windows\trivy*" 'trivy.exe')    @('--version')
Test-Tool 'sqlcmd'      (Find-One "$W\services\sqlcmd*" 'sqlcmd.exe') @('--version')
Test-PyScript 'dirsearch' (Find-One "$W\recon\dirsearch*" 'dirsearch.py') @('--version')
Test-PyScript 'Sublist3r' (Find-One "$W\recon\*Sublist3r*" 'sublist3r.py') @('-h')
Test-PyScript 'dnsrecon' (Find-One "$W\recon\*dnsrecon*" 'dnsrecon.py') @('--help') (Join-Path $Workspace 'py-venv-dnsrecon\Scripts\python.exe')
Test-PyScript 'php_filter_chain_generator' (Find-One "$W\web\*php_filter_chain*" 'php_filter_chain_generator.py') @('--help')
Test-Tool 'wafw00f' (Join-Path $venv 'Scripts\wafw00f.exe') @('--version')
Test-Tool 'wfuzz' (Join-Path $venv 'Scripts\wfuzz.exe') @('--help')
Test-Tool 'certipy' (Join-Path $venv 'Scripts\certipy.exe') @('--version')
Test-Tool 'coercer' (Join-Path $venv 'Scripts\Coercer.exe') @('--help')
Test-Tool 'bloodhound-python' (Join-Path $venv 'Scripts\bloodhound-python.exe') @('--help')
Test-Tool 'pypykatz' (Join-Path $venv 'Scripts\pypykatz.exe') @('--help')
Test-Tool 'volatility3' (Join-Path $venv 'Scripts\vol.exe') @('--help')
Test-Tool 'bandit' (Join-Path $venv 'Scripts\bandit.exe') @('--version')
Test-Tool 'semgrep' (Join-Path $venv 'Scripts\semgrep.exe') @('--version')
Test-Tool 'frida' (Join-Path $venv 'Scripts\frida.exe') @('--version')
if ($jdkHome) {
  Test-Tool 'java' (Join-Path $jdkHome 'bin\java.exe') @('-version')
  $jadx = Find-One "$W\mobile\jadx*" 'jadx.bat'
  if ($jadx) {
    try { $out = (& $jadx --version 2>&1 | Where-Object { "$_".Trim() } | Select-Object -First 1); if ($out) { $results.Add("PASS jadx $out") } else { $results.Add('WARN jadx (실행 결과 없음)') } }
    catch { if ($_.Exception.Message -match '(?i)Application Control|blocked|policy') { $results.Add('BLOCKED jadx (호스트 보안 정책)') } else { $results.Add("WARN jadx ($($_.Exception.Message))") } }
  } else { $results.Add('WARN jadx (파일 없음)') }
  $apkJar = Get-ChildItem "$W\mobile" -Filter 'apktool*.jar' -File -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($apkJar) {
    try { $out = (& (Join-Path $jdkHome 'bin\java.exe') -jar $apkJar.FullName --version 2>&1 | Where-Object { "$_".Trim() } | Select-Object -First 1); if ($out) { $results.Add("PASS apktool $out") } else { $results.Add('WARN apktool (실행 결과 없음)') } }
    catch { if ($_.Exception.Message -match '(?i)Application Control|blocked|policy') { $results.Add('BLOCKED apktool (호스트 보안 정책)') } else { $results.Add("WARN apktool ($($_.Exception.Message))") } }
  } else { $results.Add('WARN apktool (파일 없음)') }
}
$h = Join-Path $venv 'Scripts\http.exe'
if (Test-Path $h) {
  # httpie --version은 경고 노이즈와 함께 비정상 종료 코드를 낼 수 있어 기능 테스트로 대신한다:
  # 임시 응답 서버를 띄워 실제 GET이 성공하는지 확인한다.
  $j = $null
  try {
    $j = Start-Job {
      $l = New-Object System.Net.HttpListener
      $l.Prefixes.Add('http://127.0.0.1:18077/')
      $l.Start()
      $c = $l.GetContext()
      $b = [Text.Encoding]::UTF8.GetBytes('HTTPTESTPAGE-OK')
      $c.Response.OutputStream.Write($b, 0, $b.Length)
      $c.Response.Close()
      Start-Sleep -Seconds 2
      $l.Stop()
    }
    Start-Sleep -Seconds 2
    $httpResult = Invoke-ToolCapture $h @('GET', 'http://127.0.0.1:18077/')
    if ($httpResult.Output -match '(?i)Application Control|WDAC|blocked this file|policy has blocked') { $results.Add('BLOCKED httpie (호스트 보안 정책)') }
    elseif ($httpResult.Output -match 'HTTPTESTPAGE-OK') { $results.Add('PASS httpie (로컬 GET 기능 테스트)') }
    else { $results.Add("FAIL httpie (exit=$($httpResult.ExitCode))") }
  } catch {
    if ($_.Exception.Message -match '(?i)Application Control|blocked|policy') { $results.Add('BLOCKED httpie (호스트 보안 정책)') }
    else { $results.Add("WARN httpie smoke test ($($_.Exception.Message))") }
  } finally {
    if ($j) { Stop-Job $j -ErrorAction SilentlyContinue; Remove-Job $j -Force -ErrorAction SilentlyContinue }
  }
} else { $results.Add('WARN httpie (런처 없음; 보안 제품 격리 또는 선택 구성일 수 있음)') }
$smb = Join-Path $venv 'Scripts\smbclient.py'
Test-PyScript 'impacket' $smb @('--help')
$results | Sort-Object | ForEach-Object { Write-Output $_ }
$pass = @($results | Where-Object { $_ -like 'PASS*' }).Count
$blocked = @($results | Where-Object { $_ -like 'BLOCKED*' }).Count
$testWarnings = @($results | Where-Object { $_ -like 'WARN*' }).Count
$fail = @($results | Where-Object { $_ -like 'FAIL*' }).Count
Write-Output "결과: PASS $pass / BLOCKED $blocked / WARN $testWarnings / FAIL $fail"
Write-Output '참고: BLOCKED 항목은 Windows 호스트 보안 정책을 변경하지 않고 건너뛴다. 허용된 도구와 실행 경로를 현장 관리자에게 확인한다.'

Write-Step '9. 완료 요약'
Write-Output "workspace : $Workspace"
Write-Output "치트시트  : $(Join-Path $Root 'cheatsheets')"
Write-Output "installers: $inst (Burp, DBeaver, Fiddler 등 GUI 프로그램은 여기서 수동 설치)"
Write-Output 'PATH 추가 권장: workspace 하위 카테고리 폴더를 필요에 따라 PATH에 추가'
if ($fail -gt 0) { Write-Output 'SETUP_FAILED (Python 설치, 무결성 또는 도구 런타임 오류 확인 필요)'; exit 1 }
if ($warnings.Count -gt 0 -or $blocked -gt 0 -or $testWarnings -gt 0) { Write-Output "SETUP_DONE_WITH_WARNINGS (setup=$($warnings.Count), blocked=$blocked, warn=$testWarnings)"; exit 0 }
Write-Output 'SETUP_DONE'
