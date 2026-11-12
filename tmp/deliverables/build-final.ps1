param(
  [string]$Out = 'C:\workspace\kali\tmp\preferred-vulnerability-tools.zip',
  [string]$Src = 'C:\workspace\kali\tmp\deliverables',
  [string]$Zips = 'C:\workspace\kali\tmp\lists'
)
# 최종 ZIP 빌드: 스테이징 폴더를 만들어 7z로 압축한다 (PS 5.1 ZipArchive 스트림 복사 불안정 → 7z 고정)
$SevenZip = 'C:\Users\kali\AppData\Local\7-Zip\7z.exe'
$prefix = 'preferred-vulnerability-tools'
$stage = 'C:\workspace\kali\tmp\final-stage'
$items = @(
  @{ s = "$Src\README.md";                              n = 'README.md' },
  @{ s = "$Src\TOOL_LIST.md";                           n = 'TOOL_LIST.md' },
  @{ s = "$Src\HASH_LIST.md";                           n = 'HASH_LIST.md' },
  @{ s = "$Src\setup-windows.ps1";                      n = 'setup-windows.ps1' },
  @{ s = "$Src\setup-kali.sh";                          n = 'setup-kali.sh' },
  @{ s = "$Src\unzip_6.0-31_amd64.deb";                 n = 'unzip_6.0-31_amd64.deb' },
  @{ s = "$Zips\preferred-vulnerability-tools-windows.zip"; n = 'preferred-vulnerability-tools-windows.zip' },
  @{ s = "$Zips\preferred-vulnerability-tools-kali.zip";    n = 'preferred-vulnerability-tools-kali.zip' },
  @{ s = 'C:\workspace\kali\tmp\cheatsheets-final.zip';     n = 'cheatsheets-final.zip' }
)
foreach ($i in $items) { if (-not (Test-Path $i.s)) { Write-Output "MISSING: $($i.s)"; exit 1 } }
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
if (Test-Path $Out)   { Remove-Item -Force $Out }
New-Item -ItemType Directory -Path "$stage\$prefix" -Force | Out-Null
foreach ($i in $items) {
  Copy-Item -Path $i.s -Destination "$stage\$prefix\$($i.n)" -Force
  Write-Output ("ADD {0}  {1}" -f $i.n, (Get-Item $i.s).Length)
}
Push-Location $stage
& $SevenZip a -tzip "$Out" $prefix | Out-Null
Pop-Location
Remove-Item -Recurse -Force $stage
$f = Get-Item $Out
Write-Output ("DONE size={0} sha256={1}" -f $f.Length, (Get-FileHash $Out -Algorithm SHA256).Hash)
