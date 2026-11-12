param(
  [string]$Src = 'C:\workspace\kali\tmp\cheatsheets',
  [string]$Out = 'C:\workspace\kali\tmp\cheatsheets-final.zip'
)
# 치트시트 재빌드: cheatsheets/ 접두사로 전체 md를 ZIP에 담는다.
Add-Type -AssemblyName System.IO.Compression
$fs = [IO.File]::Open($Out, [IO.FileMode]::Create)
$za = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
$rootDir = $za.CreateEntry('cheatsheets/')
$rootDir.Open().Dispose()
$files = Get-ChildItem $Src -Recurse -File
foreach ($f in $files) {
  $rel = 'cheatsheets/' + $f.FullName.Substring($Src.Length + 1).Replace('\', '/')
  $e = $za.CreateEntry($rel, [IO.Compression.CompressionLevel]::Optimal)
  $es = $e.Open(); $src = $f.OpenRead()
  $src.CopyTo($es)
  $src.Dispose(); $es.Dispose()
}
$za.Dispose(); $fs.Dispose()
$f2 = Get-Item $Out
Write-Output ("DONE files={0} size={1}" -f $files.Count, $f2.Length)
