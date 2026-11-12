param(
  [string]$Lists = 'C:\workspace\kali\tmp\lists',
  [string]$Src   = 'C:\workspace\kali\tmp\deliverables',
  [string]$Cheat = 'C:\workspace\kali\tmp\cheatsheets-final.zip',
  [string]$Out   = 'C:\workspace\kali\tmp\deliverables\HASH_LIST.md'
)
# 사전 검토 제출용 HASH_LIST.md 생성기.
# 해시 원본은 각 플랫폼 ZIP 내부의 SHA256SUMS.txt (Windows 빌드 산물:
# BOM·CRLF·백슬래시 경로, 폴더 기준 상대경로 → 정규화해서 사용).
# 최종 ZIP 자체와 이 문서 자체의 해시는 자기 참조라 문서에 못 넣는다.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression

$winZip = Join-Path $Lists 'preferred-vulnerability-tools-windows.zip'
$kalZip = Join-Path $Lists 'preferred-vulnerability-tools-kali.zip'

function Get-ZipSums([string]$Zip, [string]$Entry) {
  $fs = [IO.File]::OpenRead($Zip)
  try {
    $za = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Read)
    try {
      $e = $za.GetEntry($Entry)
      if (-not $e) { throw "entry not found: $Entry in $Zip" }
      $sr = New-Object IO.StreamReader($e.Open())
      $rows = @()
      while ($null -ne ($line = $sr.ReadLine())) {
        if ($line -match '^\s*$') { continue }
        $parts = $line.Trim() -split '\s+', 2
        if ($parts.Count -lt 2) { continue }
        $rows += ,@($parts[0].ToLower(), $parts[1].Replace('\', '/'))
      }
      $sr.Dispose()
      return ,$rows
    } finally { $za.Dispose() }
  } finally { $fs.Dispose() }
}

function LocalHash([string]$Path) {
  return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
}

$winSums = Get-ZipSums $winZip 'SHA256SUMS.txt'
$kalSums = Get-ZipSums $kalZip 'SHA256SUMS.txt'
Write-Output ("win sums: {0} entries / kali sums: {1} entries" -f $winSums.Count, $kalSums.Count)

# --- windows sums를 폴더별로 분류 (키는 windows/ 기준 상대경로) ---
$portable = @(); $installers = @(); $wheels = @(); $extensions = @()
$wordlists = @(); $winRoot = @()
foreach ($r in $winSums) {
  $p = $r[1]
  if     ($p.StartsWith('portable/'))   { $portable   += ,@($r[0], 'windows/' + $p) }
  elseif ($p.StartsWith('installers/')) { $installers += ,@($r[0], 'windows/' + $p) }
  elseif ($p.StartsWith('pip-wheels/')) { $wheels     += ,@($r[0], 'windows/' + $p) }
  elseif ($p.StartsWith('extensions/')) { $extensions += ,@($r[0], 'windows/' + $p) }
  elseif ($p.StartsWith('wordlists/'))  { $wordlists  += ,@($r[0], 'windows/' + $p) }
  else { $winRoot += ,@($r[0], 'windows/' + $p) }
}
$portable    = $portable    | Sort-Object { $_[1] }
$installers  = $installers  | Sort-Object { $_[1] }
$wheels      = $wheels      | Sort-Object { $_[1] }
$extensions  = $extensions  | Sort-Object { $_[1] }
$wordlists   = $wordlists   | Sort-Object { $_[1] }

# --- kali 주요 deb 필터 (접두 일치) ---
$kaliKeys = 'nmap|masscan|rustscan|arp-scan|netdiscover|amass|subfinder|dnsrecon|dnsx|httpx-toolkit|naabu|ffuf|gobuster|feroxbuster|dirsearch|nuclei|katana|nikto|whatweb|wafw00f|wfuzz|sqlmap|commix|dalfox|arjun|wpscan|cewl|burpsuite|zaproxy|testssl|sslscan|sslyze|ssh-audit|tcpdump|wireshark|tshark|mitmproxy|bettercap|netexec|impacket|bloodhound|sharphound|neo4j|certipy|coercer|responder|mitm6|enum4linux|smbclient|smbmap|evil-winrm|ldap-utils|krb5|mimikatz|windows-binaries|hashcat|john|hydra|hashid|crunch|metasploit|exploitdb|weevely|nishang|powersploit|powershell|chisel|ligolo|proxychains|sshuttle|socat|netcat-openbsd|openvpn|tor|freerdp|openvas|gvmd|greenbone|notus|rizin|ghidra|sleuthkit|binwalk|foremost|jadx|apktool|android-sdk|aapt|postgresql|mariadb|redis|sqlite3|mosquitto|seclists|wordlists|mingw|jq|cyberchef|tmux|libimage-exiftool|volatility'
$kaliMajor = @()
foreach ($r in $kalSums) {
  $p = $r[1]
  if (-not $p.StartsWith('debs/')) { continue }
  $base = $p.Substring(5)
  if ($base -match '^(.*?)_') { $pkg = $Matches[1] } else { $pkg = $base }
  if ($pkg -match ('^(' + $kaliKeys + ')')) {
    $kaliMajor += ,@($r[0], 'kali/debs/' + $base)
  }
}
$kaliMajor = $kaliMajor | Sort-Object { $_[1] }

$L = New-Object System.Collections.Generic.List[string]
$L.Add('# 해시 목록 (HASH_LIST)')
$L.Add('')
$L.Add('사전 검토 제출용 문서다. 폐쇄망 현장에서 도구·스크립트·소스를 검토 부서에 제출할 때')
$L.Add('도구별 용도·버전·SHA-256을 함께 정리하면 승인이 빠르다.')
$L.Add('최종 ZIP 안의 모든 파일 해시를 담고 있으며, 전체 파일의 기계 판독 목록은')
$L.Add('각 플랫폼 ZIP 내부의 SHA256SUMS.txt에도 같은 값으로 들어 있다.')
$L.Add('')
$L.Add('참고: 이 문서 자체와 최종 ZIP(preferred-vulnerability-tools.zip)은 자기 해시를')
$L.Add('문서 안에 넣을 수 없으므로, 전달 시 별도로 알려준다.')
$L.Add('')
$L.Add('## 검증 방법')
$L.Add('')
$L.Add('```')
$L.Add('# Windows (PowerShell)')
$L.Add('Get-FileHash <파일> -Algorithm SHA256')
$L.Add('')
$L.Add('# Linux')
$L.Add('sha256sum <파일>')
$L.Add('sha256sum -c <이 문서의 코드 블록을 파일로 저장한 것>   # 파일 위치는 해제 폴더 기준')
$L.Add('```')
$L.Add('')
$L.Add('## 1. 최종 ZIP 루트 (문서·스크립트)')
$L.Add('')
$L.Add('- README.md — 사용법 (해제 후 폴더 구조, 설치 절차)')
$L.Add('- TOOL_LIST.md — 도구 전체 목록과 실측 검증 결과')
$L.Add('- HASH_LIST.md — 이 문서 (자기 해시 제외)')
$L.Add('- setup-windows.ps1 — Windows 자동 구성 스크립트')
$L.Add('- setup-kali.sh — Kali 자동 구성 스크립트 (네트워크 접속 없음)')
$L.Add('- unzip_6.0-31_amd64.deb — Kali 추출 도구 부트스트랩 (Debian unzip 6.0)')
$L.Add('- cheatsheets-final.zip — 치트시트 + 방법론 전체')
$L.Add('- preferred-vulnerability-tools-windows.zip — Windows 플랫폼 ZIP (내부 SHA256SUMS.txt 참조)')
$L.Add('- preferred-vulnerability-tools-kali.zip — Kali 플랫폼 ZIP (내부 SHA256SUMS.txt 참조)')
$L.Add('')
$L.Add('```')
foreach ($f in @('README.md','TOOL_LIST.md','setup-windows.ps1','setup-kali.sh','unzip_6.0-31_amd64.deb')) {
  $h = LocalHash (Join-Path $Src $f)
  $L.Add(('{0}  {1}' -f $h, $f))
}
$h = LocalHash $Cheat
$L.Add(('{0}  {1}' -f $h, 'cheatsheets-final.zip'))
$h = LocalHash (Join-Path $Lists 'preferred-vulnerability-tools-windows.zip')
$L.Add(('{0}  {1}' -f $h, 'preferred-vulnerability-tools-windows.zip'))
$h = LocalHash (Join-Path $Lists 'preferred-vulnerability-tools-kali.zip')
$L.Add(('{0}  {1}' -f $h, 'preferred-vulnerability-tools-kali.zip'))
$L.Add('```')
$L.Add('')

$L.Add('## 2. Windows 포터블 도구 (설치 없이 실행)')
$L.Add('')
$L.Add('- 정찰: ffuf 2.3.0(웹 퍼징), gobuster(디렉터리·vhost), feroxbuster(재귀 콘텐츠, VC x86 필요),')
$L.Add('  dirsearch(경로 스캔), httpx 1.12.0(HTTP 프로브), katana 1.8.0(크롤러), arjun(숨은 파라미터),')
$L.Add('  wafw00f(WAF 식별), nuclei 3.11.1 + nuclei-templates(취약점 스캔), naabu 2.7.0(포트 스캔),')
$L.Add('  rustscan(빠른 포트 스캔), amass(서브도메인), subfinder 2.17.0, dnsx 1.3.1, dnsrecon,')
$L.Add('  Sublist3r(DNS·서브도메인), WhatWeb(웹 기술 식별), nikto(웹 서버 스캔),')
$L.Add('  trufflehog 3.99.8 + gitleaks 8.30.1(시크릿 스캔)')
$L.Add('- 웹: sqlmap(SQL 인젝션), commix(명령 삽입), jwt_tool(JWT 분석),')
$L.Add('  php_filter_chain_generator(PHP 필터 체인 페이로드), dalfox(XSS), weevely(웹셸)')
$L.Add('- AD: SharpCollection(C# 도구 모음), SharpHound 2.17.1(AD 그래프 수집), BloodHound.py,')
$L.Add('  Certipy(AD CS), Coercer·PetitPotam(인증 강제), NetExec(AD 실행), impacket(SMB·Kerberos),')
$L.Add('  mimikatz(자격증명), GodPotato·JuicyPotato·RoguePotato·PrintSpoofer64(권한 상승),')
$L.Add('  Snaffler(SMB 시크릿), nishang·PowerSploit(PowerShell 공격), ysoserial.net(.NET 역직렬화)')
$L.Add('- 크래킹: hashcat 8.0.0, john 1.9.0-jumbo-1, hashID(해시 식별)')
$L.Add('- 모바일: jadx 1.5.6(APK 역분석), apktool 3.0.3, MobSF(모바일 정적 분석), adb(platform-tools)')
$L.Add('- 포렌식·역분석: rizin 0.9.1, ghidra 12.2')
$L.Add('- DB·서비스: postgresql 17.6, mariadb 11.4.5, redis, mongosh 2.14.1, HeidiSQL 12.15, sqlcmd(MSSQL)')
$L.Add('- 피벗: chisel, ligolo-ng(agent+proxy), socat, PuTTY·plink 0.85')
$L.Add('- Windows 지원: SysinternalsSuite, SystemInformer, winPEASx64, Greenshot, dnSpy(.NET), trivy 0.76.2')
$L.Add('- 유틸: jq 1.8.2, CyberChef(인코딩·디코딩), exiftool 13.63, GTFOBins 사본, sonarqube(소스 분석)')
$L.Add('- 런타임: OpenJDK 21 (jadx·ghidra 등 Java 실행 전제)')
$L.Add('')
$L.Add('```')
foreach ($r in $portable) { $L.Add(('{0}  {1}' -f $r[0], $r[1])) }
$L.Add('```')
$L.Add('')

$L.Add('## 3. Windows 설치 프로그램 (installers)')
$L.Add('')
$L.Add('- Burp Suite Pro 2026.10.1(웹 프록시·스캐너), OWASP ZAP 2.17.0, mitmproxy 12.3.1(HTTP 프록시)')
$L.Add('- Wireshark 4.6.9(패킷 분석), Nmap 7.993(포트 스캔)')
$L.Add('- DBeaver(DB GUI), Fiddler(HTTP 디버깅), Postman(API 클라이언트), WinSCP(SFTP),')
$L.Add('  HxD(헥스 편집), Notepad++, Git 2.56.1, OpenVPN 2.6.14')
$L.Add('- Python 3.13.7, RubyInstaller 4.0.9, Strawberry Perl 5.42.3(스크립트 런타임)')
$L.Add('- vc_redist.x64 / VC_redist.x86 (feroxbuster·postgresql·mariadb 실행 전제), 7-Zip 26.06')
$L.Add('')
$L.Add('```')
foreach ($r in $installers) { $L.Add(('{0}  {1}' -f $r[0], $r[1])) }
$L.Add('```')
$L.Add('')

$L.Add('## 4. Python 도구 wheel (오프라인 venv 설치용)')
$L.Add('')
$L.Add('- 주요 도구: httpie(HTTP 클라이언트), wfuzz(웹 퍼징), wafw00f(WAF 식별),')
$L.Add('  impacket(SMB·Kerberos 공격), pypykatz(LSASS 덤프 파싱), certipy-ad(AD CS),')
$L.Add('  coercer(인증 강제), objection·frida-tools(모바일 후킹), semgrep·bandit(소스 분석),')
$L.Add('  bloodhound(AD 그래프), volatility3(메모리 포렌식), pyjwt(JWT), hashID(해시 식별)')
$L.Add('- 아래 전체는 위 도구와 의존성을 합친 wheel 세트다 (setup-windows.ps1이 venv에 설치)')
$L.Add('')
$L.Add('```')
foreach ($r in $wheels) { $L.Add(('{0}  {1}' -f $r[0], $r[1])) }
$L.Add('```')
$L.Add('')

$L.Add('## 5. Burp 확장')
$L.Add('')
$L.Add('- Autorize(권한 분리 검증), LoggerPlusPlus(요청·응답 로깅), turbo-intruder(고속 Intruder)')
$L.Add('')
$L.Add('```')
foreach ($r in $extensions) { $L.Add(('{0}  {1}' -f $r[0], $r[1])) }
$L.Add('```')
$L.Add('')

$L.Add('## 6. 워드리스트')
$L.Add('')
$L.Add('- rockyou.txt.gz(패스워드 사전), SecLists 발췌: Discovery(DNS·웹 콘텐츠),')
$L.Add('  Fuzzing(LFI·SQLi 등), Passwords, Usernames')
$L.Add('')
$L.Add('```')
foreach ($r in $wordlists) { $L.Add(('{0}  {1}' -f $r[0], $r[1])) }
$L.Add('```')
$L.Add('')

$L.Add('## 7. Windows ZIP 루트 문서')
$L.Add('')
$L.Add('- CHEATSHEET.md, INSTALL.md, preferred_vulnerability_tools_windows.md — windows ZIP 내부 안내 문서')
$L.Add('')
$L.Add('```')
foreach ($r in $winRoot) { $L.Add(('{0}  {1}' -f $r[0], $r[1])) }
$L.Add('```')
$L.Add('')

$L.Add('## 8. Kali deb 세트 (주요 패키지)')
$L.Add('')
$L.Add('- 정찰: nmap, masscan, rustscan, arp-scan, netdiscover, amass, subfinder, dnsrecon, dnsx,')
$L.Add('  httpx-toolkit, naabu')
$L.Add('- 웹: burpsuite, zaproxy, ffuf, gobuster, feroxbuster, dirsearch, nuclei, katana, nikto,')
$L.Add('  whatweb, wafw00f, wfuzz, sqlmap, commix, dalfox, arjun, wpscan, cewl')
$L.Add('- TLS·네트워크 진단: testssl.sh, sslscan, sslyze, ssh-audit, tcpdump, wireshark, mitmproxy, bettercap')
$L.Add('- AD·Windows: netexec, impacket, bloodhound, sharphound, neo4j, certipy, coercer, responder,')
$L.Add('  mitm6, enum4linux-ng, smbclient, smbmap, evil-winrm, mimikatz, windows-binaries')
$L.Add('- 크래킹: hashcat, john, hydra, hashid, crunch')
$L.Add('- 악용·후속: metasploit-framework, exploitdb, weevely, powershell, nishang, powersploit')
$L.Add('- 피벗: chisel, ligolo-ng, proxychains4, sshuttle, socat, netcat-openbsd, openvpn, tor, freerdp')
$L.Add('- 취약점 진단(GVM·OpenVAS): openvas-scanner, gvmd, greenbone-security-assistant, notus-scanner')
$L.Add('- 포렌식·역분석: rizin, ghidra, sleuthkit, binwalk, foremost, jadx, apktool')
$L.Add('- 모바일: adb(android-sdk-platform-tools), aapt')
$L.Add('- DB·서비스: postgresql, mariadb-client, redis, sqlite3, mosquitto(MQTT)')
$L.Add('- 개발·컴파일: build-essential, mingw-w64(Windows exe 크로스컴파일), nsis, nasm, clang')
$L.Add('- 워드리스트·유틸: seclists, wordlists, jq, cyberchef, tmux, libimage-exiftool-perl')
$L.Add('')
$L.Add('```')
foreach ($r in $kaliMajor) { $L.Add(('{0}  {1}' -f $r[0], $r[1])) }
$L.Add('```')
$L.Add('')
$L.Add('전체 deb(1,602개)의 해시는 preferred-vulnerability-tools-kali.zip 내부의')
$L.Add('SHA256SUMS.txt에 전부 들어 있다 (setup-kali.sh가 설치 전에 이 목록으로 무결성 검사를 한다).')
$L.Add('')

[IO.File]::WriteAllText($Out, ($L -join "`r`n") + "`r`n", (New-Object Text.UTF8Encoding($true)))
Write-Output ("WROTE {0} ({1} lines)" -f $Out, $L.Count)
