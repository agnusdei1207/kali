# 도구 목록 (TOOL_LIST)

금융권 모의해킹 종합 세트에 들어있는 도구 전체 목록.
이 문서는 최종 ZIP 내부에 동봉된다.

## 1. 패키지 구성

- preferred-vulnerability-tools-windows.zip — Windows용 도구
- preferred-vulnerability-tools-kali.zip — Kali용 deb 오프라인 세트
- cheatsheets-final.zip — 치트시트 + 방법론 (19개 폴더, 문서 402개)
- setup-windows.ps1 / setup-kali.sh — 자동 구성 스크립트
- README.md — 사용법
- HASH_LIST.md — 사전 검토 제출용 해시 목록 (도구별 용도·버전·SHA-256)

## 설치 범위

- Windows 도구는 x64에서 압축 해제 후 대표 실행 파일과 Python 도구를 스모크 테스트한다. 보안 정책에 의해 차단된 실행 파일은 해당 환경에서 동작을 보장할 수 없다.
- Windows의 GUI 설치 파일은 ZIP에 포함되며 자동 설치 대상이 아니다. Burp Suite, ZAP, Wireshark 등 각 설치 파일의 설치·실행은 관리자 정책, 라이선스, 데스크톱 세션에 따라 현장에서 별도 확인한다.
- Kali는 동봉 deb 전체를 오프라인으로 설치하고 주요 CLI 도구 및 GUI 패키지의 설치 상태를 확인한다. Docker 컨테이너 검증은 GUI 화면을 띄우지 않으므로 GUI 앱 실행 여부까지 보증하지 않는다.
- 패키지 파일 무결성은 동봉 SHA256SUMS로 확인한다. 설치 성공 여부는 셋업 스크립트의 종료 코드가 0이고 마지막에 SETUP_DONE이 표시될 때만 성공으로 판정한다.
## 2. Windows 도구

### 2.1 포터블 (설치 없이 바로 실행)

- 정찰/정보수집 (recon): ffuf 2.3.0, gobuster, subfinder 2.17.0, dnsx 1.3.1, httpx 1.12.0, katana 1.8.0, naabu 2.7.0, feroxbuster, rustscan, nuclei 3.11.1, nuclei-templates, amass, trufflehog 3.99.8, gitleaks 8.30.1, dirsearch, Sublist3r, dnsrecon, WhatWeb, nikto, Arjun
- 웹 (web): sqlmap, commix, jwt_tool, php_filter_chain_generator, dalfox, weevely
- 액티브 디렉터리 (active-directory): SharpCollection, SharpHound 2.17.1, BloodHound.py, Certipy, Coercer, PetitPotam, NetExec, impacket 소스, mimikatz trunk, GodPotato, JuicyPotato, RoguePotato, PrintSpoofer64, Snaffler, nishang, PowerSploit, ysoserial.net
- 크래킹 (cracking): hashcat 8.0.0, john 1.9.0-jumbo-1, hashID
- 모바일 (mobile): jadx 1.5.6, apktool 3.0.3, MobSF, Android platform-tools (adb)
- 포렌식/역분석 (forensics): rizin 0.9.1, ghidra 12.2
- DB/서비스 클라이언트 (services): postgresql 17.6 바이너리, mariadb 11.4.5, redis, mongosh 2.14.1, HeidiSQL 12.15, sqlcmd (MSSQL)
- 피벗 (pivoting): chisel, ligolo-ng (agent+proxy), socat, PuTTY/plink 0.85
- Windows 지원 (windows): SysinternalsSuite, SystemInformer, winPEASx64, Greenshot, dnSpy, trivy 0.76.2
- 유틸 (util): jq 1.8.2, CyberChef, exiftool 13.63, GTFOBins 사본, sonarqube

### 2.2 설치 프로그램 (installers 폴더, setup 스크립트가 자동 설치 시도)

- Burp Suite Pro 2026.10.1, OWASP ZAP 2.17.0, Wireshark 4.6.9, Nmap 7.993, mitmproxy 12.3.1
- DBeaver, Fiddler, Postman, WinSCP, HxD, Notepad++, Git 2.56.1, OpenVPN 2.6.14
- Python 3.13.7, Ruby 4.0.9, Strawberry Perl 5.42.3, 7-Zip 26.06
- vc_redist.x64 / VC_redist.x86 (postgresql, mariadb, feroxbuster 실행 전제)

### 2.3 Python 도구 (wheel 오프라인 설치, venv로 구성)

httpie, wfuzz, wafw00f, impacket, pypykatz, certipy-ad, coercer, objection, frida-tools, semgrep, bandit, bloodhound, volatility3, pyjwt, hashID

### 2.4 Burp 확장 (burp-extensions 폴더)

Autorize.jar, LoggerPlusPlus.jar, turbo-intruder-all.jar

### 2.5 워드리스트 (wordlists 폴더)

rockyou.txt.gz, Discovery(DNS·Web-Content), Fuzzing(LFI·SQLi) — SecLists 발췌 13종

## 3. Kali 도구 (deb 오프라인 세트, 1602개 패키지)

setup-kali.sh가 전부 오프라인 설치한다. 주요 도구:

- 정찰: nmap, masscan, rustscan, arp-scan, netdiscover, amass, subfinder, sublist3r, dnsrecon, dnsx, httpx-toolkit, naabu
- 웹: burpsuite, zaproxy, ffuf, gobuster, feroxbuster, dirsearch, nuclei, katana, nikto, whatweb, wafw00f, wfuzz, sqlmap, commix, dalfox, arjun, wpscan, cewl
- TLS/네트워크 진단: testssl.sh, sslscan, sslyze, ssh-audit, tcpdump, wireshark, tshark, mitmproxy, bettercap
- 액티브 디렉터리/윈도우: netexec, impacket-scripts, bloodhound, bloodhound.py, sharphound, neo4j, certipy-ad, coercer, responder, mitm6, enum4linux-ng, smbclient, smbmap, polenum, evil-winrm, ldap-utils, krb5-user, mimikatz, windows-binaries, azurehound
- 크래킹: hashcat, john, hydra, hashid, crunch
- 악용/후속 (exploit/post): metasploit-framework, exploitdb, weevely, powershell, nishang, powersploit, peass
- 피벗: chisel, ligolo-ng, proxychains4, sshuttle, socat, netcat-openbsd, openvpn, easy-rsa, tor, torsocks, freerdp
- 취약점 진단: openvas-scanner, gvmd, greenbone-security-assistant, notus-scanner (GVM/OpenVAS 스윕)
- 포렌식/역분석: rizin, ghidra, sleuthkit, binwalk, foremost, jadx, apktool (메모리 분석 volatility3는 Windows 쪽 wheel로 제공)
- 모바일: apktool, jadx, adb(android-sdk-platform-tools), aapt
- DB/서비스: postgresql 18, mariadb-client, redis-server, sqlite3, mosquitto(MQTT), oracle-instantclient, freetds
- 개발/컴파일: build-essential, gcc/g++, mingw-w64(Windows exe 크로스컴파일), nsis, nasm, clang/llvm, ruby, php-cli
- 워드리스트: seclists, wordlists
- 유틸: jq, cyberchef, tmux, vim, unzip/zip, imagemagick, flameshot, exiftool(libimage-exiftool-perl), git, curl/wget, proxychains4

전체 패키지 명단은 kali.zip 내부의 MANIFEST.md와 SHA256SUMS.txt에 있다.

- 오프라인 데이터 한계: 설치된 실행 파일과 스캐너 피드는 다르다. OpenVAS/GVM 및 Trivy/WPScan 업데이트 DB는 이 패키지에 포함되지 않는다. Nuclei 템플릿은 동봉본이 있지만 업데이트는 인터넷이 필요하다. 피드나 기존 캐시가 없는 폐쇄망에서는 해당 데이터베이스 의존 기능이 제한된다.

## 4. 치트시트 구성 (cheatsheets-final.zip)

패키지에 들어가는 모든 도구에 대응하는 치트시트가 cheatsheets-final.zip 안에 있다.

- 폴더: active-directory, bruteforce, common, cracking, cve, forensics, linux, metasploit, methodology, pivoting, python, recon, scripts, services, shells, util, web, windows
- methodology — 침투 테스트 절차 (enumeration, foothold, post-exploitation, privilege-escalation, web-attacks, tools)
- 도구 → 치트시트 위치 예시: sqlmap은 web\sqli\sqlmap.md, netexec은 active-directory\nxc.md, hashcat은 cracking\hashcat\, nmap은 recon\network\nmap.md, impacket은 active-directory\impacket.md
- 각 폴더의 README.md가 문서 인덱스다.

## 5. 실측 검증 결과 (2026-11-12)

### Windows 11 x64 (PowerShell 5.1, 일반 사용자 권한, 2026-11-12 재검증)

- Windows ZIP payload 287개 SHA256 일치, 오프라인 Python wheel 설치 exit=0, DNSRecon 격리 venv 설치 exit=0 및 도움말 실행 PASS.
- 자동 smoke 결과: PASS 32 / BLOCKED 7 / WARN 7 / FAIL 0. setup 요약은 `SETUP_DONE_WITH_WARNINGS`, 종료 코드 0.
- BLOCKED: bloodhound-python, certipy, coercer, frida, httpie, pypykatz, semgrep. 이 호스트의 WDAC/Application Control이 실행을 거부했다. 스크립트는 보안 정책을 변경하지 않는다.
- WARN: bandit, volatility3, wafw00f, wfuzz는 호스트에서 런처가 출력 없이 종료했다. chisel/ligolo 실행 파일은 아카이브에는 있으나 추출 결과에서 찾지 못했다. hashcat은 15초 안에 끝나지 않았다. 정책 격리 또는 호환성 가능성이 있어 해당 기능은 현장 확인이 필요하다.
- 관리자 권한이 없어 Ruby 런타임 설치는 건너뛰었다. Ruby가 필요한 WhatWeb 등 일부 기능은 제한될 수 있다.
- Burp Suite, ZAP, Wireshark 등 GUI 설치 파일은 ZIP에 포함되지만 자동 설치·실행하지 않았다. 이 호스트에서는 GUI 앱 실행을 검증하지 않았다. 라이선스, 관리자 정책, 설치 방식 차이가 있어 개별 설치 파일에서 수동 설치한다.
- 설치 단계의 압축/해시/Python 의존성 오류는 실패(exit 1)로 처리한다. 호스트 보안 차단·시간 초과·누락 런처는 경고로 구분해 설치 결과와 함께 반환한다.

### Kali (Docker 네트워크 차단 컨테이너에서 오프라인 실설치, 2026-11-12 재검증)

- 무결성 검사: SHA256SUMS 정규화(BOM·CRLF·백슬래시·kali/ 접두) 후 1,602개 deb 전부 일치 (RC=0)
- deb 전체 오프라인 설치: 최소 kali-rolling 컨테이너(--network none)에서 1,602개 전체 RC=0.
  unzip 부트스트랩 → --no-download + Dir::Cache::archives 방식으로 네트워크 접속 0
- 주요 도구 실행 검증: PASS 77 / FAIL 0 (nmap, sqlmap, metasploit, netexec, impacket, hydra,
  john, hashcat, ffuf, gobuster, nuclei, amass, subfinder, responder, bloodhound.py, certipy,
  chisel, ligolo, testssl, ghidra, jadx, apktool, binwalk, rizin, burpsuite, zaproxy, wireshark 등)
- 실행명 참고: impacket 스크립트는 impacket-smbclient 형태(impacket- 접두), testssl 실행 파일명은 testssl
- 참고: Docker에서는 스크립트가 /usr/lib/nmap/nmap의 setcap을 제거한 뒤 Nmap 실행 확인을 한다. 실제 GUI 앱은 데스크톱에서 별도 실행 확인이 필요하다.
