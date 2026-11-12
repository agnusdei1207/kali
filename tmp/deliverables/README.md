# 금융권 모의해킹 종합 세트 - 사용법

이 패키지는 인터넷이 안 되는 폐쇄망 환경(금융권 모의해킹 현장)에서
ZIP 하나만 풀어 바로 쓰기 위한 종합 세트다. 도구 + 치트시트 + 방법론을 전부 담고 있으며,
구성 스크립트는 인터넷에 접속하지 않는다(wheel, deb, 설치 파일 전부 패키지 안에서 해결).

## 1. 패키지 구성 (ZIP 해제 직후)

- README.md — 이 문서
- TOOL_LIST.md — 도구 전체 목록과 실측 검증 결과
- HASH_LIST.md — 사전 검토 제출용 해시 목록 (도구별 용도·버전·SHA-256)
- setup-windows.ps1 — Windows 자동 구성 스크립트
- setup-kali.sh — Kali 자동 구성 스크립트
- unzip_6.0-31_amd64.deb — Kali에 unzip이 아예 없을 때 쓰는 부트스트랩 설치 파일(setup-kali.sh가 자동 사용)
- preferred-vulnerability-tools-windows.zip — Windows용 도구 ZIP
- preferred-vulnerability-tools-kali.zip — Kali용 deb 오프라인 세트 ZIP
- cheatsheets-final.zip — 치트시트 + 방법론 (도구별 치트시트 전부 수록)

## 지원 환경과 설치 전 확인

- Windows 패키지는 Windows 10/11 x64용이다. Windows ZIP에는 287개 payload 파일이 포함된다. ZIP 해제와 전체 설치를 위해 20 GiB 이상의 여유 공간을 확보한다. PowerShell 5.1 이상과 로컬 디스크 쓰기 권한이 필요하며, 스크립트가 x64와 여유 공간을 검사한다.
- Kali 패키지는 Kali Linux amd64용이다. 설치 스크립트는 root 권한과 15 GiB 이상의 여유 공간을 확인하며, 설치 후 시스템 전역 패키지를 바꾼다. 기존 업무용 Kali에 적용하지 말고 전용 또는 초기화 가능한 Kali 환경에서 실행한다. 패키지 버전 조정 중 일부 기존 패키지를 다운그레이드할 수 있다.
- 두 스크립트는 외부 네트워크를 사용하지 않는다. Windows Python 의존성은 동봉 wheel, Kali 패키지는 동봉 deb에서 설치한다. 실행 정책·WDAC·Defender와 같은 조직 보안 정책이 실행을 차단할 수 있다.
- Windows GUI 프로그램 설치 파일은 포함되어 있지만 자동 설치하지 않는다. `extract\windows\installers`에서 필요한 항목을 개별 설치한다. Burp Suite Pro는 라이선스가 필요할 수 있다. Kali에서는 GUI 패키지 설치 상태만 확인하며, 데스크톱 실행은 GUI 세션에서 별도로 확인한다.
- 치트시트는 ZIP 안에 오프라인 보관되지만, 각 문서의 외부 링크나 인터넷 다운로드/설치 명령은 폐쇄망에서 사용할 수 없다. 해당 절차가 나오면 이미 설치된 도구나 동봉 파일을 사용한다.
- 도구 실행 파일 설치와 보안 데이터베이스 준비는 별개다. OpenVAS/GVM 피드, Trivy 취약점 DB, WPScan 취약점 DB 등 업데이트 피드는 패키지에 포함되지 않는다. Nuclei 템플릿은 동봉본을 쓸 수 있지만 업데이트하려면 인터넷이 필요하다. 외부 피드가 필요한 기능은 사전 승인된 업데이트 자료나 기존 캐시가 없으면 제한된다.
## 2. 빠른 시작

### Windows

1. 폴더 전체를 로컬 디스크에 복사(압축 해제는 이미 되어 있으면 생략)
2. PowerShell에서:
   - cd <해제 폴더>
   - powershell -ExecutionPolicy Bypass -File .\setup-windows.ps1
3. 스크립트는 인터넷을 사용하지 않는다. 무결성·압축·필수 Python 의존성 오류는 `SETUP_FAILED`(종료 코드 1), WDAC 차단·시간 초과·선택 런타임 누락은 `SETUP_DONE_WITH_WARNINGS`(종료 코드 0)로 분리한다. 호스트 보안 정책을 변경하거나 우회하지 않는다.
   스크립트가 순서대로 진행한다:
   - 7-Zip 자동 설치(없으면 사용자 디렉터리에 설치)
   - windows ZIP 무결성 검사 + 해제
   - 치트시트 해제
   - vc_redist x64/x86, Python 3.13, JDK 21, Perl, Ruby 자동 설치(관리자 권한이 없으면 사용자 디렉터리에 설치하거나 건너뛴다)
   - 도구를 카테고리 폴더로 정리
   - Python 도구 wheel 오프라인 설치(venv)
   - 대표 CLI의 시작·도움말 스모크 테스트(PASS/BLOCKED/WARN/FAIL 출력)
4. 관리자 권한으로 실행하면 시스템 설치(vcredist, Perl, Ruby)를 시도한다. 권한 또는 보안 정책으로 건너뛴 항목은 WARN으로 보고한다.
   GUI 프로그램(Burp, ZAP, Wireshark, Nmap, Fiddler, DBeaver, Postman, WinSCP, OpenVPN, Git 등)은
   extract\windows\installers 폴더에서 수동 설치한다.

### Kali

1. sudo ./setup-kali.sh
2. 스크립트가 순서대로 진행한다:
   - kali ZIP 해제(unzip/7z/bsdtar/python3 중 있는 것으로)
   - SHA256SUMS 무결성 검사
   - deb 전체 오프라인 설치(--no-download로 네트워크 접근 차단, 수 분 소요)
   - 치트시트 해제
   - 주요 도구 실행 검증(PASS/FAIL 로그 출력)
3. 설치가 끝나면 도구는 PATH에서 바로 실행된다.

## 3. Windows 구성 후 폴더 위치 (setup-windows.ps1 실행 결과)

해제 폴더 아래에 이렇게 생긴다:

- workspace\
  - recon\ — 정찰 도구 (ffuf, gobuster, subfinder, dnsx, httpx, katana, naabu, feroxbuster, rustscan, nuclei, nuclei-templates, amass, trufflehog, gitleaks, dirsearch, Sublist3r, dnsrecon, WhatWeb, nikto, Arjun)
  - web\ — 웹 도구 (sqlmap, commix, jwt_tool, php_filter_chain_generator, dalfox, weevely)
  - active-directory\ — AD 도구 (SharpCollection, SharpHound, BloodHound.py, Certipy, Coercer, PetitPotam, NetExec, impacket 소스, mimikatz, GodPotato, JuicyPotato, RoguePotato, PrintSpoofer64, Snaffler, nishang, PowerSploit, ysoserial.net)
  - cracking\ — 크래킹 (hashcat, john, hashID)
  - mobile\ — 모바일 (jadx, apktool, MobSF, adb platform-tools)
  - forensics\ — 포렌식/역분석 (rizin, ghidra)
  - services\ — DB 클라이언트 (postgresql, mariadb, redis, mongosh, HeidiSQL, sqlcmd)
  - pivoting\ — 피벗 (chisel, ligolo-ng, socat, PuTTY/plink)
  - windows\ — Windows 지원 (SysinternalsSuite, SystemInformer, winPEASx64, Greenshot, dnSpy, trivy)
  - util\ — 유틸 (jq, CyberChef, exiftool, GTFOBins, sonarqube)
  - wordlists\ — rockyou.txt.gz, Discovery\, Fuzzing\ (SecLists 발췌)
  - burp-extensions\ — Autorize.jar, LoggerPlusPlus.jar, turbo-intruder-all.jar
  - py-venv\ — wheel로 설치된 Python 도구 venv (Scripts\python.exe로 실행: httpie, impacket, certipy-ad, coercer, pypykatz, volatility3, frida-tools, semgrep, bandit, bloodhound 등)
  - runtime\ — 설치된 Python 3.13 / JDK 21 (스크립트가 설치한 경우)
- cheatsheets\ — 치트시트 (active-directory, bruteforce, common, cracking, cve, forensics, linux, metasploit, methodology, pivoting, python, recon, scripts, services, shells, util, web, windows)
- extract\windows\installers\ — GUI 프로그램 설치 파일 (Burp Suite Pro, ZAP, Wireshark, Nmap, mitmproxy, Fiddler, DBeaver, Postman, WinSCP, HxD, Notepad++, OpenVPN, Git 등)
- extract\windows\portable\ — 원본 포터블 압축 파일(정리 후에도 보존)

### 도구 위치 예시

- ffuf: workspace\recon\ffuf_2.3.0_windows_amd64\ffuf.exe
- sqlmap: workspace\web\src-sqlmapproject-sqlmap-master\sqlmap.py (python으로 실행)
- impacket: workspace\py-venv\Scripts\smbclient.py 등 (venv python으로 실행)
- jadx: workspace\mobile\jadx\bin\jadx.bat (JAVA_HOME 필요, 스크립트가 설정)
- plink: workspace\pivoting\putty\plink.exe
- hashcat: workspace\cracking\hashcat-8.0.0\hashcat.exe

### PATH 등록 팁 (선택)

- 자주 쓰는 카테고리 폴더만 PATH에 추가한다:
  - $env:Path += ";C:\<해제폴더>\workspace\recon;C:\<해제폴더>\workspace\pivoting"
  - 영구 등록: setx PATH "$env:Path" (또는 시스템 환경설정 GUI)
- Python 도구는 venv를 활성화하고 쓴다:
  - workspace\py-venv\Scripts\Activate.ps1

### Burp Suite

- 설치: extract\windows\installers\burpsuite_windows-x64_v2026.10.1.exe (수동)
- 확장 적용: Burp - Extensions - Add - Extension type: Java - burp-extensions 폴더의 jar 선택

## 4. Kali 설치 후 위치

- 도구: apt로 시스템 전역 설치되어 PATH에서 바로 실행 (nmap, sqlmap, metasploit, netexec, impacket, bloodhound, certipy, responder, hashcat, john, hydra, burpsuite, zaproxy, wireshark, ghidra 등)
- 워드리스트: /usr/share/seclists, /usr/share/wordlists (rockyou.txt.gz는 gunzip 후 사용)
- 치트시트: <해제 폴더>/cheatsheets
- Python 도구(impacket 등): /usr/bin/*.py 스크립트로 설치됨 (smbclient.py, secretsdump.py 등)

## 5. 치트시트·방법론 안내

- cheatsheets\README.md — 전체 개요
- cheatsheets\methodology\ — 침투 테스트 절차 (enumeration, foothold, post-exploitation, privilege-escalation, web-attacks, tools)
- 도구별 사용법은 cheatsheets 하위 카테고리 폴더에서 찾는다 (예: sqlmap - cheatsheets\web\, netexec - cheatsheets\active-directory\)

## 6. 사전 검토 제출 (해시 목록)

현장에서 도구·스크립트·소스의 사전 검토를 요구하면 HASH_LIST.md를 제출한다.
도구별 용도·버전·SHA-256이 정리돼 있어 승인이 빠르다.

- 검증: Get-FileHash <파일> -Algorithm SHA256 (Windows) / sha256sum <파일> (Linux)
- 전체 1,602개 deb의 해시는 preferred-vulnerability-tools-kali.zip 내부 SHA256SUMS.txt에 있다
  (setup-kali.sh가 설치 전에 이 목록으로 무결성 검사를 한다)
- 최종 ZIP 자체의 해시는 문서에 못 넣으므로 전달 시 별도로 알려준다

## 7. 문제해결

- 일부 도구(naabu, dalfox, ligolo 등)가 "즉시 종료"되면 회사/호스트의 Application Control(WDAC) 정책 차단일 수 있다. 파일 자체는 정상이므로 정책이 없는 환경에서는 실행된다.
- chisel.exe, ligolo agent.exe가 아예 없으면(설치 후 사라짐) Defender 실시간 보호가 격리해 삭제한 것이다. 조직의 Application Control 또는 Defender 정책을 유지하고, 실행이 허용된 도구나 승인된 배포 경로를 확인한다.
- feroxbuster가 0xC0000135 오류로 안 뜨면 32bit 빌드라서 VC 런타임(x86)이 필요한 것이다. installers\VC_redist.x86.exe를 설치한다(스크립트가 자동 시도).
- postgresql/mariadb 바이너리가 DLL 오류를 내면 installers\vc_redist.x64.exe를 설치한다.
- 컨테이너·제한 환경에서 nmap이 권한 오류를 내면 setcap이 원인일 수 있다: setcap -r $(which nmap) 후 사용하거나 root로 실행한다.
- Windows에서 WDAC/Defender 정책이 도구 실행을 차단할 수 있다. 설치 스크립트는 이를 우회하지 않고 BLOCKED/WARN으로 보고하며, 다른 필수 설치 단계가 성공하면 `SETUP_DONE_WITH_WARNINGS`로 끝난다. Weevely는 Kali/Linux에서 사용한다. 치트시트의 외부 링크와 설치 명령은 인터넷 없는 현장에서 사용할 수 없다.
- ZIP 해제가 안 되면 7-Zip 없이도 Windows는 setup-windows.ps1이 알아서 7-Zip을 확보하고, Kali는 setup-kali.sh가 unzip/7z/bsdtar/python3 중 있는 것으로 푼다.
