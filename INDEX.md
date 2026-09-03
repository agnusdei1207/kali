# 🗂️ 침투 테스트 리소스 색인 (Pentest Resource Index)

본 문서는 침투 테스트 공격 라이프사이클과 실무 상황(트리거)에 따라 필요한 기술 치트시트, 가이드, 도구 및 실전 롸잇업을 빠르게 찾아갈 수 있는 **중앙 색인(Master Catalog)**입니다.

---

## 🧭 침투 테스트 라이프사이클별 리소스

### 1. 정보 수집 & 정찰 (Reconnaissance)

| 상황 (트리거) | 대상 기법 / 도구 | 리소스 경로 |
| :--- | :--- | :--- |
| 타겟 대역의 활성 호스트 및 열린 포트를 고속/정밀 스캔할 때 | Nmap 포트 & 스크립트 스캔 | [`item/01-reconnaissance/network/nmap.md`](item/01-reconnaissance/network/nmap.md) |
| 대규모 IP 대역을 극초고속으로 포트 스캐닝할 때 | RustScan 고속 스캔 | [`item/01-reconnaissance/network/rustscan.md`](item/01-reconnaissance/network/rustscan.md) |
| 로컬 서브넷 내 ARP 기반 활성 호스트를 탐지할 때 | Netdiscover | [`item/01-reconnaissance/network/netdiscover.md`](item/01-reconnaissance/network/netdiscover.md) |
| 패킷 덤프 및 실시간 네트워크 트래픽을 수집·분석할 때 | tcpdump / Wireshark 필터 | [`item/01-reconnaissance/network/tcpdump.md`](item/01-reconnaissance/network/tcpdump.md) · [`wireshark`](item/01-reconnaissance/network/wireshark/wireshark_display_filter.md) |
| 웹 디렉터리, 숨겨진 파일 및 파라미터를 고속 브루트포싱할 때 | Gobuster / ffuf | [`item/01-reconnaissance/web-surface/gobuster.md`](item/01-reconnaissance/web-surface/gobuster.md) · [`ffuf.md`](item/01-reconnaissance/web-surface/ffuf.md) |
| 대상 도메인의 서브도메인을 열거·수집할 때 | Sublist3r / DNSRecon | [`item/01-reconnaissance/web-surface/subdomain/Sublist3r.md`](item/01-reconnaissance/web-surface/subdomain/Sublist3r.md) |
| CLI 환경에서 HTTP 요청을 테스트하고 헤더를 확인할 때 | cURL / HTTPie | [`item/01-reconnaissance/web-surface/curl/curl.md`](item/01-reconnaissance/web-surface/curl/curl.md) · [`httpie.md`](item/01-reconnaissance/web-surface/httpie.md) |
| Active Directory 환경에서 유효 도메인 계정을 열거할 때 | Kerbrute 계정 열거 | [`item/01-reconnaissance/active-directory/kerbrute.md`](item/01-reconnaissance/active-directory/kerbrute.md) |
| AD 도메인 신뢰 관계, 공격 경로 그래프를 매핑할 때 | BloodHound | [`item/01-reconnaissance/active-directory/bloodhound.md`](item/01-reconnaissance/active-directory/bloodhound.md) |
| SMB 공유 폴더 및 윈도우/삼바 서비스 정보를 열거할 때 | enum4linux / smbclient | [`item/01-reconnaissance/active-directory/enum4linux.md`](item/01-reconnaissance/active-directory/enum4linux.md) · [`smbclient.md`](item/01-reconnaissance/active-directory/smb/smbclient.md) |
| DNS 레코드 조회 및 분석 | DNS 레코드 / hosts 매핑 | [`item/01-reconnaissance/osint-dns/dns.md`](item/01-reconnaissance/osint-dns/dns.md) · [`hosts.md`](item/01-reconnaissance/osint-dns/hosts.md) |
| 공격자 IP 은닉 및 Tor 네트워크를 통한 프록시 터널링 | Tor & torsocks 종합 가이드 | [`item/01-reconnaissance/osint-dns/tor.md`](item/01-reconnaissance/osint-dns/tor.md) |

---

### 2. 취약점 분석 (Vulnerability Assessment)

| 상황 (트리거) | 대상 기법 / 도구 | 리소스 경로 |
| :--- | :--- | :--- |
| SQL 인젝션 수동 검증 및 에러/블라인드 인젝션 페이로드 작성 | SQLi 검증 & Blind SQLi | [`item/02-vulnerability-analysis/web/sqli/blind_sql.md`](item/02-vulnerability-analysis/web/sqli/blind_sql.md) · [`sqli_exploit.md`](item/02-vulnerability-analysis/web/sqli/sqli_exploit.md) |
| SQL 인젝션 공격 및 데이터베이스 덤프 자동화 | sqlmap & 주요 옵션 | [`item/02-vulnerability-analysis/web/sqli/sqlmap.md`](item/02-vulnerability-analysis/web/sqli/sqlmap.md) |
| XSS 취약점 검증 및 블라인드 XSS 쿠키 탈취 시도 | XSS & Blind XSS | [`item/02-vulnerability-analysis/web/xss/xss.md`](item/02-vulnerability-analysis/web/xss/xss.md) · [`javascript_blind_xss.md`](item/02-vulnerability-analysis/web/xss/javascript_blind_xss.md) |
| 서버 내부망 요청 위조 및 클라우드 메타데이터 조회 | SSRF 취약점 기법 | [`item/02-vulnerability-analysis/web/ssrf/ssrf.md`](item/02-vulnerability-analysis/web/ssrf/ssrf.md) |
| 로컬/원격 파일 포함 취약점 및 PHP Wrapper 필터 체인 악용 | LFI / RFI / PHP Filter Chain | [`item/02-vulnerability-analysis/web/file-inclusion/php_filter_chain_generator.md`](item/02-vulnerability-analysis/web/file-inclusion/php_filter_chain_generator.md) · [`null_byte.md`](item/02-vulnerability-analysis/web/file-inclusion/null_byte.md) |
| 파일 업로드 확장자·MIME 검증 우회 및 웹쉘 전달 | 파일 업로드 공격 기법 | [`item/02-vulnerability-analysis/web/file-upload.md`](item/02-vulnerability-analysis/web/file-upload.md) |
| 데이터베이스별 기본 포트, 인증 결함 및 명령어 실행 확인 | DB 취약점 (MySQL/MSSQL/Mongo 등) | [`item/02-vulnerability-analysis/services/database/`](item/02-vulnerability-analysis/services/database/) |
| 워드프레스 플러그인/테마 취약점 점검 | WPScan | [`item/02-vulnerability-analysis/web/wordpress.md`](item/02-vulnerability-analysis/web/wordpress.md) |
| 공개된 CVE 취약점 및 로컬 익스플로잇 코드 검색 | Searchsploit / CVE | [`item/02-vulnerability-analysis/cve/searchsploit.md`](item/02-vulnerability-analysis/cve/searchsploit.md) · [`cve-2024-21413.md`](item/02-vulnerability-analysis/cve/cve-2024-21413.md) |

---

### 3. 초기 침투 & 익스플로잇 (Initial Access)

| 상황 (트리거) | 대상 기법 / 도구 | 리소스 경로 |
| :--- | :--- | :--- |
| 다양한 언어(Bash, Python, Netcat, PHP)별 리버스 셸 원라이너 필요 시 | 리버스 셸 종합 치트시트 | [`item/03-initial-access/shells/reverse-shell/reverse_shell.md`](item/03-initial-access/shells/reverse-shell/reverse_shell.md) |
| 덤프 셸 획득 후 상호작용 완전한 TTY 터미널로 업그레이드할 때 | PTY / TTY 스폰 가이드 | [`item/03-initial-access/shells/shell-upgrade/python_pty.md`](item/03-initial-access/shells/shell-upgrade/python_pty.md) |
| 웹서버에 업로드하여 원격 명령을 실행할 웹쉘이 필요할 때 | PHP 웹쉘 | [`item/03-initial-access/shells/web-shell/php_webshell.md`](item/03-initial-access/shells/web-shell/php_webshell.md) |
| 방화벽 아웃바운드 차단 환경에서 ICMP를 통한 셸 연결 | ICMP 리버스 셸 | [`item/03-initial-access/shells/reverse-shell/icmp_reverse_shell.md`](item/03-initial-access/shells/reverse-shell/icmp_reverse_shell.md) |
| GPU를 활용한 초고속 패스워드 해시 크래킹 | Hashcat 종합 가이드 | [`item/03-initial-access/cracking/hashcat/hashcat.md`](item/03-initial-access/cracking/hashcat/hashcat.md) |
| 다양한 포맷(Shadow, SSH 키, ZIP/RAR 등)의 해시 크래킹 | John the Ripper / 2john 도구 | [`item/03-initial-access/cracking/john-the-ripper/john_the_ripper.md`](item/03-initial-access/cracking/john-the-ripper/john_the_ripper.md) |
| 웹/SSH/FTP 등 온라인 인증 서비스 무차별 대입 공격 | Hydra 공격 가이드 | [`item/03-initial-access/cracking/hydra/hydra.md`](item/03-initial-access/cracking/hydra/hydra.md) |
| 칼리 워드리스트 다운로드, 위치 및 seclists 활용 | SecLists & Wordlists | [`item/03-initial-access/cracking/seclists.md`](item/03-initial-access/cracking/seclists.md) · [`rockyou.md`](item/03-initial-access/cracking/rockyou.md) |
| 메타스플로잇 프레임워크 핸들러 실행 및 페이로드 생성 | Metasploit & msfvenom | [`item/03-initial-access/framework/msf/msf.md`](item/03-initial-access/framework/msf/msf.md) · [`msfvenom.md`](item/03-initial-access/framework/msf/msfvenom/msfvenom.md) |

---

### 4. 권한 상승 (Privilege Escalation)

| 상황 (트리거) | 대상 기법 / 도구 | 리소스 경로 |
| :--- | :--- | :--- |
| 리눅스 로컬 권한상승 벡터 자동 점검 스크립트 실행 | LinPEAS 가이드 & 팁 | [`item/04-privilege-escalation/linux/linpeas/linpeas.md`](item/04-privilege-escalation/linux/linpeas/linpeas.md) |
| `sudo -l` 권한 결함 및 패스워드 없는 실행 악용 | Sudo 권한 상승 기법 | [`item/04-privilege-escalation/linux/sudo_privesc.md`](item/04-privilege-escalation/linux/sudo_privesc.md) |
| SUID / SGID 설정된 바이너리를 통한 권한 상승 | SUID 권한상승 & GTFOBins | [`item/04-privilege-escalation/linux/suid.md`](item/04-privilege-escalation/linux/suid.md) · [`gtfobinaries.md`](item/04-privilege-escalation/linux/gtfobins/gtfobinaries.md) |
| 백그라운드 크론 작업 및 주기적 실행 스크립트 악용 | Crontab 권한 상승 | [`item/04-privilege-escalation/linux/crontab.md`](item/04-privilege-escalation/linux/crontab.md) |
| 숨겨진 프로세스 및 실시간 실행 명령 모니터링 | pspy / ps 프로세스 모니터링 | [`item/04-privilege-escalation/linux/process-monitoring/ps.md`](item/04-privilege-escalation/linux/process-monitoring/ps.md) |
| 리눅스 계정 패스워드 해시 추출 및 검토 | /etc/passwd & /etc/shadow | [`item/04-privilege-escalation/linux/credentials/etc_passwd.md`](item/04-privilege-escalation/linux/credentials/etc_passwd.md) · [`shadow.md`](item/04-privilege-escalation/linux/credentials/shadow.md) |
| 윈도우 WinRM 서비스 원격 관리 셸 접속 | Evil-WinRM | [`item/04-privilege-escalation/windows/evil-winrm.md`](item/04-privilege-escalation/windows/evil-winrm.md) |
| 윈도우 환경 내부 탐색 및 기본 명령어 | Windows CMD & PowerShell | [`item/04-privilege-escalation/windows/cmd/base_cmd.md`](item/04-privilege-escalation/windows/cmd/base_cmd.md) · [`base_powershell.md`](item/04-privilege-escalation/windows/powershell/base_powershell.md) |

---

### 5. 측면 이동 & 피보팅 (Lateral Movement)

| 상황 (트리거) | 대상 기법 / 도구 | 리소스 경로 |
| :--- | :--- | :--- |
| HTTP/HTTPS 프록시 인터셉트 및 트래픽 변조 | mitmproxy 사용법 | [`item/05-lateral-movement/pivoting/proxy/mitmproxy_proxy.md`](item/05-lateral-movement/pivoting/proxy/mitmproxy_proxy.md) |
| SSH 로컬/리모트/다이나믹 포트 포워딩을 통한 내부망 접근 | SSH 터널링 기법 | [`item/02-vulnerability-analysis/services/ssh/ssh_key_gen.md`](item/02-vulnerability-analysis/services/ssh/ssh_key_gen.md) |

---

### 6. 포스트 익스플로잇 & 포렌식 (Post Exploitation & Forensics)

| 상황 (트리거) | 대상 기법 / 도구 | 리소스 경로 |
| :--- | :--- | :--- |
| 메모리 덤프 파일 분석 및 침해 지표 확인 | Volatility 3 메모리 포렌식 | [`item/06-post-exploitation/forensics/volatility3.md`](item/06-post-exploitation/forensics/volatility3.md) |
| 바이너리 정적/동적 역공학 및 디스어셈블링 | Rizin 리버스 엔지니어링 | [`item/06-post-exploitation/forensics/rizin.md`](item/06-post-exploitation/forensics/rizin.md) |

---

## 🛠️ 공통 기반 도구 & 환경 (Common)

| 상황 (트리거) | 리소스 내용 | 리소스 경로 |
| :--- | :--- | :--- |
| 리눅스 텍스트 검색, 치환, 파이프라인 제어 | Find, Grep, JQ, Tar, XXD, Vim 등 | [`item/common/linux-cli/`](item/common/linux-cli/) |
| Bash 스크립트 문법, 반복문, 조건문 작성 | Bash 문법 및 브루트포스 템플릿 | [`item/common/linux-cli/bash/`](item/common/linux-cli/bash/) |
| RSA, Diffie-Hellman, Base64, 해시 알고리즘 계산 | 암호학 기본 수학 및 해시 도구 | [`item/common/cryptography/`](item/common/cryptography/) |
| 간단한 HTTP 파일 서버 및 커스텀 퍼징 스크립트 | Python 간이 서버 / Fuzzing 스크립트 | [`item/common/scripts/`](item/common/scripts/) |
| 도커 환경 설치, 가상환경, OpenVPN 셋업 | 랩 구축 및 운영 가이드 | [`item/common/lab-setup/`](item/common/lab-setup/) |

---

## 🏆 실전 침투 롸잇업 (Writeups)

> 모든 롸잇업은 [`WRITEUP_GUIDE.md`](WRITEUP_GUIDE.md) 표준 서식을 준수하여 작성되었습니다.

| 대상 타겟 | 플랫폼 | 주요 취약점 / 기법 | 리소스 |
| :--- | :--- | :--- | :--- |
| **Path Traversal** | Dreamhack | 입력값 조작을 통한 디렉터리 순회 (기준 롸잇업) | [`completed/red/dreamhack_path_traversal.md`](completed/red/dreamhack_path_traversal.md) |
| **Pressed** | TryHackMe | PCAP 트래픽 분석 및 Base64 플래그 복원 | [`completed/red/pressed.md`](completed/red/pressed.md) |
| **Attacktive Directory** | TryHackMe | Kerbrute, AS-REP Roasting, Pass-the-Hash | [`completed/red/Attacktive Directory.md`](completed/red/Attacktive%20Directory.md) |
| **Skynet** | TryHackMe | SMB 열거, Cuppa RFI, Tar 와일드카드 권한상승 | [`completed/red/skynet.md`](completed/red/skynet.md) |
| **Blue** | TryHackMe | MS17-010 EternalBlue 원격 코드 실행 | [`completed/red/blue.md`](completed/red/blue.md) |
| **Pickle Rick** | TryHackMe | 웹 소스 분석, 명령 인젝션, Sudo 권한상승 | [`completed/red/Pickle_Rick.md`](completed/red/Pickle_Rick.md) |
| **Publisher** | TryHackMe | SPIP CMS RCE, AppArmor 프로필 분석 | [`completed/red/publisher.md`](completed/red/publisher.md) |
| **Smol** | TryHackMe | 워드프레스 플러그인 취약점, JS 우회 | [`completed/red/smol.md`](completed/red/smol.md) |
| *전체 롸잇업 목록* | - | 총 31건의 실전 침투 머신 롸잇업 | [`completed/red/`](completed/red/) |
