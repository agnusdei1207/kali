# 침투 테스트 & CTF 전체 수행 이력 총정리

수동 모의침투부터 취약점 전수 진단, 자체 CTF 플랫폼 구축, AI 공방 시뮬레이션까지 수행한 모든 보안 자산을 군더더기 없는 개조식으로 정리한 문서입니다.

---

## 1. 전체 영역 요약

- **수동 머신 침투**: 32개 타겟 완주 (Active Directory, Linux Boot2Root, Web)
- **침투 기법·도구 자산**: 150여 개 실전 치트시트 및 커스텀 파이썬 스크립트 구축
- **취약점 전수 진단**: XBOW 104개 산업 표준 태스크 단독 수행 및 전수 리포트 작성
- **자체 CTF 플랫폼**: LUXORA 10대 레이어 40개 독립 컨테이너 챌린지 직접 설계
- **AI 공방 시뮬레이션**: 65개 시나리오 교전 (기본 25개 100%, 심화 40개 70.3% 플래그 획득)

---

## 2. 수동 머신 침투 및 CTF (32건)

### Active Directory & Windows
- **Attacktive Directory**
  - 타겟: Windows AD Domain Controller
  - 정찰: `kerbrute userenum` 기반 도메인 유효 계정 열거
  - 침투: Impacket `GetNPUsers.py` AS-REP Roasting → Hashcat(18200) 해시 크래킹
  - 권승: `smbclient` backup 공유 접근 → `secretsdump.py` 관리자 해시 덤프 → `Evil-WinRM` Pass-the-Hash
- **Blue**
  - 타겟: Windows 7 x64
  - 정찰: SMB 포트(445) 스캔, MS17-010(EternalBlue) 취약점 탐지
  - 침투: Metasploit EternalBlue 익스플로잇
  - 결과: `SYSTEM` 권한 획득, SAM 해시 덤프

### Linux Boot2Root
- **Pickle Rick**
  - 침투: 웹 소스 주석 및 `robots.txt` 단서 확보, `less`·`grep`으로 명령어 필터링 우회
  - 권승: `sudo -l` 확인 후 `NOPASSWD: ALL` 악용 `sudo bash` 실행
- **Skynet**
  - 침투: 익명 SMB 정찰, SquirrelMail 브루트포스 로그인, Cuppa CMS RFI 웹쉘 실행
  - 권승: Crontab 백업 스크립트 내 `tar *` 와일드카드 파라미터 인젝션
- **Startup**
  - 침투: 익명 FTP 파일 업로드, 웹 경로 매핑을 통한 PHP 웹쉘 호출
  - 권승: `suspicious.pcap` 패킷 분석 자격증명 탈취, 쓰기 가능한 Crontab 스크립트(`/etc/print.sh`) 변조
- **Publisher**
  - 침투: SPIP CMS v4.2.1 비인가 RCE(CVE-2023-32943) 익스플로잇
  - 권승: AppArmor 제한 프로필 우회
- **Pyrat**
  - 침투: 8000 포트 원시 파이썬 인터프리터 소켓 연결, 리버스 셸 주입
  - 권승: 내부 백그라운드 프로세스 분석 및 패스워드 크래킹
- **Cheese CTF**
  - 침투: `php_filter_chain_generator.py`를 이용한 메모리상 LFI to RCE 유발
  - 권승: 내부 Sudo 취약 설정 악용
- **Billing**
  - 침투: MagnusBilling v6.x 대상 CVE-2023-30258 인증 우회 및 커맨드 인젝션 RCE
- **Smol / Silverplatter / Lookup**
  - Smol: WordPress 취약 플러그인(CSRF, SSRF, RCE) 탐지 및 침투
  - Silverplatter: Tor 프록시(`torsocks`) 환경 정찰 및 Silverpeas 그룹웨어 취약점 공략
  - Lookup: `ffuf` 서브도메인 브루트포싱, 노출된 엘라스틱서치 로그 분석

### 웹 취약점 (OWASP Top 10)
- **Dreamhack Path Traversal**: `curl` 직접 요청으로 클라이언트 JS 우회, `../` 디렉터리 순회
- **lo-fi**: `?page=` 파라미터 상대 경로 주입(`../../../../flag.txt`)
- **The Sticker Shop**: 피드백 폼 Blind XSS 주입, 내부 봇을 통한 로컬 플래그 탈취
- **Light**: 1337 포트 SQLite 원시 소켓 대상 대소문자 혼합 필터 우회, Blind SQLi
- **sqlmap_thm**: 로그인 파라미터 대상 `sqlmap --dbs --level=5` MariaDB 덤프
- **SSRF**: 이미지 파라미터 루프백 주소 주입, 내부 관리자 페이지 접근 및 Base64 플래그 복원
- **Corridor**: 방 번호 정수 MD5 해시 패턴 식별, `0`의 MD5 해시 대입 관리자 방 침투
- **Neighbour**: 프로필 파라미터 변조(IDOR)를 통한 타 사용자 정보 및 플래그 무단 열거
- **Take-Over**: TLS 인증서 SAN 열거, 미할당 AWS S3 버킷 서브도메인 테이크오버

### 네트워크 포렌식 / AI 보안 / 암호학 / 리버싱
- **Pressed**: `traffic.pcapng` 패킷 분석, HTTP POST 내 분할된 3개 Base64 조각 병합 복원
- **Evil GPT (v1, v2)**: 탈옥(Jailbreak) 프롬프트 인젝션, 시스템 프롬프트 유출 및 OS 명령 실행
- **w1se_guy**: XOR 스트림 암호 대상 Known Plaintext Attack, 키 역산 복호화 스크립트 구현
- **off_by_one_001**: C 언어 1바이트 버퍼 오버플로우, 인접 변수 변조를 통한 조건문 무력화
- **rev-basic-0 / compiled**: Rizin/GDB 디스어셈블링, `strncmp` 분기문 분석 메모리 문자열 추출

---

## 3. 침투 도구 및 기법 자산화 (150+개)

`kali/item/` 디렉터리에 구축된 도메인별 실전 가이드입니다.

- **정찰 (Recon)**
  - 포트·네트워크 스캔: Nmap, RustScan, Netdiscover, Tcpdump, Wireshark
  - 웹 디렉터리·도메인 탐색: Gobuster, ffuf, Sublist3r, DNSRecon, Curl, Httpie, Tor
- **Active Directory**
  - 계정 열거 및 도메인 분석: Kerbrute, Bloodhound, enum4linux
  - SMB·RPC 진단: smbclient, rpcclient, smbmap
- **취약점 분석**
  - 웹 취약점: SQLi, Blind SQLi, XSS, SSRF, LFI/RFI, PHP Filter Chain, IDOR, 파일 업로드
  - 데이터베이스 핸드북: MySQL, MSSQL, MongoDB, Oracle, PostgreSQL, SQLite
  - 자동화 진단: sqlmap, Burp Suite, WPScan, Searchsploit
- **초기 침투 & 크래킹**
  - 자격증명 크래킹: Hashcat (Mangling Rules), John the Ripper (Custom Rules), Hydra
  - 셸 핸들링: Metasploit, msfvenom, ICMP Reverse Shell, TTY 인터랙티브 업그레이드
- **권한 상승**
  - Linux: LinPEAS, pspy, GTFOBins(xxd 등), Sudo 취약점, SUID/SGID, Crontab, AppArmor
  - Windows: Evil-WinRM, CMD, PowerShell
- **피보팅 & 포렌식 & 스크립트**
  - 피보팅: mitmproxy, SSH Port Forwarding, Proxychains
  - 포렌식·역공학: Volatility 3, Rizin
  - 자체 개발 도구: 커스텀 TCP 소켓 무차별 대입 스크립트, URL 인코더/디코더

---

## 4. XBOW-104 실전 벤치마크 전수 진단 (104개)

104개 전체 태스크 전수 수행 및 개별 트랜스크립트 분석 리포트 보유 (`XBEN-001-24` ~ `XBEN-104-24`).

- **수행 통계**: 총 104개 태스크, 18.6시간 교전, 3억 2,500만 토큰 소모 분석
- **레벨별 해결률**: Level 1 (78.9%), Level 2 (52.3%), Level 3 (28.6%)
- **취약점 유형별 태스크 분포**:
  - XSS: 23건 (Reflected, Stored, DOM)
  - SSTI: 13건 (Jinja2, Twig, ERB)
  - IDOR / BOLA: 12건
  - 권한 상승: 14건 (수평·수직 인가 결함)
  - Command Injection: 10건
  - LFI / Path Traversal: 9건
  - SQLi / Blind SQLi: 7건
  - Insecure Deserialization: 5건
  - SSRF (3건), XXE (3건), Arbitrary File Upload (4건), JWT (2건) 등

---

## 5. LUXORA 자체 CTF 플랫폼 (40개)

`vulnerable/` 저장소에 자체 구축한 10대 레이어 40개 독립 컨테이너 격리 챌린지 인프라입니다.

- **아키텍처**: 40개 서비스가 전용 도커 컨테이너 및 유닉스 소켓으로 격리, 독립 플래그 보유
- **레이어별 챌린지**:
  - `Injection`: sqli, nosqli, cmdi, ldap, ssti
  - `Authentication`: brute, jwt, oauth, mfa
  - `Access Control`: admin, idor, privesc, rbac
  - `Client-Side`: xss, csrf, clickjack, postmsg
  - `File & Resource`: lfi, upload, xxe, deser
  - `Server-Side`: ssrf, proto_pollute, race, smuggle
  - `Logic & Business`: biz_logic, ratelimit, payment
  - `Crypto & Secrets`: weak_crypto, info_disc, secret, timing
  - `Infrastructure`: redirect, cors, host, container
  - `Advanced`: reverse, webshell, multistage, persist

---

## 6. AI 레드팀 vs 블루팀 실전 공방 (65개)

[`pentesting/`](pentesting/) ([GitHub: agnusdei1207/pentesting](https://github.com/agnusdei1207/pentesting.git)) 서브모듈 기반 AI 자율 침투 및 방어 연구 과제입니다.

- **시나리오**: OWASP·MITRE ATT&CK 기반 기본 25개 + 심화 40개 (총 65개)
- **침투 성능**: 기본 25개 플래그 획득률 **8% → 100%**, 심화 40개 **70.3%** 달성
- **방어 성능**: 블루팀 다이나믹 허니팟 적용 시 레드 에이전트 실서버 침투 **0건** 완벽 차단
- **인프라 기술**: PTY 세션 보존, UDS 파일 디스크립터 전달, Mux/deMux 병렬 세션 라우팅
