# 침투 테스트 & CTF 전체 수행 이력 총정리

수동 모의침투부터 취약점 전수 진단, 자체 CTF 플랫폼 구축, AI 공방 시뮬레이션까지 수행한 모든 보안 자산을 한눈에 파악할 수 있도록 표 중심으로 재구성한 총정리 문서입니다.

---

## 1. 전체 영역 요약

| 영역 | 규모 | 주요 대상 및 핵심 기법 |
| :--- | :---: | :--- |
| **수동 머신 침투** | 32건 | Active Directory, Linux Boot2Root, OWASP Top 10 완주 |
| **침투 도구·기법 자산** | 150+개 | 7대 라이프사이클 치트시트, 커스텀 Fuzzing 스크립트 |
| **취약점 전수 진단** | 104건 | XBOW-104 (XSS 23, SSTI 13, IDOR 12, RCE 10 등) 전수 분석 |
| **자체 CTF 플랫폼** | 40개 | LUXORA 10대 레이어 독립 컨테이너 격리 챌린지 직접 구축 |
| **AI 공방 시뮬레이션** | 65개 | 레드팀(기본 100%, 심화 70.3%) vs 블루팀(허니팟 방어) 교전 |

---

## 2. 수동 머신 침투 및 CTF (32건)

### 2.1 Active Directory & Windows 인프라
| 머신명 | 타겟 환경 | 취약점 및 초기 침투 | 권한 상승 (PrivEsc) 및 결과 |
| :--- | :--- | :--- | :--- |
| **Attacktive Directory** | Windows AD DC | Kerbrute 유효 계정 열거, AS-REP Roasting (`GetNPUsers.py`) | SMB `backup` 자격증명 확보 → `secretsdump` NTLM 해시 덤프 → `Evil-WinRM` Pass-the-Hash |
| **Blue** | Windows 7 x64 | SMB 포트(445) MS17-010 (EternalBlue) | Metasploit 익스플로잇 → `SYSTEM` 권한 획득 및 SAM 해시 덤프 |

### 2.2 Linux Boot2Root 머신
| 머신명 | 초기 침투 벡터 | 권한 상승 (PrivEsc) 기법 |
| :--- | :--- | :--- |
| **Pickle Rick** | 웹 소스 주석 단서 확보, `less`·`grep` 명령어 필터링 우회 | `sudo -l` 조회 후 `NOPASSWD: ALL` 악용 `sudo bash` 실행 |
| **Skynet** | SquirrelMail 브루트포스 로그인, Cuppa CMS RFI 웹쉘 실행 | Crontab 백업 스크립트 내 `tar *` 와일드카드 파라미터 인젝션 |
| **Startup** | 익명 FTP 파일 업로드 및 웹 경로 매핑을 통한 PHP 웹쉘 호출 | `suspicious.pcap` 분석 자격증명 확보, 쓰기 가능 Crontab 스크립트 변조 |
| **Publisher** | SPIP CMS v4.2.1 비인가 RCE (CVE-2023-32943) 익스플로잇 | AppArmor 제한 프로필 우회 |
| **Pyrat** | 8000 포트 원시 파이썬 인터프리터 소켓 연결, 리버스 셸 주입 | 내부 백그라운드 프로세스 분석 및 패스워드 크래킹 |
| **Cheese CTF** | PHP Filter Chain Generator를 이용한 메모리상 LFI to RCE | 내부 Sudo 취약 설정 악용 |
| **Billing** | MagnusBilling v6.x CVE-2023-30258 인증 우회 및 커맨드 인젝션 | 로컬 권한 상승 |
| **Smol** | WordPress 취약 플러그인 (CSRF, SSRF, RCE) 탐지 및 침투 | 웹쉘 업로드 및 관리자 권한 장악 |
| **Silverplatter** | Tor 프록시(`torsocks`) 환경 정찰, Silverpeas 취약점 공략 | 시스템 내부 자격증명 탈취 |
| **Lookup** | `ffuf` 서브도메인 브루트포싱, 노출된 엘라스틱서치 로그 분석 | 시스템 계정 확보 및 침투 |

### 2.3 웹 취약점 심층 실습 (OWASP Top 10)
| 챌린지명 | 취약점 유형 | 공격 메커니즘 및 수행 방식 |
| :--- | :--- | :--- |
| **Dreamhack Path Traversal** | Directory Traversal | `curl` 직접 요청으로 클라이언트 JS 우회, `../` 디렉터리 순회 |
| **lo-fi** | LFI | `?page=` 파라미터에 `../../../../flag.txt` 상대 경로 주입 |
| **The Sticker Shop** | Blind XSS | 피드백 폼 Blind XSS 주입, 내부 검토 봇을 통한 로컬 플래그 탈취 |
| **Light** | Blind SQLi | 1337 포트 SQLite 원시 소켓 대상 대소문자 혼합 필터링 우회 |
| **sqlmap_thm** | SQL Injection | 로그인 폼 대상 `sqlmap --dbs --level=5` MariaDB 전체 덤프 |
| **SSRF** | SSRF | 이미지 URL 파라미터 루프백 주소 주입, 내부 관리자 페이지 접근 |
| **Corridor** | IDOR | 방 번호 정수 MD5 해시 규칙 식별, `0`의 해시 대입 관리자 방 침투 |
| **Neighbour** | IDOR | 프로필 파라미터 변조로 타 사용자 정보 및 플래그 무단 열거 |
| **Take-Over** | Subdomain Takeover | TLS SAN 열거, 미할당 AWS S3 버킷 선점으로 도메인 장악 |

### 2.4 포렌식 · AI 보안 · 암호학 · 리버싱
| 분야 | 챌린지명 | 핵심 기법 및 수행 방식 |
| :--- | :--- | :--- |
| **네트워크 포렌식** | **Pressed** | `traffic.pcapng` 패킷 분석, HTTP POST 내 분할 Base64 조각 병합 복원 |
| **AI 보안** | **Evil GPT (v1, v2)** | 탈옥(Jailbreak) 프롬프트 인젝션, 시스템 프롬프트 유출 및 OS 명령 실행 |
| **암호학** | **w1se_guy** | XOR 스트림 암호 대상 Known Plaintext Attack, 대칭 키 역산 복호화 스크립트 구현 |
| **포너블** | **off_by_one_001** | C 언어 1바이트 버퍼 오버플로우, 인접 변수 변조로 검증 조건문 무력화 |
| **리버싱** | **rev-basic-0 / compiled** | Rizin/GDB 디스어셈블링, `strncmp` 분기문 분석 메모리 문자열 추출 |

---

## 3. 침투 도구 및 기법 자산화 (150+개)

`kali/item/` 디렉터리에 구축된 7대 라이프사이클 실전 가이드입니다.

| 도메인 | 핵심 기법 및 보유 도구 |
| :--- | :--- |
| **정찰 (Recon)** | Nmap, RustScan, Netdiscover, Tcpdump, Wireshark, Gobuster, ffuf, Sublist3r, DNSRecon, Curl, Httpie, Tor |
| **Active Directory** | Kerbrute, Bloodhound, enum4linux, smbclient, rpcclient, smbmap |
| **취약점 분석** | sqlmap, Burp Suite, WPScan, Searchsploit, DB별(MySQL, MSSQL, MongoDB, Oracle, PostgreSQL, SQLite) 핸드북 |
| **초기 침투 & 크래킹** | Hashcat (Mangling Rules), John the Ripper (Custom Rules), Hydra, Metasploit, msfvenom, ICMP 셸, TTY 업그레이드 |
| **권한 상승 (PrivEsc)** | LinPEAS, pspy, GTFOBins(xxd 등), Sudo 취약점, SUID/SGID, Crontab, AppArmor, Evil-WinRM, PowerShell |
| **피보팅 & 포렌식** | mitmproxy, SSH Port Forwarding, Proxychains, Volatility 3, Rizin, 커스텀 TCP 무차별 대입 스크립트 |

---

## 4. XBOW-104 실전 벤치마크 전수 진단 (104개)

104개 전체 태스크 전수 수행 및 개별 트랜스크립트 분석 리포트 보유 (`XBEN-001-24` ~ `XBEN-104-24`).

| 항목 | 상세 내용 |
| :--- | :--- |
| **수행 규모** | 총 104개 태스크, 18.6시간 교전, 3억 2,500만 토큰 소모 분석 |
| **레벨별 해결률** | Level 1: **78.9%** (30/38) · Level 2: **52.3%** (23/44) · Level 3: **28.6%** (2/7) |
| **취약점 분포** | XSS(23), SSTI(13), IDOR(12), 권한상승(14), 커맨드 인젝션(10), LFI(9), SQLi(7), 역직렬화(5), SSRF(3), XXE(3) 등 |

---

## 5. LUXORA 자체 CTF 플랫폼 구축 (40개)

`vulnerable/` 저장소에 자체 설계·구축한 10대 레이어 40개 독립 컨테이너 격리 챌린지 인프라입니다.

| 공격 레이어 | 독립 챌린지 목록 (각 컨테이너 격리 및 독립 플래그) |
| :--- | :--- |
| **Injection** | `sqli`, `nosqli`, `cmdi`, `ldap`, `ssti` |
| **Authentication** | `brute`, `jwt`, `oauth`, `mfa` |
| **Access Control** | `admin`, `idor`, `privesc`, `rbac` |
| **Client-Side** | `xss`, `csrf`, `clickjack`, `postmsg` |
| **File & Resource** | `lfi`, `upload`, `xxe`, `deser` |
| **Server-Side** | `ssrf`, `proto_pollute`, `race`, `smuggle` |
| **Logic & Business** | `biz_logic`, `ratelimit`, `payment` |
| **Crypto & Secrets** | `weak_crypto`, `info_disc`, `secret`, `timing` |
| **Infrastructure** | `redirect`, `cors`, `host`, `container` |
| **Advanced** | `reverse`, `webshell`, `multistage`, `persist` |

---

## 6. AI 레드팀 vs 블루팀 실전 공방 (65개)

[`pentesting/`](pentesting/) ([GitHub: agnusdei1207/pentesting](https://github.com/agnusdei1207/pentesting.git)) 서브모듈 기반 AI 자율 침투 및 방어 연구 과제입니다.

| 항목 | 상세 내용 |
| :--- | :--- |
| **시나리오 구성** | OWASP · MITRE ATT&CK 기반 기본 25개 + 심화 40개 (총 65개) |
| **침투 성능** | 기본 25개 플래그 획득률 **8% → 100%**, 심화 40개 **70.3%** 달성 |
| **방어 성능** | 블루팀 다이나믹 허니팟 적용 시 레드 에이전트 실서버 침투 **0건** 완벽 차단 |
| **핵심 인프라 기술** | PTY 세션 보존, UDS 파일 디스크립터 전달, Mux/deMux 병렬 세션 라우팅 |
