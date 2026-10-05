# 🔴 Red Team 실습 롸잇업 허브 (Completed Labs)

CTF, Wargame, 모의침투 랩(TryHackMe, DreamHack, OffSec 등)의 완료 및 진행 중인 침투테스트 롸잇업 모음입니다.  
각 실습은 독립된 디렉터리 내의 마크다운 파일로 체계적으로 분류되어 관리됩니다.

---

## 📂 실습 디렉터리 목차 (Alphabetical Index)

총 **32개**의 실습 롸잇업이 정리되어 있습니다.

| 번호 | 실습 이름 | 경로 | 플랫폼 / 대상 | 주요 공격 기법 및 핵심 취약점 |
|:---:|---|---|---|---|
| 01 | **Attacktive Directory** | [`attacktive-directory/`](./attacktive-directory/README.md) | TryHackMe | Windows Active Directory 열거, Kerbrute, AS-REP Roasting, SMB/LDAP |
| 02 | **Billing** | [`billing/`](./billing/README.md) | OSCP / Lab | CVE-2023-30258 취약점 분석, 웹 열거 및 권한 상승 |
| 03 | **Blue** | [`blue/`](./blue/README.md) | TryHackMe | Windows SMB MS17-010 (EternalBlue) 원격 코드 실행 |
| 04 | **Cheese CTF** | [`cheese-ctf/`](./cheese-ctf/README.md) | CTF | Cheese Shop 웹 애플리케이션 분석, LFI/RCE, 권한 상승 |
| 05 | **Compiled** | [`compiled/`](./compiled/README.md) | Reversing | Rizin 도구를 활용한 바이너리 정적/동적 리버스 엔지니어링 |
| 06 | **Corridor** | [`corridor/`](./corridor/README.md) | TryHackMe | MD5 해시 파라미터 기반 IDOR / 디렉터리 트래버설 |
| 07 | **CVE-2026-22200** | [`cve-2026-22200/`](./cve-2026-22200/README.md) | OffSec | osTicket mPDF `php://filter` 임의 파일 읽기 (단계별 모듈형) |
| 08 | **Dreamhack 3166** | [`dreamhack-3166/`](./dreamhack-3166/README.md) | DreamHack | Hidden Text (Zero-Width Unicode 스테가노그래피 분석) |
| 09 | **Dreamhack Path Traversal** | [`dreamhack-path-traversal/`](./dreamhack-path-traversal/README.md) | DreamHack | Web Path Traversal 취약점 및 파라미터 우회 |
| 10 | **Evil GPT** | [`evil-gpt/`](./evil-gpt/README.md) | CTF | 악성 AI 툴 기반 공격 시나리오 정찰 및 침투 |
| 11 | **Hydra Base** | [`hydra-base/`](./hydra-base/README.md) | Lab / Tool | Hydra HTTP POST Form 기반 웹 로그인 무차별 대입 실습 |
| 12 | **Light** | [`light/`](./light/README.md) | TryHackMe | SQLite 데이터베이스 인젝션 및 인증 우회 |
| 13 | **Lo-fi** | [`lo-fi/`](./lo-fi/README.md) | TryHackMe | Local File Inclusion (LFI) 취약점 분석 및 시스템 파일 추출 |
| 14 | **Lookup** | [`lookup/`](./lookup/README.md) | TryHackMe | 불완전한 SSH 인증 설정 취약점 및 쉘 획득 |
| 15 | **MSF** | [`msf/`](./msf/README.md) | Lab / Tool | Metasploit Framework `psexec` 모듈 활용 SMB 침투 |
| 16 | **Neighbour** | [`neighbour/`](./neighbour/README.md) | TryHackMe | IDOR (Insecure Direct Object Reference) 취약점 악용 |
| 17 | **Off-by-One 001** | [`off-by-one-001/`](./off-by-one-001/README.md) | DreamHack | Pwnable Off-by-one 버퍼 오버플로우 메모리 변조 |
| 18 | **Pickle Rick** | [`pickle-rick/`](./pickle-rick/README.md) | TryHackMe | 웹 폼 분석, 커맨드 인젝션(Command Injection) 및 권한 상승 |
| 19 | **Planning** | [`planning/`](./planning/README.md) | TryHackMe | 포트 스캐닝 및 웹 서비스 취약점 분석 |
| 20 | **Pressed** | [`pressed/`](./pressed/README.md) | TryHackMe | WordPress PCAP 네트워크 패킷 분석 및 침해 지표 조사 |
| 21 | **Publisher** | [`publisher/`](./publisher/README.md) | TryHackMe | SPIP CMS 취약점 악용 및 AppArmor 제한 우회 권한 상승 |
| 22 | **Pyrat** | [`pyrat/`](./pyrat/README.md) | TryHackMe | 커스텀 Python 네트워크 서비스 분석 및 백도어 탈취 |
| 23 | **Rev-Basic-0** | [`rev-basic-0/`](./rev-basic-0/README.md) | DreamHack | x86-64 바이너리 기본 분기문 리버스 엔지니어링 |
| 24 | **Silverplatter** | [`silverplatter/`](./silverplatter/README.md) | TryHackMe | Silverpeas 협업 도구 취약점 및 내부 침투 |
| 25 | **Skynet** | [`skynet/`](./skynet/README.md) | TryHackMe | Samba 공유 열거, Cuppa CMS LFI, Tar 와일드카드 권한 상승 |
| 26 | **Smol** | [`smol/`](./smol/README.md) | TryHackMe | WordPress 취약 플러그인 악용, 다단계 권한 상승 체인 |
| 27 | **SQLMap THM** | [`sqlmap-thm/`](./sqlmap-thm/README.md) | TryHackMe | SQLMap 자동화 인젝션 도구 활용 데이터베이스 덤프 |
| 28 | **SSRF** | [`ssrf/`](./ssrf/README.md) | Lab / Web | Server-Side Request Forgery 내부 루프백 서비스 접근 |
| 29 | **Startup** | [`startup/`](./startup/README.md) | TryHackMe | FTP Anonymous 업로드 웹쉘 획득, PCAP 트래픽 분석 및 역쉘 |
| 30 | **Take-Over** | [`take-over/`](./take-over/README.md) | TryHackMe | DNS CNAME 서브도메인 탈취(Subdomain Takeover) 취약점 |
| 31 | **The Sticker Shop** | [`the-sticker-shop/`](./the-sticker-shop/README.md) | TryHackMe | Blind Stored XSS 악용 내부 웹페이지 및 플래그 탈취 |
| 32 | **W1se Guy** | [`w1se-guy/`](./w1se-guy/README.md) | TryHackMe | XOR 스트림 암호화 취약점 분석 및 키 복구 브루트포스 |

---

## 🎯 CVE-2026-22200 단계별 문서 구조

[`cve-2026-22200/`](./cve-2026-22200/README.md) 실습은 문서 분량이 방대하여 아래와 같이 했던 작업 단위별 번호 마크다운(`1.md`~`6.md`)로 분리되어 있습니다:

- [README.md](./cve-2026-22200/README.md): 실습 개요, 타겟 정보, 현황 및 종합 인덱스
- [1. 공격 표면 조사 및 취약점 진단](./cve-2026-22200/1.md): `ffuf` 경로 탐색, 웹 폼 조사, `check.py` 취약 여부 진단
- [2. 페이로드 생성 및 티켓 생성](./cve-2026-22200/2.md): mPDF 필터 체인 페이로드 생성(`/etc/passwd`, `ost-config.php`), 페이로드 장착 티켓 제출
- [3. 티켓 번호 브루트포스 및 접근 확보](./cve-2026-22200/3.md): 티켓 번호 브루트포스, 등록 계정 열거, 접근 링크 위조
- 4단계 이후(PDF 추출, SSH 후속 침투, 근본 원인)는 실제 진행 후 문서를 추가한다
- [tmp/submit_guest_tickets.py](./cve-2026-22200/tmp/submit_guest_tickets.py): 게스트 티켓 자동 생성 및 페이로드 삽입 스크립트
- [tmp/burp-open-request.md](./cve-2026-22200/tmp/burp-open-request.md): Burp Suite로 캡처한 페이로드 제출 요청 본문(원본 + 분석)

---

## 💡 문서 작성 규칙

모든 롸잇업은 [`docs/WRITEUP_GUIDE.md`](../../WRITEUP_GUIDE.md)의 원칙을 준수하여 작성됩니다:
- `관찰 → 판단 → 실행 → 결과` 순서로 간결하게 기록
- 각 단계는 1~3문장 이내로 핵심만 서술
- 민감 정보(패스워드, 개인키, 토큰, 플래그)는 `REDACTED` 처리
