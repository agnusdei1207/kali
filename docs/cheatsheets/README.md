# 치트시트 인덱스

침투 테스트 기법·도구 모음이다. 폴더는 단계가 아니라 대상(도메인) 기준으로 나눈다. 검색은 파일명(Ctrl+P) 기준이므로 파일명이 기법을 드러내게 쓴다.

> 관련 문서: [루트 README](../../README.md) · [롸잇업 인덱스](../write-ups/red/README.md) · [OSCP 학습 경로](../OSCP/README.md) · [AGENTS.md](../../AGENTS.md)

---

| 폴더 | 다루는 내용 |
|---|---|
| [recon/](./recon/) | 네트워크 스캔(nmap, rustscan, netcat…), 웹 표면(ffuf, gobuster, curl, nikto…), DNS·서브도메인, Wireshark |
| [active-directory/](./active-directory/) | AD 열거(bloodhound, crackmapexec, impacket, kerbrute, smb…) |
| [web/](./web/) | 웹 취약점 전반(xss, ssrf, idor, file-upload, file-inclusion, wordpress…) |
| [web/sqli/](./web/sqli/) | SQL 인젝션(PoC·UNION 추출·blind·sqlmap) |
| [services/](./services/) | 서비스별 기초·열거(database, ftp, ssh, tls, openssl) |
| [shells/](./shells/) | 리버스·바인드 쉘, 웹쉘, 쉘 업그레이드 |
| [cracking/](./cracking/) | hashcat, john, hydra, wordlists, 아카이브 크래킹 |
| [metasploit/](./metasploit/) | msf 전반(msfvenom, meterpreter, 리스너…) |
| [linux/](./linux/) | Linux 프리비슥(privesc/)과 CLI 기본(cli/) |
| [windows/](./windows/) | Windows 프리비슥, cmd, powershell |
| [pivoting/](./pivoting/) | 프록시(burp, mitmproxy, proxychains), 프록시 포트스캔 |
| [forensics/](./forensics/) | volatility3, rizin |
| [cve/](./cve/) | searchsploit, CVE 개별 노트 |
| [common/](./common/README.md) | 인코딩·암호화, 마크업, 랩 구성, 유틸 스크립트 |

---

## 파일 구성 규칙

- 파일명은 기법 단위로 쓰고, 같은 파일명이 다른 폴더에 반복되지 않게 한다. (예: `postgres.md`는 services/database에만 두고, Linux 프리비슥 문서는 `postgres_privesc.md`)
- 같은 지식을 단계별로 사본 내지 않고 이곳 한곳에만 둔다. 단계는 폴더 축이 아니다.
- 실행 스크립트(.sh, .py, .cmd, .ps1)는 성격에 맞는 폴더의 scripts/ 아래에 모은다.
- 파일명은 검색으로 찾는 것을 전제로 한다. 약어를 쓰지 않고 끝까지 적는다. (예: `xss_exfil.md` (X) → `xss_exfiltration.md` (O), `xss_recon.md` (X) → `xss_reconnaissance.md` (O))
- 원리·배경 설명(이론)은 해당 주제 폴더 안의 `theory/` 하위 폴더에 두고, 파일명에 theory를 포함한다. (예: `smb/theory/smb_ports_theory.md`)

## 작성 규칙

- 표를 쓰지 않는다. 비교·정리가 필요하면 목록이나 코드 블록으로 풀어 쓴다.
- 설명은 최소한으로 한다. OSCP 시험 등 실전에서 바로 쓸 수 있도록 명령어·페이로드를 중심으로 배치한다.
- 기술 설명이 필요한 부분은 직관적이고 간결하게 쓰고, 이해를 돕는 도해는 ASCII 그래프로 표현한다. Mermaid(` ```mermaid `)는 쓰지 않는다.
- 명령은 복붙 가능한 형태로 쓰고, 실행 결과가 필요한 경우만 짧게 덧붙인다.
- 볼드(`**`) 강조를 쓰지 않는다. 강조는 제목·목록·코드 블록으로 대신한다.
- "모든 시도는 합법적인 대상에서만", "오직 교육 목적" 같은 당연한 법적·윤리 면책 문구를 반복하지 않는다. (본문에 적지 않는다)
- 금지 문구(일부): "합법적인 대상", "합법적인 보안 테스트", "오직 교육 목적", "법적 주의사항", "합법적 사용", "합법성". 이 단어가 들어간 면책 문장은 작성하지 않는다.

## 사용법

- 실습 중 막힐 때 해당 주제 폴더에서 명령을 찾는다.
- 실제 적용 사례는 [롸잇업 인덱스](../write-ups/red/README.md)에서 확인한다.
