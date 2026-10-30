# 01. 커리큘럼

> 단계별 학습 순서. 각 단계는 [02-platform-plan.md](./02-platform-plan.md)의 무료 플랫폼 위에서 머신을 공략하며 익힌다. 관련 도구 사용법은 [../cheatsheets/](../cheatsheets/)의 해당 문서를 참조한다.\n>\n> 이 커리큘럼은 현재는 무료 자료로만 구성한다. 유료 플랫폼을 원할 때는 그때 대비해 유연하게 확장할 수 있다.

---

## 단계 0. 선행 학습 (기초 다지기)

| 항목 | 내용 | 무료 자료 |
|------|------|----------|
| bash | 명령어, 리다이렉션, 파이프, 반복문, 조건문 | OverTheWire Bandit, [../cheatsheets/linux/cli/](../cheatsheets/linux/cli/) |
| 네트워크 | IP, 라우팅, ARP, 포트, VPN(tun0) | [iproute2.md](../cheatsheets/recon/network/iproute2.md), [hostname.md](../cheatsheets/recon/network/hostname.md) |
| 웹 기초 | HTTP 요청/응답, 쿠키, 상태 코드 | Professor Messer, PortSwigger Academy 기초 |
| 보안 기초 | CIA 삼각구, 인증/인가, 취약점 개념 | Professor Messer Security+ |

---

## 단계 1. 정찰 및 열거 (Reconnaissance)

- 호스트 탐색: `ping`, `netdiscover`, `rustscan`, `nmap` (-sS, -sV, -O)
- 서비스/기술 스택: `whatweb`, `nikto`, `gobuster`, `ffuf`
- DNS/서브도메인: `dnsrecon`, `Sublist3r`, `hosts`, `enum4linux`
- 웹 표면: `curl` (GET/POST, 헤더), `httpie`
- OSINT: whois, DNS 조회, `shodan`(공개 제한 있음)

관련 치트시트: [recon](../cheatsheets/recon/)

---

## 단계 2. 취약점 분석 (Vulnerability Analysis)

- CVE/익스플로잇 검색: `searchsploit`, Exploit-DB
- 웹: SQLi, XSS, SSRF, IDOR, 파일 인클루전(파일 업로드), PHP 필터 체인
- 인증: 쿠키 디코딩, 기본 자격 증명, 브루트 포스(Hydra, wordlist)
- 참고: sqlmap 같은 자동 툴은 OSCP에서 금지될 수 있으므로, 수동 기법 위주로 익힌다.

관련 치트시트: [web](../cheatsheets/web/) 쨌 [services](../cheatsheets/services/) 쨌 [cve](../cheatsheets/cve/)

---

## 단계 3. 초기 침투 (Initial Access)

- 리버스 쉘/바인드 쉘: bash, python, php, netcat 변형
- 셸 안정화: `python3 -c 'import pty; pty.spawn("/bin/bash")'`, `rlwrap`, `script`
- 웹셸: PHP 웹셸 업로드, 명령 실행
- 크리덴셜: Hydra, John the Ripper, hashcat, wordlists (rockyou 등)
- Metasploit: `msfvenom` 페이로드 생성, `exploit/multi/handler` 리스너 (독립 머신 1대 한도 참고)

관련 치트시트: [shells](../cheatsheets/shells/) 쨌 [cracking](../cheatsheets/cracking/) 쨌 [metasploit](../cheatsheets/metasploit/)

---

## 단계 4. 권한 상승 (Privilege Escalation)

- Linux: SUID/SGID, sudo, crontab, GTFOBins, linpeas(열거 전용), 커널 익스플로잇
- Windows: SeDebug/SeImpersonate/SeTcb 특권, 토큰 위장, 서비스/스케줄된 작업, LOLBAS
- AD: BloodHound, enum4linux, crackmapexec, Kerberos 공격 기초

관련 치트시트: [linux/privesc](../cheatsheets/linux/privesc/) 쨌 [windows](../cheatsheets/windows/)

---

## 단계 5. Active Directory (집중 영역)

- 전체 학습 시간의 약 1/3을 AD에 배분한다(06-pen200-module-map ⭐ 참조).
- 열거: enum4linux, rpcclient, crackmapexec, BloodHound
- 공격: Kerberoasting, AS-REP Roasting, Pass-the-Hash, 골든 티켓 기초
- 측면 이동: SMB, WinRM, evil-winrm

관련 치트시트: [active-directory](../cheatsheets/active-directory/)

---

## 단계 6. 증적 및 리포트

- 각 단계의 스크린샷, 명령어, 출력, 판단을 노트(05-progress-tracker)에 기록한다.
- 리포트 템플릿: noraj OSCP Exam Report Template(공개), 또는 OffSec 공식 템플릿(시험 응시 시).
- 모의 시나리오를 직접 풀고 리포트를 작성하는 연습을 반복한다.

관련 치트시트: [../cheatsheets/common/](../cheatsheets/common/)

---

## 학습 비율 가이드

- 정찰·취약점 분석: 25%
- 초기 침투: 15%
- 권한 상승(Linux/Windows): 20%
- AD: 25% (⭐ 가장 많은 시간)
- 리포트/증적: 15%

> 순서는 정찰 → 웹 → 침투 → 권한 상승 → AD 순서로, 약한 단계는 반복한다.
