# 03. 방법론 체크리스트 (시험장용)

> 시험장에서 멍해질 때 위에서부터 그대로 따라가는 체크리스트.
> 연습하면서 본인 손에 맞게 계속 고쳐 나갈 것. 치트시트 링크는 `docs/cheatsheets/` 기준.

---

## A. 시험 전체 시간 배분 (23h 45m)

```text
0h          환경 세팅 · 모든 타깃 동시 nmap 시작 · 스크린샷 준비
0~1h        AD 세트 먼저 착수 (40점, 체인이 길어 시간이 많이 듦)
            └ 막히면 독립 머신으로 전환, AD는 틈틈이
~타깃당      독립 머신 1대당 타임박스 3~4h, 넘으면 다음 머신으로
중간중간     70점 도달 여부 계속 확인 — 넘으면 안정화 + 증적 보강
식사·수면     최소 1회 식사와 2~4h 수면을 미리 일정에 넣는다 (감독관에게 알리고 휴식 가능)
마지막 2~3h  더 파기 중단, 플래그·스크린샷·명령어 로그 정리
리포트(+24h) 재현 가능한 스텝으로 작성
```

- 70점 안전 조합을 먼저 확보한 뒤 추가 점수를 노린다. (예: AD 40 + 독립 1.5대)
  - 단 2026-12-01부터는 환산 채점(scaled scoring)이라 "70점"이 그대로 합격선이 아닐 수 있다. 응시 전 Exam Guide에서 현재 기준을 확인할 것. 그래도 "최대한 많이, AD를 끝까지"라는 전략 자체는 동일하다.
- 한 머신 타임박스를 넘기면 미련 없이 전환. 머리를 식히면 보이는 게 생긴다.

---

## B. 포트/서비스 발견 직후 (enumeration 반사표)

> "열거할 게 더 없나?"를 매 서비스마다. 참고: [nmap](../cheatsheets/01-reconnaissance/network/nmap.md)

```text
전체        nmap -p- 빠른 스캔 → 열린 포트에 -sCV 정밀 스캔
UDP         nmap -sU --top-ports 로 SNMP 등 UDP 서비스 확인 (TCP만 보면 161을 놓친다)
21 FTP      anonymous 로그인? 버전 exploit? 업로드 가능? → ftp.md
22 SSH      버전/배너, 키 재사용, 약한 크리덴셜(hydra는 신중)
25/110/143  메일 서비스, 사용자 열거
53 DNS      zone transfer, 서브도메인 → dns.md / dnsrecon.md
80/443 HTTP ★가장 중요★ → 아래 C 섹션
88 Kerberos → AD 머신 신호! → D 섹션
389/636 LDAP 도메인 정보, 익명 바인드 가능 여부 → D 섹션
111/2049 NFS showmount, 마운트
139/445 SMB enum4linux / smbmap / smbclient — 공유·널세션 → AD 치트시트
161 SNMP    community string, snmpwalk
1433 MSSQL  / 3306 MySQL / 5432 Postgres → services/database/
3389 RDP    크리덴셜 확보 후 접속
5985 WinRM  evil-winrm 대상 → evil-winrm.md
```

---

## C. 웹(80/443) 체크리스트

> 참고: [whatweb](../cheatsheets/01-reconnaissance/web-surface/whatweb.md) · [ffuf](../cheatsheets/01-reconnaissance/web-surface/ffuf.md) · [gobuster](../cheatsheets/01-reconnaissance/web-surface/gobuster.md)

```text
[ ] whatweb / 헤더 / 소스보기 / robots.txt / sitemap
[ ] 디렉터리·파일 퍼징 (ffuf/gobuster, 확장자 포함)
[ ] 서브도메인/vhost 퍼징 (Host 헤더)
[ ] CMS면 전용 스캐너 (wpscan 등)
[ ] 로그인 폼 → 기본 크리덴셜 / SQLi
[ ] 입력값마다: SQLi / LFI·RFI / 파일 업로드 / SSRF / IDOR / 커맨드 인젝션
[ ] 발견한 버전 → searchsploit → 수동 검증
```
관련: [sql_inject](../cheatsheets/02-vulnerability-analysis/web/sqli/sql_inject.md) · [rfi](../cheatsheets/02-vulnerability-analysis/web/file-inclusion/rfi.md) · [file-upload](../cheatsheets/02-vulnerability-analysis/web/file-upload.md) · [ssrf](../cheatsheets/02-vulnerability-analysis/web/ssrf/ssrf.md)

---

## D. Active Directory 세트 (assumed breach)

> 저권한 도메인 계정 1개에서 시작. 참고: [bloodhound](../cheatsheets/01-reconnaissance/active-directory/bloodhound.md) · [impacket](../cheatsheets/01-reconnaissance/active-directory/impacket.md)

```text
[ ] 주어진 크리덴셜로 도메인 열거 (crackmapexec / ldapdomaindump)
[ ] 첫 진입 호스트에서 로컬 권한 상승 (F 섹션 Windows)
[ ] 관리자 권한 확보 후 크리덴셜 덤프 (mimikatz / secretsdump) → 다음 호스트로
[ ] BloodHound 수집 → DC까지 최단 경로 확인
[ ] AS-REP Roasting (pre-auth 미설정 계정)
[ ] Kerberoasting (SPN 계정) → hashcat으로 크랙
[ ] 공유/스크립트/GPP에서 평문·재사용 크리덴셜 탐색
[ ] 크리덴셜 재사용: Pass-the-Hash / Pass-the-Ticket
[ ] 측면 이동: evil-winrm / psexec / wmiexec
[ ] delegation(비제약/제약/RBCD) 악용 가능?
[ ] DC 장악 → DCSync로 마무리
```
크래킹: [hashcat](../cheatsheets/03-initial-access/cracking/hashcat/hashcat.md) · 이동: [evil-winrm](../cheatsheets/04-privilege-escalation/windows/evil-winrm.md) · [crackmapexec](../cheatsheets/01-reconnaissance/active-directory/crackmapexe.md)

---

## E. 셸 획득 직후

> 참고: [python_pty](../cheatsheets/03-initial-access/shells/shell-upgrade/python_pty.md) · [reverse_shell_cheatsheet](../cheatsheets/03-initial-access/shells/reverse-shell/reverse_shell_cheatsheet.md)

```text
[ ] Linux: TTY 업그레이드 (python pty + stty) / Windows: rlwrap nc로 받기
[ ] whoami / id / hostname / ip  → 스크린샷
[ ] local.txt 확보 → 스크린샷 (내용 + IP가 한 화면에)
[ ] 곧바로 권한상승 열거로 (F 섹션)
```

---

## F. 권한 상승 체크리스트

### Linux — 참고: [privilege_escalation_overview](../cheatsheets/04-privilege-escalation/linux/privilege_escalation_overview.md)
```text
[ ] sudo -l  (GTFOBins 매칭)
[ ] SUID/SGID 바이너리  (GTFOBins)
[ ] cron / 쓰기 가능 스크립트·PATH
[ ] 평문 크리덴셜(설정/히스토리/백업), /etc/passwd 쓰기, shadow
[ ] 커널/서비스 버전 exploit
[ ] 자동: linpeas (하지만 "악용 가능한 한 줄"만 취한다)
```
링크: [sudo_privesc](../cheatsheets/04-privilege-escalation/linux/sudo_privesc.md) · [suid](../cheatsheets/04-privilege-escalation/linux/suid.md) · [gtfobinaries](../cheatsheets/04-privilege-escalation/linux/gtfobins/gtfobinaries.md) · [crontab](../cheatsheets/04-privilege-escalation/linux/crontab.md) · [linpeas](../cheatsheets/04-privilege-escalation/linux/linpeas/linpeas.md)

### Windows — 참고: [privileges/00-overview](../cheatsheets/04-privilege-escalation/windows/privileges/00-overview.md)
```text
[ ] whoami /priv  → SeImpersonate/SeDebug 등 악용 가능 권한
[ ] 서비스 권한(바이너리 경로/unquoted path/약한 ACL)
[ ] AlwaysInstallElevated, 스케줄 작업
[ ] 평문 크리덴셜(설정/레지스트리/히스토리)
[ ] 자동: winPEAS
```
링크: [SeImpersonatePrivilege](../cheatsheets/04-privilege-escalation/windows/privileges/02-SeImpersonatePrivilege.md) · [scenarios-tools](../cheatsheets/04-privilege-escalation/windows/privileges/04-scenarios-tools.md)

---

## G. Pivoting (멀티 네트워크)

```text
[ ] 발판 호스트의 추가 인터페이스/내부 대역 확인
[ ] ligolo-ng 또는 chisel로 터널
[ ] proxychains 통해 내부 타깃 enum
```
(치트시트 얇은 영역 → 외부 자료로 보강: [04-resources.md](./04-resources.md))

---

## H. 증적/리포트 (점수의 일부)

```text
[ ] 머신마다: 공격 경로 명령어 전부 로그로 저장
[ ] 플래그 스크린샷은 대화형 셸에서 cat/type local.txt·proof.txt + ip addr/ipconfig를 한 화면에 (웹셸 화면은 인정 안 됨)
[ ] 플래그는 복붙 가능하게 텍스트로도 보관하고 시험 포털에 바로 제출
[ ] 리포트는 "제3자가 그대로 재현 가능한" 수준으로
```

---

## 막혔을 때 리셋 루틴

```text
1. 스캔 결과를 처음부터 다시 읽는다 (놓친 포트/서비스?)
2. 모든 서비스에 C/D 체크리스트를 다시 적용
3. 15분 자리 비우기 → 다른 머신 → 돌아오기
4. 그래도 안 되면 그 머신은 타임박스 종료, 노트에 "왜 막혔는지" 기록
```
