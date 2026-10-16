# 01. 커리큘럼 — 단계별 학습 순서

> 아래 순서대로 공부하면 이 레포의 `docs/cheatsheets/` 치트시트를 킬체인 흐름대로 복습하게 된다.
> 각 단계 끝의 체크포인트를 통과하면 다음 단계로.
> 경로는 이 문서(`docs/OSCP/`) 기준 상대경로.

```text
0. 기반 환경  ─▶  1. 정찰  ─▶  2. 취약점 분석  ─▶  3. 초기 침투
                                                        │
        6. 포스트 익스플로잇  ◀─  5. 측면 이동(AD)  ◀─  4. 권한 상승
```

---

## 단계 0 — 기반 환경 / CLI 체력

OSCP는 도구를 많이 아는 시험이 아니라, 아는 것을 얼마나 빠르고 정확하게 쓰느냐의 시험이다. 이 단계는 가볍게 넘기되 확실히 익혀 두자.

- Kali/랩 세팅: [lab-setup](../cheatsheets/common/lab-setup/) — [open_vpn.md](../cheatsheets/common/lab-setup/open_vpn.md), [python_venv.md](../cheatsheets/common/lab-setup/python_venv.md)
- Bash 기초: [bash_overview.md](../cheatsheets/common/linux-cli/bash/bash_overview.md), [loop.md](../cheatsheets/common/linux-cli/bash/loop.md), [brute_force.md](../cheatsheets/common/linux-cli/bash/brute_force.md)
- 필수 CLI: [grep](../cheatsheets/common/linux-cli/grep.md) · [find](../cheatsheets/common/linux-cli/find.md) · [vim](../cheatsheets/common/linux-cli/vim.md) · [scp](../cheatsheets/common/linux-cli/scp.md) · [jq](../cheatsheets/common/linux-cli/jq.md)
- 인코딩/암호: [ENCODING_DECODING_REFERENCE.md](../cheatsheets/common/ENCODING_DECODING_REFERENCE.md), [base64](../cheatsheets/common/cryptography/base64.md), [hashid](../cheatsheets/common/cryptography/hashid.md)

체크포인트: VPN 연결 후 타깃까지 ping·nmap이 막힘없이 나가고, bash 반복문으로 간단한 포트/단어 루프를 즉석에서 짤 수 있다.

---

## 단계 1 — 정찰 (Reconnaissance)

머신을 뚫느냐 마느냐는 대부분 정찰(enumeration)에서 갈린다. "더 찾아볼 건 없나?"를 입에 붙이자.

- 호스트 발견/스캔: [netdiscover](../cheatsheets/01-reconnaissance/network/netdiscover.md) · [nmap](../cheatsheets/01-reconnaissance/network/nmap.md) · [rustscan](../cheatsheets/01-reconnaissance/network/rustscan.md)
- 트래픽: [tcpdump](../cheatsheets/01-reconnaissance/network/tcpdump.md) · [wireshark](../cheatsheets/01-reconnaissance/network/wireshark/wireshark_display_filter.md) · [netcat](../cheatsheets/01-reconnaissance/network/netcat.md)
- DNS/OSINT: [dns.md](../cheatsheets/01-reconnaissance/osint-dns/dns.md) · [hosts.md](../cheatsheets/01-reconnaissance/osint-dns/hosts.md)
- 웹 표면: [whatweb](../cheatsheets/01-reconnaissance/web-surface/whatweb.md) · [nikto](../cheatsheets/01-reconnaissance/web-surface/nikto.md) · [gobuster](../cheatsheets/01-reconnaissance/web-surface/gobuster.md) · [ffuf](../cheatsheets/01-reconnaissance/web-surface/ffuf.md) · [wpscan](../cheatsheets/01-reconnaissance/web-surface/wpscan.md) · [curl](../cheatsheets/01-reconnaissance/web-surface/curl/curl.md)
- 서브도메인: [dnsrecon](../cheatsheets/01-reconnaissance/web-surface/subdomain/dnsrecon.md) · [Sublist3r](../cheatsheets/01-reconnaissance/web-surface/subdomain/Sublist3r.md)
- AD 정찰(최우선): [enum4linux](../cheatsheets/01-reconnaissance/active-directory/enum4linux.md) · [crackmapexec](../cheatsheets/01-reconnaissance/active-directory/crackmapexe.md) · [rpcclient](../cheatsheets/01-reconnaissance/active-directory/rpcclient.md) · [smbclient](../cheatsheets/01-reconnaissance/active-directory/smb/smbclient.md) · [smbmap](../cheatsheets/01-reconnaissance/active-directory/smb/smbmap.md) · [kerbrute](../cheatsheets/01-reconnaissance/active-directory/kerbrute.md) · [impacket](../cheatsheets/01-reconnaissance/active-directory/impacket.md) · [bloodhound](../cheatsheets/01-reconnaissance/active-directory/bloodhound.md)

체크포인트: 포트·서비스별 "다음에 무엇을 열거할지"를 외우지 않고도 체크리스트로 끌어낼 수 있다. ([03-methodology-checklist.md](./03-methodology-checklist.md)와 연동)

---

## 단계 2 — 취약점 분석 (Vulnerability Analysis)

- 익스플로잇 검색: [searchsploit](../cheatsheets/02-vulnerability-analysis/cve/searchsploit.md)
- 서비스별: [ftp](../cheatsheets/02-vulnerability-analysis/services/ftp/ftp.md) · [mysql](../cheatsheets/02-vulnerability-analysis/services/database/mysql.md) · [mssql](../cheatsheets/02-vulnerability-analysis/services/database/mssql.md) · [postgres](../cheatsheets/02-vulnerability-analysis/services/database/postgres.md) · [oracle](../cheatsheets/02-vulnerability-analysis/services/database/oracle.md)
- 웹 취약점(시험 빈출):
  - SQLi: [sql_inject](../cheatsheets/02-vulnerability-analysis/web/sqli/sql_inject.md) · [blind_sql](../cheatsheets/02-vulnerability-analysis/web/sqli/blind_sql.md) · [sqlmap](../cheatsheets/02-vulnerability-analysis/web/sqli/sqlmap.md)
  - 파일 인클루전/업로드: [rfi](../cheatsheets/02-vulnerability-analysis/web/file-inclusion/rfi.md) · [php_filter_chain_generator](../cheatsheets/02-vulnerability-analysis/web/file-inclusion/php_filter_chain_generator.md) · [file-upload](../cheatsheets/02-vulnerability-analysis/web/file-upload.md)
  - 기타: [ssrf](../cheatsheets/02-vulnerability-analysis/web/ssrf/ssrf.md) · [idor](../cheatsheets/02-vulnerability-analysis/web/idor.md) · [xss](../cheatsheets/02-vulnerability-analysis/web/xss/xss.md) · [flask](../cheatsheets/02-vulnerability-analysis/web/flask.md)

체크포인트: 발견한 서비스/버전에서 searchsploit → 수동 검증까지 자동반사. SQLi를 sqlmap 없이 손으로 뽑아낼 수 있다(시험에서 sqlmap 사용 금지).

---

## 단계 3 — 초기 침투 (Initial Access)

- 셸 기초: [reverse_shell](../cheatsheets/03-initial-access/shells/reverse-shell/reverse_shell.md) · [reverse_shell_cheatsheet](../cheatsheets/03-initial-access/shells/reverse-shell/reverse_shell_cheatsheet.md) · [bind-shell](../cheatsheets/03-initial-access/shells/bind-shell.md)
- 셸 안정화: [python_pty](../cheatsheets/03-initial-access/shells/shell-upgrade/python_pty.md) · [dump_shell_upgrade](../cheatsheets/03-initial-access/shells/reverse-shell/dump_shell_upgrade.md) · [rlwrap](../cheatsheets/common/lab-setup/rlwrap.md)
- 웹셸: [php_webshell](../cheatsheets/03-initial-access/shells/web-shell/php_webshell.md)
- 크리덴셜 공격: [hydra](../cheatsheets/03-initial-access/cracking/hydra/hydra.md) · [hashcat](../cheatsheets/03-initial-access/cracking/hashcat/hashcat.md) · [john_the_ripper](../cheatsheets/03-initial-access/cracking/john-the-ripper/john_the_ripper.md) · [wordlists](../cheatsheets/03-initial-access/cracking/wordlists.md) · [seclists](../cheatsheets/03-initial-access/cracking/seclists.md)
- MSF(시험은 1대 제한, 그래도 숙지): [msfvenom](../cheatsheets/03-initial-access/framework/msf/msfvenom/msfvenom.md) · [meterpreter](../cheatsheets/03-initial-access/framework/msf/meterpreter/meterpreter.md)

체크포인트: 리버스 셸을 받고 즉시 안정화(TTY 업그레이드)까지 1~2분 안에. msfvenom 없이도 여러 언어로 셸 페이로드를 쓸 수 있다.

> 버퍼 오버플로우(BOF)는? 예전처럼 반드시 나오는 전용 문제는 아니다. 다만 20점짜리 머신의 권한 상승 경로로 부수적으로 등장할 수 있으니, 기본 개념과 흐름 정도만 익혀 두면 충분하다. 여기에 많은 시간을 쏟을 필요는 없다.

---

## 단계 4 — 권한 상승 (Privilege Escalation)

독립 머신 점수의 절반이 여기서 나온다. Linux와 Windows 어느 쪽도 소홀히 하면 안 된다.

- 개요/공통: [privilege_escalation_overview](../cheatsheets/04-privilege-escalation/linux/privilege_escalation_overview.md)
- Linux:
  - 자동열거: [linpeas](../cheatsheets/04-privilege-escalation/linux/linpeas/linpeas.md)
  - 수동: [information_gathering](../cheatsheets/04-privilege-escalation/linux/information_gathering.md) · [sudo_privesc](../cheatsheets/04-privilege-escalation/linux/sudo_privesc.md) · [suid](../cheatsheets/04-privilege-escalation/linux/suid.md) · [sgid](../cheatsheets/04-privilege-escalation/linux/sgid.md) · [gtfobinaries](../cheatsheets/04-privilege-escalation/linux/gtfobins/gtfobinaries.md) · [crontab](../cheatsheets/04-privilege-escalation/linux/crontab.md) · [pkexec](../cheatsheets/04-privilege-escalation/linux/pkexec.md)
  - 크리덴셜: [etc_passwd](../cheatsheets/04-privilege-escalation/linux/credentials/etc_passwd.md) · [shadow](../cheatsheets/04-privilege-escalation/linux/credentials/shadow.md)
- Windows:
  - 기초: [windows_basic](../cheatsheets/04-privilege-escalation/windows/cmd/windows_basic.md) · [base_powershell](../cheatsheets/04-privilege-escalation/windows/powershell/base_powershell.md) · [evil-winrm](../cheatsheets/04-privilege-escalation/windows/evil-winrm.md)
  - 권한 악용: [privileges/00-overview](../cheatsheets/04-privilege-escalation/windows/privileges/00-overview.md) · [SeImpersonatePrivilege](../cheatsheets/04-privilege-escalation/windows/privileges/02-SeImpersonatePrivilege.md) · [SeDebugPrivilege](../cheatsheets/04-privilege-escalation/windows/privileges/01-SeDebugPrivilege.md) · [scenarios-tools](../cheatsheets/04-privilege-escalation/windows/privileges/04-scenarios-tools.md)

체크포인트: linpeas/winPEAS 출력에서 "실제로 악용 가능한 한 줄"을 골라낼 수 있다. GTFOBins·SeImpersonate 류를 보자마자 공격 경로가 떠오른다.

---

## 단계 5 — 측면 이동 / Active Directory (최우선 투자)

AD 세트는 40점이라 사실상 여기서 합격 여부가 갈린다. 이 레포의 치트시트가 얇은 영역이므로 외부 자료([04-resources.md](./04-resources.md))로 보강하자.

- Pivoting: 이 레포에는 아직 피벗팅 치트시트가 없다. `ligolo-ng`, `chisel`, SSH 포트포워딩, `proxychains`를 외부 자료로 학습하고 치트시트를 새로 만든다.
  - 참고로 [mitmproxy_quick](../cheatsheets/05-lateral-movement/pivoting/proxy/mitmproxy_quick.md)은 HTTP 가로채기 프록시라 네트워크 피벗팅 용도가 아니다.
- AD 공격 체인(정찰은 단계 1의 AD 섹션과 연결):
  1. 열거 → BloodHound로 경로 파악 ([bloodhound](../cheatsheets/01-reconnaissance/active-directory/bloodhound.md))
  2. 크리덴셜 획득: 장악한 호스트에서 크리덴셜 덤프(mimikatz, secretsdump), AS-REP Roasting, Kerberoasting ([kerbrute](../cheatsheets/01-reconnaissance/active-directory/kerbrute.md), [impacket](../cheatsheets/01-reconnaissance/active-directory/impacket.md))
  3. 재사용/이동: Pass-the-Hash, Pass-the-Ticket, `crackmapexec`/`evil-winrm`
  4. 권한 위임(delegation) 악용, DCSync로 도메인 장악

체크포인트: assumed-breach 상황(저권한 도메인 계정 1개)에서 DC까지 가는 경로를 외부 walkthrough 없이 스스로 세울 수 있다.

---

## 단계 6 — 포스트 익스플로잇 & 리포트

- OSCP의 post-exploitation 핵심은 크리덴셜 수집과 피벗팅이며, 이는 단계 5(AD/측면 이동)에서 이미 다뤘다.
- 참고: 레포의 [volatility3](../cheatsheets/06-post-exploitation/forensics/volatility3.md)·[rizin](../cheatsheets/06-post-exploitation/forensics/rizin.md)은 메모리 포렌식/리버싱 도구로 OSCP 시험 범위 밖이다. 궁금하면 참고만, 우선순위는 낮게.
- 증적 수집 습관화: 각 머신에서 `whoami`/`hostname`/`ip`/flag를 스크린샷. 시험은 리포트까지가 점수.
- 리포트 작성 연습: [04-resources.md](./04-resources.md)의 템플릿 참고. 랩/모의시험마다 짧게라도 리포트를 써 본다.

체크포인트: 머신 하나를 풀면 재현 가능한 스텝 + 스크린샷이 리포트에 바로 들어갈 형태로 남는다.

---

## 단계별 완료 기준 요약

```text
[0] CLI/환경 무리 없음           [1] enum 체크리스트 자동반사
[2] 수동 취약점 검증 가능         [3] 셸 획득·안정화 빠름
[4] Linux+Windows privesc 양손   [5] AD 체인 스스로 설계  ← 가장 중요
[6] 리포트가 풀이와 동시에 완성
```
