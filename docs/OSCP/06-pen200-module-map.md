# 06. OSCP+ 시험에 필요한 역량 ↔ 무료 학습 자료 매핑

> 목적: OSCP+ 시험의 핵심 역량을, 무료로 공개된 자료만으로 미리 익힌다.\n>\n> - 이 표는 유료 OSCP+ 강의(PEN-200, Challenge Labs)의 모듈 구성을 그대로 따라 하지 않는다. OSCP+ 강의 자료는 유출되어 사용할 수 없다.\n> - 대신, OSCP 시험이 평가하는 역량(정찰 → 취약점 → 침투 → 권한 상승 → AD → 리포트)에 해당하는 무료 공개 자료를 매핑한다.\n> - 무료 자료는 강의 시청·실습으로 이미 넉넉하다. 그래서 이 표는 "무엇을 공부해야 하는가"를 빠르게 보여주는 데 쓴다.\n> - 실제 공부 순서는 [01-curriculum.md](./01-curriculum.md)의 단계 순서를 따른다.

범례: 🆓 무료 · 🧪 실습 룸(무료)

---

## 1. 정보 수집 (Reconnaissance) — 🆓

| 역량 | 무료 자료 | 레포 치트시트 |
|------|----------|--------------|
| 호스트/포트 스캔 | 🆓 Metasploit Unleashed의 enum 섹션 · 🆓 TryHackMe Nmap 룸 | [nmap](../cheatsheets/recon/network/nmap.md) · [rustscan](../cheatsheets/recon/network/rustscan.md) · [netdiscover](../cheatsheets/recon/network/netdiscover.md) · [ping](../cheatsheets/recon/network/ping.md) |
| 트래픽 분석 | 🆓 tcpdump · 🆓 Wireshark 기본기 (위키/방송) | [tcpdump](../cheatsheets/recon/network/tcpdump.md) · [wireshark_display_filter](../cheatsheets/recon/wireshark/wireshark_display_filter.md) |
| DNS/OSINT | 🆓 Offsec의 enum 자료 · 🆓 TryHackMe 관련 룸 | [dns](../cheatsheets/recon/dns/dns.md) · [hosts](../cheatsheets/recon/dns/hosts.md) |
| 웹 서브도메인/vhost | 🆓 dnsrecon · Sublist3r (무료) | [dnsrecon](../cheatsheets/recon/dns/dnsrecon.md) · [Sublist3r](../cheatsheets/recon/dns/Sublist3r.md) |

> enum 체크리스트는 [03-methodology-checklist.md](./03-methodology-checklist.md)의 B섹션을 따른다.

---

## 2. 취약점 분석 (Vulnerability Analysis)

| 역량 | 무료 자료 | 레포 치트시트 |
|------|----------|--------------|
| searchsploit / Exploit-DB | 🆓 Exploit-DB GitHub · 🆓 searchsploit 문서 | [searchsploit](../cheatsheets/cve/searchsploit.md) |
| 서비스별 버전 확인 | 🆓 whatweb / nikto / wpscan (무료 강의) | [whatweb](../cheatsheets/recon/web-surface/whatweb.md) · [nikto](../cheatsheets/recon/web-surface/nikto.md) · [gobuster](../cheatsheets/recon/web-surface/gobuster.md) · [ffuf](../cheatsheets/recon/web-surface/ffuf.md) · [wpscan](../cheatsheets/recon/web-surface/wpscan.md) |
| SQLi | 🆓 PortSwigger SQLi Academy (무료) · 🆓 The Hacker Recipes | [sql_inject](../cheatsheets/web/sqli/sql_inject.md) · [blind_sql](../cheatsheets/web/sqli/blind_sql.md) · [sqlmap](../cheatsheets/web/sqli/sqlmap.md) |
| 파일 인클루전·업로드 | 🆓 PortSwigger (무료) · 🆓 HackTricks | [rfi](../cheatsheets/web/file-inclusion/rfi.md) · [php_filter_chain_generator](../cheatsheets/web/file-inclusion/php_filter_chain_generator.md) · [file-upload](../cheatsheets/web/file-upload.md) |
| SSRF / IDOR | 🆓 PortSwigger (무료) | [ssrf](../cheatsheets/web/ssrf/ssrf.md) · [idor](../cheatsheets/web/idor.md) |
| XSS | 🆓 PortSwigger XSS Academy (무료) · 🆓 HackTricks | [xss](../cheatsheets/web/xss/xss.md) · [javascript_blind_xss](../cheatsheets/web/xss/javascript_blind_xss.md) |
| Flask/개발서비스 특화 | 🆓 Flask 공식 튜토리얼 | [flask](../cheatsheets/web/flask.md) |

> SQLmap 같은 자동 익스플로잇은 OSCP에서 금지된다. 학습용으로 써도 되지만, 시험에서는 사용하지 않는 것이 규칙이다([01-curriculum.md 단계 2 참고](./01-curriculum.md)).

---

## 3. 초기 침투 (Initial Access)

| 역량 | 무료 자료 | 레포 치트시트 |
|------|----------|--------------|
| reverse shell | 🆓 모든 언어 cheat sheet | [reverse_shell](../cheatsheets/shells/reverse-shell/reverse_shell.md) · [bind-shell](../cheatsheets/shells/bind-shell.md) · [cmd_list](../cheatsheets/shells/reverse-shell/cmd_list.md) |
| 셸 안정화 | 🆓 `python -c 'import pty...'` (Metasploit Unleashed) · 🆓 rlwrap | [python_pty](../cheatsheets/shells/shell-upgrade/python_pty.md) · [dump_shell_upgrade](../cheatsheets/shells/reverse-shell/dump_shell_upgrade.md) |
| 웹셸 | 🆓 php_filter_chain_generator (PayloadsAllTheThings) | [php_webshell](../cheatsheets/shells/web-shell/php_webshell.md) · [php_pipe](../cheatsheets/shells/reverse-shell/php_pipe.md) · [icmp_reverse_shell](../cheatsheets/shells/reverse-shell/icmp_reverse_shell.md) |
| 패스워드 공격 | 🆓 SecLists · Hydra · John/hashcat (각 GitHub 문서) | [hydra](../cheatsheets/cracking/hydra/hydra.md) · [hashcat](../cheatsheets/cracking/hashcat/hashcat.md) · [john_the_ripper](../cheatsheets/cracking/john/john_the_ripper.md) · [wordlists](../cheatsheets/cracking/wordlists.md) |
| Metasploit 활용 | 🆓 Metasploit Unleashed (공개 강의) | [msfvenom](../cheatsheets/metasploit/msfvenom.md) · [meterpreter](../cheatsheets/metasploit/meterpreter/meterpreter.md) |

> Metasploit은 시험에서 독립 머신 1대에만 사용 가능하다. 학습에는 공개 강의에서 충분히 익힌다.

---

## 4. Windows / Linux 권한 상승

| 역량 | 무료 자료 | 레포 치트시트 |
|------|----------|--------------|
| Windows 권한 | 🆓 LOLBAS · 🆓 HackTricks Windows PrivEsc | [00-overview](../cheatsheets/windows/privileges/overview.md) · [SeDebugPrivilege](../cheatsheets/windows/privileges/SeDebugPrivilege.md) · [SeImpersonatePrivilege](../cheatsheets/windows/privileges/SeImpersonatePrivilege.md) · [SeTcbPrivilege](../cheatsheets/windows/privileges/SeTcbPrivilege.md) · [scenarios-tools](../cheatsheets/windows/privileges/scenarios-tools.md) |
| Linux 권한 | 🆓 GTFOBins · 🆓 linpeas/winpeas (Kali 기본) | [privilege_escalation_overview](../cheatsheets/linux/privesc/privilege_escalation_overview.md) · [linpeas](../cheatsheets/linux/privesc/linpeas/linpeas.md) · [sudo_privesc](../cheatsheets/linux/privesc/sudo_privesc.md) · [suid](../cheatsheets/linux/privesc/suid.md) · [crontab](../cheatsheets/linux/privesc/crontab.md) · [gtfobinaries](../cheatsheets/linux/privesc/gtfobins/gtfobinaries.md) |

---

## 5. Active Directory (⭐)

> ⭐ 표시는 전체 학습 시간의 1/3을 배분할 만한 핵심 영역이다. (01-curriculum 단계 5 참고)

| 역량 | 무료 자료 | 레포 치트시트 |
|------|----------|--------------|
| AD 열거 | 🆓 The Hacker Recipes · 🆓 BloodHound (GitHub) | [bloodhound](../cheatsheets/active-directory/bloodhound.md) · [enum4linux](../cheatsheets/active-directory/enum4linux.md) · [crackmapexec](../cheatsheets/active-directory/crackmapexec.md) · [rpcclient](../cheatsheets/active-directory/rpcclient.md) |
| Kerberos 공격 | 🆓 The Hacker Recipes · 🆓 HackTricks | [kerbrute](../cheatsheets/active-directory/kerbrute.md) · [impacket](../cheatsheets/active-directory/impacket.md) · [hashcat](../cheatsheets/cracking/hashcat/hashcat.md) |
| AD 이동·재사용 | 🆓 The Hacker Recipes · 🆓 PayloadsAllTheThings | [evil-winrm](../cheatsheets/windows/evil-winrm.md) · [smbmap](../cheatsheets/active-directory/smb/smbmap.md) · [bloodhound](../cheatsheets/active-directory/bloodhound.md) |
| delegation / DCSync | 🆓 HackTricks AD | [scenarios-tools](../cheatsheets/windows/privileges/scenarios-tools.md) |

---

## 6. 터널링 / 측면 이동 (Advanced Tunneling)

| 역량 | 무료 자료 | 레포 치트시트 |
|------|----------|--------------|
| 피벗팅 | 🆓 ligolo-ng · chisel (GitHub 공개) | [mitmproxy_quick](../cheatsheets/pivoting/proxy/mitmproxy_quick.md) — HTTP 가로채기용이며, 피벗팅의 대표 도구는 ligolo-ng/chisel |
| SSH 터널링 | 🆓 `ligolo-ng`/`chisel` 문서 | — (무료로 학습 후 신규 작성 필요) |
| proxychains | 🆓 각 보안 블로그의 "proxychains" 문서 | — |

> OSCP의 Advanced Tunneling 모듈은 유료 경로에만 있다. 무료 경로에서는 이 표의 무료 자료로 충분히 익힌다.

---

## 7. 증적 수집 & 리포트

| 역량 | 무료 자료 | 레포 치트시트 |
|------|----------|--------------|
| 증적 수집 습관 | 🆓 OSCP Exam Guide(공개)의 증적 규칙 | [03-methodology-checklist.md](./03-methodology-checklist.md) — H섹션 |
| 리포트 작성 | 🆓 noraj 템플릿 (GitHub 공개) | [04-resources.md](./04-resources.md) — 리포트 섹션 |

---

## 8. 공부 순서 권장

```text
선행 → 2(리포트 습관) → 3·4(정찰/스캔) → 5·6·7(웹) → 9(익스플로잇 다루기)\n   → 12(패스워드) → 13·14(privesc, 양손) → 15(터널링) → 17·18·19(AD, 가장 많은 시간)\n   → 반복 복습 → 리포트 완성
```

- 8·11(클라이언트·AV)은 시험 비중이 낮아 가볍게.
- ⭐ 표시(AD)에 전체 시간의 1/3 이상을 배분한다.
- PortSwigger Academy·HackTricks·The Hacker Recipes·TryHackMe는 전부 무료이며, 결제 전에 이 자료로 실무 역량을 대부분 익힐 수 있다.

---

## 9. 출처

- 공개 강의/방송/저장소는 각 링크의 제공자 페이지를 기준으로 한다.
- OSCP/OSCP+ 시험의 "역량" 정의 자체는 공개된 Exam Guide를 참고하되, 유료 강의 모듈 구성은 사용하지 않는다.
