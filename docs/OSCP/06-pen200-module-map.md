# 06. PEN-200 모듈 ↔ 무료 공개 자료 매핑

> 목적: $1,749 PEN-200 교재를 결제하기 전에, 각 모듈이 다루는 주제를
> 합법적인 무료/저가 공개 자료로 미리 학습해서 여유 있게 들어가기 위한 표.
>
> - 모듈 목록은 OffSec 공식 PEN-200 신택스(2026-03판)에서 가져온 공개 정보다.
> - 아래 "무료 자료"는 OffSec 교재의 복제·대체가 아니라, 같은 주제를 다루는 공개 레퍼런스다.
> - "레포 치트시트"는 이 저장소의 `docs/cheatsheets/` 파일 (경로는 `docs/OSCP/` 기준).
> - 실제 교재의 모듈 구성·순서는 결제 후 학생 포털에서 다시 확인할 것.

범례: 🆓 무료 · 💲 저가 유료 · 🧪 실습 플랫폼

---

## 선행(파운데이션) — PEN-200 본문 전에 깔아둘 것

> OffSec은 Linux/Bash/네트워킹/Python 같은 기초를 별도 파운데이션으로 둔다. 개발·인프라 배경이면 빠르게 통과.

| 주제 | 무료/공개 자료 | 레포 치트시트 |
|------|----------------|---------------|
| Linux CLI / Bash | 🆓 OverTheWire *Bandit*, 🆓 Linux Journey | [linux-cli/](../cheatsheets/common/linux-cli/) · [bash_overview](../cheatsheets/common/linux-cli/bash/bash_overview.md) |
| 네트워킹 기초 | 🆓 Professor Messer Network+ (YouTube) | [iproute2](../cheatsheets/01-reconnaissance/iproute2.md) |
| Python/스크립팅 | 🆓 Automate the Boring Stuff | [scripts/](../cheatsheets/common/scripts/) |
| Kali/랩 세팅 | 🆓 Kali 공식 docs | [lab-setup/](../cheatsheets/common/lab-setup/) · [open_vpn](../cheatsheets/common/lab-setup/open_vpn.md) |

---

## 본문 모듈 매핑 (공식 신택스 순서)

### 1. Introduction to Cybersecurity
| | |
|---|---|
| 무료 자료 | 🆓 TryHackMe *Pre Security* 패스 · 🆓 HackTricks 개요 |
| 레포 | — (개념 모듈, 치트시트 없음) |
| 메모 | 가볍게 통과. 경험자면 스킵 가능 |

### 2. Report Writing for Penetration Testers
| | |
|---|---|
| 무료 자료 | 🆓 noraj OSCP 리포트 템플릿 · 🆓 OffSec 공개 샘플 리포트 |
| 레포 | — |
| 메모 | 일찍 시작. 랩 머신마다 짧게라도 리포트 작성 습관 → [04-resources](./04-resources.md) |

### 3. Information Gathering
| | |
|---|---|
| 무료 자료 | 🆓 HackTricks *Pentesting Methodology* · 🧪 TryHackMe *Nmap* 룸 |
| 레포 | [nmap](../cheatsheets/01-reconnaissance/network/nmap.md) · [rustscan](../cheatsheets/01-reconnaissance/network/rustscan.md) · [netdiscover](../cheatsheets/01-reconnaissance/network/netdiscover.md) · [dns](../cheatsheets/01-reconnaissance/osint-dns/dns.md) |
| 메모 | 커리큘럼 단계 1과 직결. enum 체크리스트 → [03-methodology](./03-methodology-checklist.md) |

### 4. Vulnerability Scanning
| | |
|---|---|
| 무료 자료 | 🆓 Nessus Essentials(무료판) · 🆓 OpenVAS(Greenbone GVM) 문서 |
| 시험 | 취약점 스캐너는 시험에서 사용 금지. 랩에서 원리만 이해 |
| 레포 | [searchsploit](../cheatsheets/02-vulnerability-analysis/cve/searchsploit.md) |
| 메모 | 시험은 자동 스캐너 제한 → 도구 이해만, 의존 금지 |

### 5. Introduction to Web Applications
| | |
|---|---|
| 무료 자료 | 🆓 PortSwigger *Web Security Academy* (무료, 최고 수준) · 🆓 MDN HTTP |
| 레포 | [web-surface/](../cheatsheets/01-reconnaissance/web-surface/) · [whatweb](../cheatsheets/01-reconnaissance/web-surface/whatweb.md) · [ffuf](../cheatsheets/01-reconnaissance/web-surface/ffuf.md) |

### 6. Common Web Application Attacks
| | |
|---|---|
| 무료 자료 | 🆓 PortSwigger Academy (파일인클루전·업로드·커맨드인젝션 랩) · 🆓 OWASP Top 10 |
| 레포 | [rfi](../cheatsheets/02-vulnerability-analysis/web/file-inclusion/rfi.md) · [file-upload](../cheatsheets/02-vulnerability-analysis/web/file-upload.md) · [ssrf](../cheatsheets/02-vulnerability-analysis/web/ssrf/ssrf.md) · [idor](../cheatsheets/02-vulnerability-analysis/web/idor.md) |

### 7. SQL Injection Attacks
| | |
|---|---|
| 무료 자료 | 🆓 PortSwigger *SQL injection* 랩(무료, 강력 추천) |
| 레포 | [sql_inject](../cheatsheets/02-vulnerability-analysis/web/sqli/sql_inject.md) · [blind_sql](../cheatsheets/02-vulnerability-analysis/web/sqli/blind_sql.md) · [sqlmap](../cheatsheets/02-vulnerability-analysis/web/sqli/sqlmap.md) |
| 메모 | sqlmap 없이 수동 추출까지 연습 (시험에서 sqlmap 사용 금지) |

### 8. Client-Side Attacks
| | |
|---|---|
| 무료 자료 | 🆓 HackTricks *Phishing / Office macro* · 🧪 TryHackMe 관련 룸 |
| 레포 | [msfvenom](../cheatsheets/03-initial-access/framework/msf/msfvenom/msfvenom.md) · [payload](../cheatsheets/03-initial-access/shells/payload.md) |

### 9. Locating Public Exploits
| | |
|---|---|
| 무료 자료 | 🆓 Exploit-DB · 🆓 searchsploit 문서 |
| 레포 | [searchsploit](../cheatsheets/02-vulnerability-analysis/cve/searchsploit.md) · [cve-2024-21413](../cheatsheets/02-vulnerability-analysis/cve/cve-2024-21413.md) |

### 10. Fixing Exploits
| | |
|---|---|
| 무료 자료 | 🆓 공개 PoC 수정 사례 글 · C/Python PoC 분석 블로그 |
| 레포 | [reverse_shell_cheatsheet](../cheatsheets/03-initial-access/shells/reverse-shell/reverse_shell_cheatsheet.md) |
| 메모 | 공개 익스플로잇의 IP/포트/오프셋 수정·컴파일 능력. 시험 빈출 함정 |

### 11. Antivirus Evasion
| | |
|---|---|
| 무료 자료 | 🆓 HackTricks *AV Bypass* 개요 (개념 수준) |
| 레포 | [msfvenom](../cheatsheets/03-initial-access/framework/msf/msfvenom/msfvenom.md) |
| 메모 | 시험 비중 낮음. 기본 개념만 |

### 12. Password Attacks
| | |
|---|---|
| 무료 자료 | 🆓 SecLists(GitHub) · 🧪 TryHackMe *Crack the hash* |
| 레포 | [hydra](../cheatsheets/03-initial-access/cracking/hydra/hydra.md) · [hashcat](../cheatsheets/03-initial-access/cracking/hashcat/hashcat.md) · [john_the_ripper](../cheatsheets/03-initial-access/cracking/john-the-ripper/john_the_ripper.md) · [wordlists](../cheatsheets/03-initial-access/cracking/wordlists.md) |

### 13. Windows Privilege Escalation
| | |
|---|---|
| 무료 자료 | 🆓 HackTricks *Windows Local Privesc* · 🆓 LOLBAS · 🧪 TryHackMe *Windows PrivEsc* |
| 레포 | [privileges/00-overview](../cheatsheets/04-privilege-escalation/windows/privileges/00-overview.md) · [SeImpersonatePrivilege](../cheatsheets/04-privilege-escalation/windows/privileges/02-SeImpersonatePrivilege.md) · [scenarios-tools](../cheatsheets/04-privilege-escalation/windows/privileges/04-scenarios-tools.md) |

### 14. Linux Privilege Escalation
| | |
|---|---|
| 무료 자료 | 🆓 HackTricks *Linux Privesc* · 🆓 GTFOBins · 🧪 TryHackMe *Linux PrivEsc* |
| 레포 | [privilege_escalation_overview](../cheatsheets/04-privilege-escalation/linux/privilege_escalation_overview.md) · [sudo_privesc](../cheatsheets/04-privilege-escalation/linux/sudo_privesc.md) · [suid](../cheatsheets/04-privilege-escalation/linux/suid.md) · [gtfobinaries](../cheatsheets/04-privilege-escalation/linux/gtfobins/gtfobinaries.md) |

### 15. Advanced Tunneling (포트 리다이렉션/피벗팅)
| | |
|---|---|
| 무료 자료 | 🆓 `ligolo-ng`/`chisel` 공식 위키 · 🆓 HackTricks *Tunneling and Port Forwarding* |
| 레포 | 없음 (`pivoting/proxy/`의 mitmproxy는 HTTP 프록시라 해당 없음) → 외부 자료로 학습 후 치트시트 신규 작성 |
| 메모 | 치트시트 공백 영역. [04-resources](./04-resources.md)의 Pivoting 섹션으로 보강 |

### 16. The Metasploit Framework
| | |
|---|---|
| 무료 자료 | 🆓 Metasploit Unleashed(OffSec 공개 무료 과정) · 🧪 TryHackMe *Metasploit* |
| 레포 | [msf](../cheatsheets/03-initial-access/framework/msf/msf.md) · [meterpreter](../cheatsheets/03-initial-access/framework/msf/meterpreter/meterpreter.md) |
| 메모 | 시험은 독립 머신 1대에만 MSF 허용. 의존하지 말 것 |

### 17. Active Directory: Introduction and Enumeration ⭐
| | |
|---|---|
| 무료 자료 | 💲 HTB Academy *AD Enumeration & Attacks* · 🆓 The Hacker Recipes *AD* · 🧪 TryHackMe AD 기초 룸 |
| 레포 | [bloodhound](../cheatsheets/01-reconnaissance/active-directory/bloodhound.md) · [enum4linux](../cheatsheets/01-reconnaissance/active-directory/enum4linux.md) · [crackmapexec](../cheatsheets/01-reconnaissance/active-directory/crackmapexe.md) · [rpcclient](../cheatsheets/01-reconnaissance/active-directory/rpcclient.md) |

### 18. Attacking Active Directory Authentication ⭐
| | |
|---|---|
| 무료 자료 | 🆓 The Hacker Recipes *Kerberos* · 🆓 HackTricks *AD Methodology* |
| 레포 | [kerbrute](../cheatsheets/01-reconnaissance/active-directory/kerbrute.md) · [impacket](../cheatsheets/01-reconnaissance/active-directory/impacket.md) · [hashcat](../cheatsheets/03-initial-access/cracking/hashcat/hashcat.md) |
| 메모 | AS-REP/Kerberoasting, PtH/PtT. 시험 당락 핵심 |

### 19. Lateral Movement in Active Directory ⭐
| | |
|---|---|
| 무료 자료 | 🆓 The Hacker Recipes *Movement* · 🆓 PayloadsAllTheThings *AD* |
| 레포 | [evil-winrm](../cheatsheets/04-privilege-escalation/windows/evil-winrm.md) · [impacket](../cheatsheets/01-reconnaissance/active-directory/impacket.md) · [smbmap](../cheatsheets/01-reconnaissance/active-directory/smb/smbmap.md) |
| 메모 | psexec/wmiexec/winrm, delegation, DCSync → [03-methodology](./03-methodology-checklist.md) D섹션 |

---

## 캡스톤 / 랩 (본문 모듈 이후)

| 단계 | 무료·저가 대체 연습 |
|------|---------------------|
| Assembling the Pieces(종합 walkthrough) | 🧪 PG Practice의 멀티스텝 머신 · HTB의 AD 포함 Medium 머신 |
| Challenge Labs (Medtech/Relia 등) | 🧪 결제 후에만. 대체로 PG Practice + HTB AD 네트워크 |

---

## 공부 순서 권장 (이 표 기준)

```text
선행 → 2(리포트 습관) → 3·4(정찰/스캔) → 5·6·7(웹) → 9·10(익스플로잇 다루기)
   → 12(패스워드) → 13·14(privesc, 양손) → 15(터널) → 16(MSF)
   → 17·18·19(AD, 가장 많은 시간) → 캡스톤/랩 → 모의시험
```

- 8·11(클라이언트·AV)은 시험 비중이 낮아 가볍게.
- ⭐ 표시(17~19 AD)에 전체 시간의 1/3 이상을 배분.
- PortSwigger Academy·HackTricks·The Hacker Recipes·TryHackMe는 전부 합법 공개 자료이고, PEN-200 웹/AD 파트를 결제 전에 거의 그대로 선행할 수 있다.

---

## 출처 (모듈 목록)
- OffSec PEN-200 공식 신택스 (2026-03판, `manage.offsec.com`의 `PEN-200_Syllabus.pdf`)
- OffSec PEN-200 코스 페이지 / Offline Video Mapping (help.offsec.com)
