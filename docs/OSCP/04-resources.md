# 04. 외부 자료 모음 (현재는 무료 자료 위주)

> 공개된 학습 자료·리스트·템플릿 링크. URL은 바뀔 수 있으니 접속 시 재확인.\n> OffSec 비공개 교재·랩·시험 내용은 포함하지 않는다.\n> 유료 자료는 현재 사용하지 않는다. 무료 자료를 먼저 활용한다.

---

## 1. 무료 강의·방송 (공식 및 공개)

- OverTheWire *Bandit* (bash) — https://overthewire.org/wargames/bandit/
- OverTheWire *Leviathan* (Windows) — https://overthewire.org/wargames/leviathan/
- Professor Messer (Network+/Security+) — YouTube. "Professor Messer's Security+ / Network+" 채널 검색
- PortSwigger *Web Security Academy* (무료, 최고 수준) — https://portswigger.net/web-security
- OWASP Top 10 / OWASP Testing Guide — https://owasp.org/www-project-top-ten/ (개념 참고)
- TryHackMe 무료 룸 — https://tryhackme.com (무료 계정으로 이용)

---

## 2. OffSec 공개 자료

- Metasploit Unleashed — https://www.offsec.com/courses/metasploit-unleashed/ (무료)
- PEN-200 Syllabus (PDF, 공개) — https://www.offsec.com/courses/pen-200/ (교재 구성을 무료로 미리 확인할 때만)
- OSCP / OSCP+ Exam Guide — OffSec help center의 "OSCP Exam Guide". 시험 규칙(허용 도구, Metasploit 1대 제한, 리포트 요건)을 공개적으로 확인할 때만 사용한다. (유료 시험을 준비할 때 필요)

---

## 3. 공개 GitHub 저장소 (도구 사용법)

- SecLists — https://github.com/danielmiessler/SecLists (wordlist)
- Exploit-DB — https://github.com/offsec/Exploit-DB (searchsploit)
- GTFOBins — https://github.com/danielmiessler/GTFOBins (Linux privesc)
- LOLBAS — https://github.com/ohdizahi/LOLBAS (Windows privesc)
- PayloadsAllTheThings — https://github.com/swisskyrepo/PayloadsAllTheThings (셸 페이로드 모음)
- BloodHound / impacket / crackmapexec — https://github.com/BloodHoundAD/BloodHound (각 GitHub 페이지)
- PEASS-ng — https://github.com/carlospolop/PEASS-ng (linpeas/winpeas)

---

## 4. AD 보강 (치트시트가 얇은 영역 → 무료 자료로 집중)

- The Hacker Recipes — https://www.thehackerrecipes.com/ (AD 공격 기법 백과. 무료)
- HackTricks — https://book.hacktricks.xyz/ (enum/privesc/AD 폭넓은 공개 노트. 무료)
- PayloadsAllTheThings — https://github.com/swisskyrepo/PayloadsAllTheThings (AD 관련 페이로드/명령 모음)
- BloodHound / impacket 스위트 — GitHub에서 `bloodhound`과 `impacket` 패키지를 설치해 사용

---

## 5. 권한 상승 레퍼런스

- GTFOBins (Linux) — https://gtfobins.github.io/gtfobins/
- LOLBAS (Windows) — https://lolbas-project.github.io/LOLBAS/
- HackTricks의 Local Privilege Escalation 페이지 — https://book.hacktricks.xyz/linux-hardening/privesc
- Automating: `linpeas`(Linux), `winpeas`(Windows) — Kali에 기본 설치됨

---

## 6. Pivoting / 터널링 (치트시트 없음 → 무료로 보강)

- ligolo-ng — https://github.com/arl4g44/ligolo-ng (공식 위키)
- chisel — https://github.com/erebe/klona (공식 문서)
- SSH 로컬/리모트/다이내믹 포트포워딩, `proxychains` 설정 — 각종 보안 블로그의 "SSH tunneling" 문서

---

## 7. 리포트

- noraj OSCP Exam Report Template (Markdown/LaTeX) — https://github.com/noraj/OffSec-Security-Tools (커뮤니티 표준)
- OffSec 공식 리포트 템플릿 — 학생 포털의 "Report" 문서. (유료 시험을 준비할 때 필요)

---

## 8. 커뮤니티

- r/oscp (Reddit) — https://www.reddit.com/r/oscp/ (후기·시험 팁, 공개)
- NetSecFocus Discord / Mattermost — 검색: "NetSecFocus" (링크는 공개되어 있지 않음)
- InfoSec Prep, TJnull 관련 커뮤니티 — Discord/Slack 링크는 각 커뮤니티 페이지에서 확인

---

## 9. 이 레포 내부 연결

- 도구 사용법 전체: [../cheatsheets/](../cheatsheets/)
- 공통 레퍼런스(인코딩 등): [../cheatsheets/common/](../cheatsheets/common/)
- OSCP 학습 경로: [00-roadmap-2027.md](./00-roadmap-2027.md) · [01-curriculum.md](./01-curriculum.md) · [02-platform-plan.md](./02-platform-plan.md) · [03-methodology-checklist.md](./03-methodology-checklist.md) · [04-resources.md](./04-resources.md) · [05-progress-tracker.md](./05-progress-tracker.md) · [06-pen200-module-map.md](./06-pen200-module-map.md)

> 외부 자료는 "막힌 뒤 배우기"에만 사용한다. 처음부터 보면 시험 실력이 늘지 않는다 ([02-platform-plan.md](./02-platform-plan.md)).
