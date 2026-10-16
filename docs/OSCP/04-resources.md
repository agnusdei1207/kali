# 04. 외부 자료 모음

> 공개된 학습 자료·리스트·템플릿 링크. URL은 바뀔 수 있으니 접속 시 재확인.
> OffSec 비공개 교재·랩·시험 내용은 포함하지 않는다.

---

## 공식 (결제·정책은 항상 공식 우선)

- PEN-200 코스: https://www.offsec.com/courses/pen-200/
- Learn One: https://www.offsec.com/products/learn-one/
- OSCP+ Exam Guide (시험 규칙·허용 도구·리포트 요건): OffSec help center "OSCP Exam Guide"
- Course & Cert Bundle FAQ / Certification Exam FAQ: help.offsec.com

> 시험 규칙(Metasploit 1대 제한, 금지 도구, 리포트 형식)은 응시 전 Exam Guide 최신본을 반드시 정독.

---

## 연습 머신 리스트

- TJnull OSCP Prep 리스트 (NetSecFocus) — HTB/PG/VulnHub 중 OSCP 유사 머신 선별. "NetSecFocus Trophy Room"으로 검색.
- LainKusanagi OSCP-like 리스트 — 최신 성향 반영된 대안 리스트.
- PG Practice (OffSec) — 출제사 제작, 시험과 가장 유사.
- HTB — Retired 머신 위주(VIP). AD 포함 머신 비중 ↑.
- VulnHub — 무료, 오프라인 추가 연습.

---

## AD 보강 (치트시트 얇은 영역 → 집중 보강)

- HTB Academy: "Active Directory Enumeration & Attacks" 등 AD 모듈.
- 참고 사이트(공개 노트):
  - The Hacker Recipes — AD 공격 기법 백과.
  - HackTricks — enum/privesc/AD 폭넓은 공개 노트.
  - PayloadsAllTheThings — 기법별 페이로드/명령 모음.
- 도구: `BloodHound`, `impacket` 스위트, `crackmapexec`/`netexec`, `evil-winrm`, `kerbrute`.

---

## 권한 상승 레퍼런스

- GTFOBins (Linux) — SUID/sudo 악용 바이너리.
- LOLBAS (Windows) — 합법 바이너리 악용.
- PEASS-ng — `linpeas` / `winpeas` 자동 열거.
- HackTricks의 Linux/Windows Local Privilege Escalation 페이지.

---

## Pivoting / 터널링 (치트시트 없음 → 외부로 보강)

- `ligolo-ng` (권장) — 공식 리드미/위키.
- `chisel` — 공식 리드미.
- SSH 로컬/리모트/다이내믹 포트포워딩, `proxychains` 설정.

---

## 리포트

- noraj OSCP Exam Report Template (Markdown/LaTeX) — 커뮤니티 표준.
- OffSec 제공 공식 리포트 템플릿 (학생 포털).
- 랩/모의시험마다 짧게라도 리포트를 써서 작성 속도를 올려 둘 것.

---

## 커뮤니티

- r/oscp (Reddit) — 후기·시험 팁(규칙 내에서).
- NetSecFocus Discord / Mattermost.
- InfoSec Prep, TJnull 관련 커뮤니티.

---

## 이 레포 내부 연결

- 도구 사용법 전체: [../cheatsheets/](../cheatsheets/)
- 공통 레퍼런스(인코딩 등): [../cheatsheets/common/](../cheatsheets/common/)
- 라이트업: [../write-ups/](../write-ups/)

> 주의: 외부 walkthrough는 "막힌 뒤 배우기"에만. 처음부터 보면 시험 실력이 늘지 않는다 ([02-platform-plan.md](./02-platform-plan.md)).
