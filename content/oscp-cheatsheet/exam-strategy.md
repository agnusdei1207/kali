---
title: "OSCP 시험 전략 (Exam Strategy)"
date: 2026-06-20
weight: 200
draft: false
tags: ["oscp", "cheatsheet"]
summary: "시험 당일 시간 배분, 도구 제한, 막혔을 때 대응, 디스트랙터 판별."
---

시험 당일 시간 배분, 도구 제한, 막혔을 때 대응, 디스트랙터 판별을 정리한 치트시트.

- 출처: https://heretek.dev/oscp-cheatsheet/exam-strategy/ (Jean Romero) — 재구성

## 시험 구성 (2025/2026)

- AD Set: 40점 — 머신 3대, assumed breach (도메인 creds 제공)
- Standalone 1: 20점 — 독립 (initial 10 + root/admin 10)
- Standalone 2: 20점 — 독립 (initial 10 + root/admin 10)
- Standalone 3: 20점 — 독립 (initial 10 + root/admin 10)
- 합계 100점, 70점 통과

2024년 11월부터: 보너스 점수는 폐지. AD 세트는 부분 점수 있음 (워크스테이션당 10점, DC 20점).

### 통과 조합

- AD full(40) + standalone full(20) + standalone initial(10) = 70 → 통과
- AD partial(30) + standalone full(40) x 2 = 70 → 통과
- AD full(40) + standalone full(40) x 2 = 80 → 여유

## 시간 배분 — 23시간 45분 (Time Management)

- 0–1시간: 전 머신 스캔. 스캔 병렬로 돌려두고 결과 읽기. 공격 계획 수립.
- 1–5시간: AD 세트 — 최우선. 40점.
- 5–9시간: standalone 1 — 정찰 결과 기준 가장 쉬운 것부터.
- 9–13시간: standalone 2.
- 13–16시간: standalone 3 또는 막힌 머신 재도전.
- 16–20시간: 미완료 전부 재공격. 새로운 시선으로.
- 20–24시간: 스크린샷 정리, 플래그 검증, 리포트 노트 시작.

## 시험 당일 규칙 (Rules to Live By)

1. 45분 막히면 → 피벗. 다른 머신으로 이동하고 새 시선으로 복귀.
2. 스크린샷 전부 찍기. 모든 쉘, 모든 명령, 모든 플래그. 증거가 필요하다 ← 중요
3. 휴식. 산책, 식사, 수분. 10분 휴식이 2시간의 터널비전을 막는다.
4. AD 먼저. 40점이고, 진입점을 찾으면 체인은 보통 논리적이다.
5. 커널 익스플로잇에 빠지지 않기. 의도된 경로가 아닌 경우가 많다.
6. 발견한 모든 creds → 즉시 전체 스프레이.

## 도구 제한 — 암기 필수 (Tool Restrictions)

### 금지 — 즉시 탈락 (BANNED)

- SQLmap, SQLninja, db_autopwn, browser_autopwn — 자동 SQLi 없음
- Nessus, OpenVAS, Nexpose — 취약점 스캐너 없음
- Metasploit Pro, Cobalt Strike, Core Impact, Burp Pro — 상용 도구 없음
- 모든 AI/LLM — ChatGPT, Claude, Copilot, DeepSeek, OffSec의 KAI까지 전부
- 스푸핑/포이즈닝 — ARP, DNS, NBNS, LLMNR, mDNS 전부 금지
  - Responder 포이즈닝 = 금지. Responder `-A` (analyze/passive) = 허용

### 제한 — Metasploit (RESTRICTED)

- exploit/auxiliary/post 모듈 + Meterpreter는 딱 1대에서만. 신중하게 선택 ← 중요
- `msfvenom`, `multi/handler`, `pattern_create/offset` → 전 타깃 무제한
- `check` 명령도 다른 타깃에서는 사용 불가
- 한 타깃에 모듈을 한 번 쓰면, 그것이 그 타깃의 1회 몫이다.

### 허용 (ALLOWED)

- Nmap + NSE 스크립트, Nikto, Burp Community, Gobuster, Feroxbuster
- BloodHound, Mimikatz, Impacket 스위트, NetExec, Rubeus, evil-winrm, PowerView
- LinPEAS/WinPEAS, pspy, Ligolo-ng, Chisel, GodPotato, PrintSpoofer
- 임의 언어로 작성한 커스텀 스크립트
- 오픈북: 개인 노트, 인터넷, OffSec 포털

## 막혔을 때 (일반) — 순서대로

1. 스캔 출력 다시 읽기. 놓친 포트? 버전? 호스트명?
2. 다른 워드리스트, 더 많은 확장자로 디렉터리 브루트포스 재실행
3. 페이지 소스 재확인 — 주석, hidden 필드, JS 파일
4. 찾은 모든 서비스에 기본 creds 시도
5. 찾은 creds로 재열거 — 서비스 간 패스워드 재사용
6. UDP 포트 확인 — SNMP(161)에 중요 데이터가 숨어 있다
7. 서비스 + 버전 검색 — 익스플로잇, 기본 creds, 알려진 이슈
8. 발견한 것끼리 체인 — 한 정보가 다른 정보의 열쇠가 될 수 있다
9. 10분 휴식. 자리를 떠난다. 진짜로.

## proof 스크린샷 요건 (Proof / Screenshot Requirements)

```bash
# Linux — 네 가지 전부 ONE 터미널 스크린샷에
whoami && hostname && ip a && cat /root/proof.txt

# Windows — 네 가지 전부 ONE 터미널 스크린샷에
whoami && hostname && ipconfig && type C:\Users\Administrator\Desktop\proof.txt
```

스크린샷 한 화면에 플래그 내용 + `whoami` + `hostname` + `ip a`/`ipconfig` 가 같은 창에 전부 보여야 한다 ← 중요

## 시험 전 셋업 체크리스트 (Pre-Exam Setup Checklist)

- [ ] VPN 연결 및 테스트 완료
- [ ] Kali 업데이트, 모든 도구 동작 확인
- [ ] 이 치트시트를 연 Obsidian
- [ ] 스크린샷 도구 준비 (Flameshot)
- [ ] 리버스 쉘 원라이너 저장 완료
- [ ] HTTP 서버 준비: `python3 -m http.server 80`
- [ ] 워드리스트: rockyou.txt, SecLists 설치
- [ ] LinPEAS, WinPEAS, pspy64, PowerUp, GodPotato, PrintSpoofer, nc.exe 다운로드
- [ ] Ligolo-ng 프록시 + 에이전트(Linux/Windows) 준비
- [ ] 터미널 로깅: `script -a exam_log.txt`
- [ ] 책상 위 음식과 물
- [ ] 전날 밤 충분한 수면
- [ ] 기억: SQLmap = 금지, AI/LLM = 금지, Metasploit = 1개 타깃 ← 중요

## 리포트 리마인더 (Report Reminder)

- 시험 종료 후 24시간 안에 리포트 제출 ← 중요
- 공식 OSCP 리포트 템플릿 사용
- 모든 단계를 스크린샷으로 문서화
- 실패한 시도도 포함 — 방법론을 보여준다
- 리포트 없음 = 통과 없음. 100점이라도 ← 중요

## 디스트랙터 판별 (Distractor Recognition)

시험의 일부 해시, creds, 서비스는 의도된 래빗홀이다. 빠르게 판별해서 시간을 태우지 않는다.

### 래빗홀 신호 (Rabbit Hole Signals)

1. 크랙 불가능한 해시

- rockyou + rules로 30분 이상 돌려도 아무것도 안 나오는 Kerberoast 해시
- 기이하게 복잡한 패스워드 패턴의 AS-REP 해시
- 웹 앱의 Bcrypt/Argon2
- 대응: 넘어간다. 의도된 것이었다면 10분 안에 크랙되게 만들었을 것이다.

Kerberoast 해시가 rockyou+rules에 30분 이상 저항하면 중단하고 AS-REP 로스팅으로 전환 — 일부는 다른 기법으로 방향을 돌리려는 의도의 크랙 불가능 해시다.

2. 어디서도 인증되지 않는 creds

- 스크립트/설정 파일에 유저명이 있는데 AD에 그 유저가 없음 (nxc LDAP 질의 빈 결과, BloodHound에 노드 없음)
- 진짜처럼 보이는 creds 파일인데 모든 타깃이 거부
- 유저명 변형(john.miller, jmiller, j.m)이 어디서도 인증 실패

3. 악용 가능해 보이지만 노이즈용인 서비스/포트

- 실제 경로가 없는 IP의 기본 웹 페이지
- 열거해도 끝이 없는 제네릭 배너 서비스

### 시간 예산 규칙 (Time Budget Rules)

- 해시 크랙 시도 하나에 최대 30분
- creds 스프레이 한 번에 최대 15분, 그다음엔 이동
- 한 박스에서 2시간 동안 새 정보가 없으면 → 열거를 처음부터 다시
- 4시간 이상 막혀 있으면 → 그 머신은 되돌려서 재시작

### 시간 낭비 전 검증 (Validation Before Burning Hours)

공격 경로에 들어가기 전에 확인:

- 이 유저가 AD에 존재하는가? (nxc ldap + BloodHound)
- 이 해시가 rockyou로 보통 크랙되는 타입인가?
- 이 서비스가 익스플로잇 사전 조건에 실제로 응답하는가?

하나라도 "아니오" 또는 "모름"이면, 5분의 검증이 3시간의 래빗홀을 막는다.

### 시험 적용 (Exam Application)

OSCP 시험은 공격적인 익스플로잇보다 체계적인 열거를 보상한다. creds나 해시가 이상해 보이면 실제로 이상한 경우가 많다. 넘어가고, 맥락이 더 생기면 다시 돌아온다.

## 빠른 참조 링크 (같은 폴더 문서)

- 전체 흐름 체크리스트 → [methodology.md](methodology.md)
- 리포트 작성 → [report-writing.md](report-writing.md)
