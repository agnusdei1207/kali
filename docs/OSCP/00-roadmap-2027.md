# 00. 로드맵 — 2027 상반기 OSCP+ 취득

> 직장 병행 기준(주당 투입 적음, 꾸준함 유지). 날짜는 2026-10-16 기준으로 환산.\n> 현재 계획은 무료 자료 우선이다. 나중에 OffSec 강의/시험을 결제하더라도 이 문서의 구조는 그대로 쓸 수 있다. 결제는 강제하지 않는다.

---

## 1. 학습 경로의 현재 계획

- 기본 경로: Kali + 공개 무료 자료(OverTheWire, TryHackMe 무료 룸, VulnHub, OffSec Metasploit Unleashed, PortSwigger Academy, HackTricks, The Hacker Recipes, SecLists, GTFOBins/LOLBAS 등)로 실력을 쌓는다.
- 유료 경로(나중에 검토 가능): OffSec PEN-200/Challenge Labs, PG Practice, HTB, OSCP 시험 응시권. 결제는 사용자의 판단에 맡기며, 이 문서는 무료 우선 시점을 가정한다.
- 두 경로는 같은 커리큘럼 구조(01-curriculum)를 따르므로, 어느 쪽을 선택하든 이후 문서의 대부분은 그대로 사용할 수 있다.
- OSCP 자격증 취득을 최종 목표로 하지 않을 수도 있다. 이 경우 학습 기록과 모의 시나리오 완료를 역량 증적으로 대체한다.

---

## 2. 월별 계획 (2026-10 ~ 2027-06, 직장 병행)

```text
2026-10 ~ 11   [자가 준비 / 결제 전]
               · OTW Bandit/Leviathan, Professor Messer Network+ 기초
               · TryHackMe 무료 룸, VulnHub 무료 머신 15~20대
               · AD 기초 (The Hacker Recipes, HackTricks 무료 자료)
               · 01-curriculum 단계 0~4

2026-11 ~ 12   [랩 집중]
               · 무료 머신 누적 30~40대, 한 머신 1~2주
               · 01-curriculum 단계 5 (AD), 단계 6 (리포트)
               · 02-platform-plan 페이스 준수 (주말 3~4h 몰입)

2027-01 ~ 02   [모의 시나리오]
               · 약한 단계 재복습 + 모의 침투 시나리오 + 리포트 작성 연습
               · 03-methodology-checklist, 06-pen200-module-map 기준 반복

2027-03 ~ 06   [유료 경로 검토 / 시험 대비]
               · OffSec 강의·시험을 결제한다면 이 시기 검토
               · 결제 전: PG Practice/HTB 중급 머신 힌트 없이 절반 이상 풀 수 있는지 확인
               · 아니면 무료 경로로 계속 반복 학습
```

---

## 3. 주간 루틴 (직장 병행)

```
주중 (하루 1~1.5h)   노트 정리 · 기법 복습 · 짧은 enumeration (머신 정찰까지만)
주말 (3~4h 몰입 x2)  머신 1~2대 끝까지 공략 — 몰입 블록이 실력을 만든다
```

- 평일엔 "끝내지 못할 머신"을 시작하지 말고, 정찰·분석까지만. 공략은 주말 블록에.
- 2주에 한 번은 [05-progress-tracker.md](./05-progress-tracker.md)를 열어 반복되는 약점 1개를 그 주의 집중 주제로 삼는다.
- 위 루틴은 주 11~15시간 기준이다. 실제 가능 시간이 더 적으면 머신 목표 수를 비례해 줄이거나 일정을 늦춘다.

---

## 4. 참고

- 외부 자료 링크는 접속 시점 기준으로 재확인한다.
- 유료 상품 가격·기한은 자주 바뀌므로, 결제 전 OffSec 공식 페이지에서 반드시 재확인한다.
- 모든 학습·공격 활동은 본인 소유 또는 허가받은 시스템에서만 수행한다.
