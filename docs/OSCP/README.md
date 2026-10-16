# OSCP 학습 허브 (2027 취득 목표)

> OffSec PEN-200 / OSCP+ 취득을 위한 학습 자료 모음.
> 공개된 시험 정보와 일반적인 침투 테스트 방법론만을 다룬다. 시험 문제·랩 내용 등
> OffSec 비공개 자료는 포함하지 않는다.

이 폴더는 이 레포의 `docs/cheatsheets/` 치트시트와 연결되는 학습 로드맵·커리큘럼이다.
치트시트가 "도구 사용법"이라면, 이 폴더는 "무엇을 어떤 순서로 공부하고 연습할지"를 담는다.

---

## 읽는 순서

| # | 문서 | 내용 |
|---|------|------|
| 0 | [00-roadmap-2027.md](./00-roadmap-2027.md) | 결제 시점·시험 기한, 2027 상반기까지 월별 타임라인 |
| 1 | [01-curriculum.md](./01-curriculum.md) | 주제별 학습 커리큘럼 (단계별, 치트시트 링크 포함) |
| 2 | [02-platform-plan.md](./02-platform-plan.md) | PG Practice / HTB / THM 플랫폼 활용 전략 |
| 3 | [03-methodology-checklist.md](./03-methodology-checklist.md) | 시험장에서 그대로 따라가는 방법론 체크리스트 |
| 4 | [04-resources.md](./04-resources.md) | 리스트·치트시트·리포트 템플릿 등 외부 자료 |
| 5 | [05-progress-tracker.md](./05-progress-tracker.md) | 머신 풀이 기록 / 약점 추적 표 |
| 6 | [06-pen200-module-map.md](./06-pen200-module-map.md) | PEN-200 공식 모듈 ↔ 무료 공개 자료 매핑 (결제 전 선행 학습용) |

---

## OSCP+ 시험 핵심 사실 (2026-10 기준, 결제 전 공식 페이지 재확인 필수)

- 형식: 23시간 45분 proctored 실기 + 이후 24시간 내 리포트 제출
- 구성: 독립(standalone) 머신 3대 (각 initial access + privesc) + AD 세트 3대 (assumed breach)
- 배점: 독립 머신 60점(각 20점) + AD 세트 40점(10/10/20) = 100점
- 합격선: 2026-11-30까지는 고정 70점. 단 2026-12-01부터 scaled scoring(환산 채점)으로 바뀌므로, 2027년 응시자는 공식 Exam Guide에서 합격 기준을 반드시 다시 확인할 것
- AD 세트는 체인 구조(앞 머신을 뚫어야 다음으로 진행)지만 단계별 부분 점수(10/10/20)가 있다 → 끝까지 연결할수록 유리하고, 40점이 걸려 있어 최우선 투자 영역
- 랩/연습문제 보너스 점수 폐지 → 모듈 연습문제를 전부 풀 필요 없음
- Metasploit은 시험 머신 중 1대에만 사용 가능(한 번 고르면 실패해도 대상 변경 불가, msfvenom·multi/handler는 예외). sqlmap 같은 자동 익스플로잇 도구와 취약점 스캐너(Nessus·OpenVAS)는 금지. 단 nmap·nikto·Burp 무료판 등 자동 '열거' 도구는 허용
- 시험 중 AI 챗봇 사용 금지 → 평소에 AI 없이 수동으로 푸는 연습을 해 둘 것

> 자세한 기간·기한·비용은 [00-roadmap-2027.md](./00-roadmap-2027.md) 참고.

---

## 이 자료 사용 원칙

1. 풀이(walkthrough)에 기대지 않는다. 처음에는 따라가도 되지만, 익숙해지면 혼자 힘으로 풀어야 실력이 는다. 스스로 정찰하고, 가설을 세우고, 공격해 보는 과정을 반복하자.
2. 막히면 30~60분쯤 혼자 버틴 뒤에 힌트를 본다. 대신 무엇을 왜 놓쳤는지는 반드시 노트에 적어 둔다 ([05-progress-tracker.md](./05-progress-tracker.md)).
3. 자기만의 방법론을 글로 정리해 둔다. 시험장에서 머리가 하얘질 때 [03-methodology-checklist.md](./03-methodology-checklist.md)를 그대로 따라가는 것이 가장 든든하다.
4. AD와 Windows 권한 상승에 시간을 더 쓴다. 개발·인프라 경험이 있으면 웹과 리눅스는 금방 익숙해지지만, AD는 병목이 되기 쉽기 때문이다.
