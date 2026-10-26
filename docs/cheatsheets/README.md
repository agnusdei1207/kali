# 📚 치트시트 인덱스

침투 테스트 단계별 명령·도구·기법 모음입니다.

> 관련 문서: [루트 README](../../README.md) · [롸잇업 인덱스](../write-ups/red/README.md) · [OSCP 학습 경로](../OSCP/README.md) · [AGENTS.md](../../AGENTS.md)

---

| 단계 | 폴더 | 다루는 내용 |
|:---:|---|---|
| 01 | [정찰 (`01-reconnaissance/`)](./01-reconnaissance) | 네트워크 스캔, 웹 표면 조사, OSINT·DNS, Active Directory 열거 |
| 02 | [취약점 분석 (`02-vulnerability-analysis/`)](./02-vulnerability-analysis) | 웹 취약점, 서비스별 취약점, CVE 분석 |
| 03 | [초기 침투 (`03-initial-access/`)](./03-initial-access) | 쉘 획득, 웹쉘, SQL 인젝션, 크래킹, 프레임워크 |
| 04 | [권한 상승 (`04-privilege-escalation/`)](./04-privilege-escalation) | Linux / Windows 권한 상승 |
| 05 | [측면 이동 (`05-lateral-movement/`)](./05-lateral-movement) | 피벗팅, 터널링 |
| 06 | [후속 공격 (`06-post-exploitation/`)](./06-post-exploitation) | 포렌식, 흔적 분석 |
| 공통 | [공통 도구·형식 (`common/`)](./common/README.md) | 암호화, Linux CLI, Bash, 스크립트, 랩 구성, 마크업, Windows |

---

## 사용법

- 실습 중 막힐 때 해당 단계 폴더에서 명령을 찾습니다.
- 실제 적용 사례는 [롸잇업 인덱스](../write-ups/red/README.md)에서 확인합니다.
- 치트시트를 추가하면 이 표의 해당 폴더에 파일을 넣고, 필요한 경우 `common/README.md`도 갱신합니다.
