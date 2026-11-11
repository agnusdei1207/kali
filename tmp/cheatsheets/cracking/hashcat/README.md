# Hashcat 치트시트

## 폴더 구조

- `attacks/` 공격 모드, 마스크, 후보 생성 (straight, combination, brute-force, hybrid, rule-based)
- `hashes/` 해시 유형별 (-m 모드별 명령, 엣지 케이스)
- `common/` 공통 (벤치마크, 세션/potfile, 배치, 워드리스트 준비, 해시 식별, salt 처리)
- `indexes/` 인덱스 (모드 번호, 시나리오, 공격 모드, 대상)
- `theory/` 작동 원리

## 빠른 검색

- 모드 번호로: `indexes/hashcat_modes_index.md` 또는 `grep -rl "m 5600" .`
- 시나리오로: `indexes/index_by_scenario.md`
- 공격 모드로: `indexes/index_by_attack.md`
- 대상으로: `indexes/index_by_target.md`
- 해시 유형으로: `hashes/hash_<유형>.md`
- 공격 모드로: `attacks/attack_<모드>.md`

## 주요 파일 (루트)

- `hashcat.md` 기본 문법, 공격 모드, 옵션, 예시, 파일 검색 방법
- `installation.md` 설치
- `options.md` 옵션 레퍼런스
- `gpu_setup.md` GPU 설정
- `mangling_rules.md` 규칙 문법
- `precautions.md` 주의사항
- `usage.md` 사용법 모음
- `archive_cracking.md` 압축 파일 크래킹