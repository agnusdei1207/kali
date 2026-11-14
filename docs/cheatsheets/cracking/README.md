# Cracking 인덱스

패스워드 크래킹·워드리스트 문서 폴더. 도구별 상세는 하위 폴더 README를 따른다.

## 하위 폴더

- `archive/` 압축 파일 해시 추출
- `hashcat/` hashcat 전체 구조 — `hashcat/README.md`가 다시 인덱스를 제공한다
- `hydra/` hydra
- `john/` John the Ripper

## archive/

- `rar2john.md` RAR 파일에서 john용 해시 추출
- `zip2john.md` ZIP 파일에서 john용 해시 추출

## hydra/

- `hydra.md` 로그인 폼·SSH·FTP 등 프로토콜 브루트포스 기본 사용법
- `hydra_structured.md` 단계 구조로 정리한 hydra 실전 절차
- `hydra_practice.md` 실습 기록

## john/ — John the Ripper

- `john_the_ripper.md` 기본 사용법과 포맷 지정
- `custom_mangling_rules.md` 커스텀 마들링 규칙
- `custom_rules.md` 규칙 작성·적용
- `john_the_ripper_ssh.md` SSH 개인키(id_rsa) 패스프레이즈 크래킹
- `single_crack_mode.md` 싱글 크랙 모드
- `unshadow.md` /etc/passwd + /etc/shadow 병합

## hashcat/ — 상세는 hashcat/README.md

- attacks/ 공격 방식(마스크·조합·하이브리드·룰 기반·직접 대입)
- hashes/ 해시 형식별 모드 문서(NTLM·NetNTLM·Linux crypt·SSH 키·문서·디스크 암호화 등)
- common/ 세션·potfile·솔트·워드리스트 준비
- indexes/ 모드 번호·시나리오 인덱스
- theory/ 원리, gpu_setup·installation·options·usage·precautions

## 루트 파일

- `crunch.md` 패턴 기반 워드리스트 생성기
- `rockyou.md` rockyou 워드리스트 위치·사용법
- `seclists.md` SecLists 워드리스트 모음
- `wordlists.md` 워드리스트 정리
