# Metasploit 인덱스

Metasploit Framework 문서 폴더. 콘솔(msf) → DB → 페이로드 → 실행 → meterpreter 순서가 기본 흐름이다.

## 루트 파일

- `install.md` 프레임워크 설치·초기화
- `msf.md` msfconsole 콘솔 기본 (search·use·show·set·run)
- `msfdb.md` msfdb 데이터베이스 초기화·초기 설정
- `msf_usage.md` 프레임워크 전반 사용법
- `msf_payload.md` 페이로드 선택·옵션 정리
- `msfvenom.md` msfvenom 페이로드 생성 (exe·elf·php 등 형식, 인코딩)
- `listen.md` 리스너 (multi/handler) 설정
- `scanner_vnc.md` VNC 인증 스캐너 모듈 사용

## exploit/

- `eternalblue.md` MS17-010 EternalBlue 익스플로잇 실습 (Windows SMB)

## meterpreter/

- `meterpreter.md` meterpreter 세션 기본
- `command.md` meterpreter 명령 모음 (getuid·hashdump·upload 등)
- `portwd.md` 포트 포워딩 (portfwd)

## 흐름 정리

```text
1. msfdb init -> 데이터베이스 켜기 (스캔 결과 저장)
2. msfconsole -> search로 모듈 탐색 -> use로 선택
3. msfvenom   -> 스탠드얼론 페이로드 필요할 때만 생성
4. multi/handler -> 리스너 대기 (listen.md)
5. 세션 확보 -> meterpreter 명령으로 후속 작업
```
