# Endianness (리틀 엔디언 / 빅 엔디언)

멀티바이트 데이터를 메모리에 저장할 때 바이트 순서를 정하는 방식.

## 기본 개념

```
값: 0x12345678 (4바이트)

Little Endian:  78 56 34 12  (낮은 바이트부터)
Big Endian:     12 34 56 78  (높은 바이트부터)
```

## 어디에 사용되는가

### Little Endian (LE)
- x86/x64 CPU (Intel, AMD) — PC, 서버 대부분
- Windows 운영체제
- PowerShell 문자열 인코딩 (UTF-16LE)
- x86 바이너리/PE 파일 형식

### Big Endian (BE)
- 네트워크 프로토콜 — TCP/IP 패킷 헤더 (RFC 표준)
- ARM/MIPS/PDP 일부 (설정 가능)
- JPEG, PNG 같은 이미지 포맷 헤더
- Java .class 파일 (JVM 표준)
- 모토로라 68k 구형 CPU

## 왜 두 가지가 존재하는가

역사적 이유:
- Intel 8086 (1978) → Little Endian 채택
- Motorola 68000 → Big Endian 채택
- 각 진영이 서로 다른 방식으로 발전 → 호환성 문제 발생

네트워크 바이트 순서 = Big Endian (RFC 1700 표준)
→ 모든 시스템이 네트워크 통신 시 BE로 변환 후 전송 (htonl/ntohl)

## 이 개념이 어디에 쓰이는가

| 분야 | 용도 |
|------|------|
| CPU 아키텍처 | 메모리 접근 순서 결정 |
| 네트워크 | 패킷 바이트 순서 (BE 표준) |
| 파일 포맷 | 헤더 파싱 시 순서 확인 필수 |
| 역공학/익스플로잇 | 셸코드 작성 시 바이트 순서 맞춰야 함 |
| PowerShell -EncodedCommand | UTF-16LE 입력 요구 |
| 크로스 플랫폼 | ARM/x86 간 데이터 교환 시 변환 필요 |

## 실무에서의 함정

- 이기종 시스템 간 통신: LE ↔ BE 변환 안 하면 값이 깨짐
- 파일 포맷 파싱: BMP는 LE, PNG는 BE → 혼동 주의
- exploit 개발: 셸코드 주소를 LE로 변환해야 실제 메모리에 맞음
- 디버깅: hex dump 볼 때 바이트 순서 헷갈리기 쉬움

## 한 줄 요약

엔디언은 "멀티바이트 숫자를 메모리에 어떤 순서로 놓을지"의 약속.
CPU/OS/네트워크/파일포맷마다 다른 약속을 쓰므로, 데이터 교환 시 반드시 변환 필요.

## 참고: SmarterMail RCE (CVE-2019-7214)와의 연관

test.py에서 PowerShell 명령을 UTF-16LE로 인코딩하는 이유:
- Windows PowerShell -EncodedCommand 파라미터는 UTF-16LE(base64) 입력을 기대
- Python의 encode("utf-16")은 BOM(2바이트) + UTF-16 데이터 생성
- [2:]로 BOM 제거 → PowerShell이 요구하는 BOM 없는 UTF-16LE만 남김
- BOM이 남으면 PowerShell 디코딩 실패 → 명령 실행 안 됨