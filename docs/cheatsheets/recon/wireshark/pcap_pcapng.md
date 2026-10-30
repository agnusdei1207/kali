# pcap / pcapng (Wireshark)

## 개요

`pcap`/`pcapng`은 패킷 캡처 파일 포맷이다. Wireshark/tcpdump가 기록하는 파일이며, 트래픽을 분석해 서비스 버전·쿠키·페이로드를 확인한다.

## 기본 확인

```bash
# 캡처 파일 열기 (GUI)
wireshark capture.pcapng &

# 텍스트로 간단히 보기
tcpdump -r capture.pcapng -nn
```

- `tcpdump -r`: 캡처 파일을 읽어들여 텍스트로 출력한다.
- `-nn`: IP/포트 번호를 숫자로 출력(역분석 생략, 속도 향상).

## 자주 보는 필터 (Wireshark)

| 필터 | 의미 |
|------|------|
| `http` | HTTP 트래픽만 |
| `tcp.port == 80` | 포트 80 트래픽만 |
| `ip.addr == 10.10.10.10` | 특정 IP와 관련된 트래픽 |
| `http.request.method == POST` | POST 요청만 |

## 실전에서 하는 일

- 캡처 파일을 열어 쿠키, 세션 토큰, 평문 자격 증명을 찾는다(예: HTTP Basic Auth, 쿠키 값).
- `Follow > TCP Stream`으로 특정 연결의 전체 흐름을 확인한다.
- 찾은 값은 웹 취약점 분석 단계(쿠키 디코딩, XSS/SQLi 페이로드 조립)에 쓴다.

## 팁

- 캡처 파일은 증적(단계 6)의 증거로 첨부할 수 있다.
- 대용량 캡처는 `http` 필터로 먼저 좁힌 뒤 분석한다.

## 참고 / 증적
- 발견한 내용과 증거는 노트(05-progress-tracker.md)에 함께 기록한다.
