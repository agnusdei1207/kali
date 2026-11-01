# Hashcat 웹 애플리케이션 해시 (-m 400, 7900, 11, 10000, 400)

CMS/프레임워크 패스워드 해시.

## phpass (WordPress/Drupal/Joomla/phpBB) (-m 400)

```bash
hashcat -m 400 -a 0 phpass.txt /usr/share/wordlists/rockyou.txt
```

## Drupal 7 (-m 7900)

```bash
hashcat -m 7900 -a 0 drupal.txt wordlist.txt
```

## Joomla (-m 11)

```bash
hashcat -m 11 -a 0 joomla.txt wordlist.txt
```

## Django (PBKDF2-SHA256) (-m 10000)

```bash
hashcat -m 10000 -a 0 django.txt wordlist.txt
```

## PrestaShop (-m 11000)

```bash
hashcat -m 11000 -a 0 prestashop.txt wordlist.txt
```

## OpenCart (-m 13900)

```bash
hashcat -m 13900 -a 0 opencart.txt wordlist.txt
```

## WordPress (phpass) DB 추출

```sql
SELECT user_login, user_pass FROM wp_users;
```

## 팁

- phpass는 MD5 기반으로 빠름. 먼저 시도
- Django PBKDF2는 느림. 시간 제한 두고 시도
- DB 덤프에서 해시 컬럼만 추출해 정리