# wordlists

## 개요

`wordlists` 패키지로 기본 wordlist를 설치하고, 크게 세 종류로 나뉜다.

| 종류                           | 경로                                   | 주 용처                         |
| ------------------------------ | -------------------------------------- | ------------------------------- |
| rockyou.txt                    | `/usr/share/wordlists/rockyou.txt`     | MD5·SHA-1·MD5crypt 해시         |
| SecLists/Web-Content/*         | `/opt/SecLists/Discovery/Web-Content/` | SQLi·서비스 취약점 검색         |
| SecLists/Credentials/*         | `/opt/SecLists/Discovery/Credentials/` | Hydra/Hashcat용 사용자/비밀번호 |
| SecLists/Discovery/Passwords/* | `/opt/SecLists/Discovery/Passwords/`   | SSH 계정                        |

## 설치와 확인

```bash
sudo apt update
sudo apt install wordlists -y
sudo apt install seclists -y

sudo gzip -d /usr/share/wordlists/rockyou.txt.gz /usr/share/wordlists/

ls /opt/SecLists/Discovery/Web-Content/ | head
ls /opt/SecLists/Discovery/Credentials/ | head
```

## 실전 예시

```bash
# Hydra: SSH에 rockyou로 대입
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10

# Hydra: HTTP 폼에 SecLists의 common-passwords
hydra -l admin -P /opt/SecLists/Discovery/Passwords/common-passwords.txt http-post-form \"user=^USER&pass=^PASS\"

# John: 해시 파일의 기본 wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# hashcat: gpu가 있는 경우(모듈 ID)
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

## 주의

- 해시의 알고리즘에 맞는 wordlist를 고른다(해시 형식을 먼저 확인).
- wordlist가 길어지면 시험 시간이 크게 줄어든다. OSCP에서는 합리적인 개수로 제한한다.
- 계정 락·무차별 대입은 합법적이지 않으므로 허가된 대상에서만.
- 모든 시도는 합법적인 대상(본인 소유·허가받은 시스템)에서만 실행한다.
