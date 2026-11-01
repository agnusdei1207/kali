# Hashcat salt 처리

salt 포함 해시 크래킹.

## hashcat 형식 (salt:hash)

많은 모드에서 `hash:salt` 또는 별도 파일. 모드별 형식은 `hashcat --example-hashes`로 확인.

```bash
# 예: md5($pass.$salt) -m 10 형식: hash:salt
echo '5d41402abc4b2a76b9719d911017c592:salt123' > hash.txt
hashcat -m 10 -a 0 hash.txt wordlist.txt
```

## salt 파일 분리

```bash
# 해시와 salt가 분리된 경우 모드에 맞게 결합
paste -d ':' hash_only.txt salt_only.txt > hash.txt
```

## 다중 salt

- hashcat은 해시별 salt를 자동 처리
- 같은 워드리스트로 여러 salt 해시 동시 크래킹 가능

## 커스텀 salt (rule 기반 append)

2중 MD5 + salt (-m 2600)처럼 salt가 고정인 경우 rule로 append.

```text
# rule.txt (salt = SALT)
$S $A $L $T
```

```bash
hashcat -m 2600 -a 0 hash.txt wordlist.txt -r rule.txt
```

## 팁

- salt는 해시 파일에 포함되어야 함. 누락 시 오류
- salt 길이/문자셋은 모드별로 다름
- `--example-hashes`로 정확한 형식 확인 필수