# 해시 길이로 알고리즘 판별

- 해시 문자열의 글자 수로 알고리즘을 가리는 방법. MD5는 16진수 32자, SHA-1은 40자, SHA-256은 64자. `wc -c`에 개행이 섞이면 각각 1씩 늘어 33·41·65로 보이므로 `-n` 여부를 항상 확인한다.
- 해시 값만 주어지고 알고리즘을 모를 때, hashcat 모드 번호(-m)나 크래킹 도구를 고르기 전 길이부터 세어 후보를 좁힐 때.
- `wc -c`와 `-n` 옵션의 개행 처리만 조심하면 되고, 추가 도구는 필요 없다. 형식(예: `$id$salt$hash`)이 붙어 있으면 길이 판별 전에 분리해야 한다.

## 기본 명령

```bash
# 개행을 빼고 정확한 길이 세기
echo -n "844ffc2c7150b93c4133a6ff2e1a2dba" | wc -c
# 32

# -n을 빼면 개행 1자가 섞여 33이 나온다 — 실수하기 쉬운 함정
echo "844ffc2c7150b93c4133a6ff2e1a2dba" | wc -c
# 33 (개행 포함)
```

## 길이 기준 판별표

```text
32자   -> MD5                  hashcat -m 0     john --format=Raw-MD5
40자   -> SHA-1                hashcat -m 100   john --format=Raw-SHA1
56자   -> SHA-224              hashcat -m 10100
64자   -> SHA-256              hashcat -m 1400  john --format=Raw-SHA256
128자  -> SHA-512              hashcat -m 1700
32자   + 소문자만 + 순수16진수 -> MD5 (가장 흔한 경우)
```

- 65자가 나오면 64자 해시에 개행이 붙은 것으로 보고 `-n`으로 다시 센다.
- 길이가 판별표에 없으면 형식 접두사(`$6$`, `$2y$`, `NT:` 등)가 붙어 있는지 먼저 확인한다. 이 경우 raw 해시가 아니라 crypt 형식이고 모드 번호가 완전히 달라진다.

## 형식 접두사도 같이 보기

```text
$1$  -> MD5 crypt       hashcat -m 500
$5$  -> SHA-256 crypt   hashcat -m 7400
$6$  -> SHA-512 crypt   hashcat -m 1800   (Linux /etc/shadow 기본값 중 하나)
$2y$ -> bcrypt          hashcat -m 3200
NT:  또는 rid:lm:ntlm   -> NTLM           hashcat -m 1000 (ntlm 필드만)
```

## 실전 절차

```bash
# 1) 길이 확인
echo -n "<해시>" | wc -c

# 2) 16진수인지 확인 (raw MD5/SHA 계열 판정)
echo -n "<해시>" | grep -E '^[0-9a-f]{32}$' && echo "MD5 raw"

# 3) 후보 모드로 크래킹
hashcat -m 0 -a 0 <해시파일> /usr/share/wordlists/rockyou.txt
```

- hashid 같은 도구로 교차 검증해도 좋다: `hashid <해시>` → 후보 알고리즘 목록이 뜬다. 도구가 여러 후보를 주는 것과 달리 길이는 결정적 단서다.
- 대소문자가 섞여 있으면 raw 16진수가 아니라 Base32/Base64 계열일 가능성을 의심한다.

## 트러블슈팅

- wc -c가 예상보다 1 크면 개행 문제다. `echo -n` 또는 `printf '%s'`를 쓴다.
- 해시에 공백이 섞여 있으면 복사 단계에서 잘못된 것이다. 붙여넣기 전후로 길이를 재검증한다.
- 길이가 맞는데 크래킹이 안 되면 솔트가 붙은 변형(MD5 salted = -m 10, SHA1 salted = -m 110)일 수 있다. 앞/뒤에 `salt:` 구분이 있는지 본문을 살핀다.
