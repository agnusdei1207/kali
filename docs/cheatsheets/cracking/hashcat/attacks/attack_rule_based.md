# Hashcat 규칙 기반 공격 (Rule-based)

- hashcat 규칙 기반 공격 — -r로 규칙 파일(best64.rule 등)을 지정해 워드리스트 단어를 대소문자 토글·접미사 추가 등 맹글링 변형한 후보로 크래킹
- 사전 공격(-a 0)이 실패한 직후. 원 단어는 사전에 있지만 Password1!, p@ssw0rd 같은 변형이 쓰였을 가능성이 클 때
- hashcat 설치, 워드리스트와 규칙 파일(/usr/share/hashcat/rules/) — 규칙은 --stdout으로 미리보기 검증 권장, 다중 규칙 파일 조합은 후보 수 곱셈 폭발 주의

워드리스트에 맹글링 규칙을 적용해 변형 후보를 생성한다. `-r`로 규칙 파일 지정.

## 기본

```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

## 다중 규칙 파일

```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rule1.rule -r rule2.rule
```

## 규칙 테스트 (stdout)

```bash
echo "password" | hashcat --stdout -r /usr/share/hashcat/rules/best64.rule
echo "password" | hashcat --stdout -r custom.rule | head -20
```

## 인기 규칙 파일

- best64.rule: 64개 핵심 규칙, 빠름
- d3ad0ne.rule: 더 많은 변형, 느림
- rockyou-30000.rule: 30000개 규칙, 매우 느림
- dive.rule: 가장 광범위, 극도로 느림
- toggles1.rule, toggles2.rule: 대소문자 토글

## 커스텀 규칙 파일 예시

```text
# custom.rule
$1
$!
c
u
r
$2$0$2$4
```

```bash
hashcat -m 0 -a 0 hash.txt wordlist.txt -r custom.rule
```

## 팁

- 규칙 조합 시 곱셈 효과로 메모리/시간 폭발 주의
- 작은 워드리스트 + 강한 규칙이 큰 워드리스트 + 약한 규칙보다 효율적일 수 있음
- `--generate-rules`로 자동 규칙 생성 가능 (고급)