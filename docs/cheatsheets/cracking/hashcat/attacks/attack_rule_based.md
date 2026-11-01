# Hashcat 규칙 기반 공격 (Rule-based)

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