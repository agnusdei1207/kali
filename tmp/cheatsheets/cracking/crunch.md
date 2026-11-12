# crunch 워드리스트 생성

- crunch — 문자 집합과 길이를 지정해 가능한 조합을 전부 생성하는 사전(wordlist) 제조 도구. john·hashcat 앞 단계의 후보군 생성기다.
- 암호 정책(길이·구성)이 알려져 패턴 기반 조합이 필요할 때, 마스크(@, %, ^)로 타깃형 리스트를 만들 때, 디스크에 쓰지 않고 john/hashcat에 파이프로 바로 넣을 때.
- apt install crunch. charset.lst 경로는 /usr/share/crunch/charset.lst. 긴 조합은 생성량이 폭발하므로 사전에 자릿수를 계산한다.

## 기본 명령어 구조

```bash
crunch <min> <max> [charset] [옵션]
```

## 기본 생성

```bash
crunch 4 6 abc123 -o words.txt
crunch 8 8 0123456789 -o numeric8.txt
```

- min/max는 후보 문자열의 최소·최대 길이다. charset 생략 시 기본 문자 집합(소문자)이 쓰인다.
- -o로 저장 파일을 지정한다. 없으면 stdout으로 흘러나온다.

## 패턴 (-t)과 자리표

```bash
# @ = 소문자, , = 대문자, % = 숫자, ^ = 기호
crunch 10 10 -t Passw0rd@@ -o suffix.txt     # Passw0rd 뒤 소문자 2자리
crunch 8 8 -t passw%%% -o digits3.txt        # passw 뒤 숫자 3자리
crunch 10 10 -t Company%^% -o pattern.txt    # 기호-숫자-기호 패턴
```

- -t를 쓰면 min/max는 패턴 길이와 같게 맞춘다.
- 패턴에 리터럴 @, ^ 문자 자체가 필요하면 -l로 escape 대상 자리를 지정한다.

## charset.lst (-f)

```bash
# 미리 정의된 문자 집합 사용
crunch 6 8 -f /usr/share/crunch/charset.lst mixalpha-numeric-all -o words.txt
```

- -f <경로> <이름> 형태. 주요 이름: numeric, loweralpha, mixalpha-numeric, mixalpha-numeric-all-space 등.
- charset을 직접 타이핑하는 것보다 오타 없이 정확한 집합을 지정할 수 있다.

## 분할·압축 저장

```bash
crunch 4 8 abcdefgh -b 20mb -o START        # 20MB 단위로 파일 분할
crunch 4 8 abcdefgh -c 1000000 -o START     # 100만 라인 단위 분할
crunch 4 8 abcdefgh -z gzip -o START        # gzip 압축 저장
```

- -b(용량)·-c(라인 수)로 분할할 때 출력 파일명을 START로 지정하면 crunch가 START01, START02... 형태로 자동 분할한다.

## john / hashcat 파이프 연계

```bash
# john --stdin: 후보를 디스크에 쓰지 않고 즉시 크랙
crunch 6 8 abc123 | john --stdin hashes.txt

# hashcat 파이프 입력
crunch 8 8 0123456789 | hashcat -m 0 hashes.txt -a 0

# 마스크 생성 후 hashcat 마스크 모드로 동일 후보군 재현
crunch 8 8 -t passw%%% | head -5
hashcat -m 0 hashes.txt -a 3 passw?d?d?d
```

- 파이프는 후보가 늘어도 디스크를 소모하지 않는다. 긴 조합일수록 파이프가 유리하다.
- hashcat 마스크 모드(-a 3, ?d 자리표)로 같은 패턴을 crunch 없이 재현할 수도 있다.

## 실전 예시

```bash
# 10자리 고정 접두사 + 숫자 3자리
crunch 13 13 -t adminuser%%% -o admin_suffix.txt

# 대문자 시작 + 소문자 + 숫자 2자리 (회사 정책 패턴)
crunch 11 11 -t ,@@@@@@%% -o corp_pattern.txt
```

## 팁·트러블슈팅

- 생성량은 (문자집합 크기)^자릿수다. 8자리 숫자가 이미 1억 개다. 실행 전에 계산하고 파이프나 -b 분할을 쓴다.
- -t 패턴 사용 시 min/max를 패턴 길이와 안 맞추면 의도와 다른 후보가 나온다.
- 순수 브루트포스보다는 알려진 접두사·정책 패턴에 -t를 조합하는 편이 효율이 크다.
- 리터럴 @ 문자가 필요한 패턴은 -l 옵션을 잊기 쉽다. 결과에 @ 가 없으면 escape 누락을 의심한다.
