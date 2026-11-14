# Hashcat -m 2600 md5(md5($pass).$salt)

- hashcat -m 2600 md5(md5($pass).$salt) 크래킹 — MD5를 두 번 적용하고 salt를 뒤에 붙인 해시로, 고정 salt를 rule 파일에서 $Y $O $U처럼 한 문자씩 append해 처리
- 일부 웹 앱·레거시 시스템에서 이 형식의 해시를 덤프했고 salt가 고정값일 때
- hashcat 설치, salt 문자를 rule 문법으로 변환한 rule 파일 — salt가 해시별로 다르면 rule 대신 salt 포함 모드 사용, 특수문자는 $ 이스케이프와 대소문자 정확 일치 주의

MD5를 두 번 적용하고 salt를 뒤에 붙인 해시. 일부 웹 앱/레거시 시스템에서 사용.

## rule 파일 작성

hashcat rule 문법은 각 문자별로 `$`를 붙여야 하나씩 뒤에 append된다.

```txt
# rule.txt
# salt = "YOUR_SALT_HERE" (하드코딩된 고정 salt)
$Y $O $U $R $_ $S $A $L $T $_ $H $E $R $E
```

각 `$X`는 문자 X를 후보 뒤에 append한다. 공백은 구분자.

## 실행

```bash
hashcat -m 2600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -r rule.txt
```

## salt가 다른 경우

salt가 해시별로 다르면 rule 방식이 아닌 salt 포함 모드 사용. 고정 salt일 때만 rule 방식.

## 확인

```bash
# 규칙 결과 미리보기
echo "password" | hashcat --stdout -r rule.txt
```

## 팁

- salt 문자열에 특수문자가 있으면 `$` 이스케이프 필요
- rule 파일의 salt는 정확히 일치해야 합니다 (대소문자 포함)
- salt가 고정이 아닐 경우 hash 형식에 salt를 포함하는 모드 사용