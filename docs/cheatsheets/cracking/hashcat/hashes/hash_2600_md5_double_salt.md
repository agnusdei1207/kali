# Hashcat -m 2600 md5(md5($pass).$salt)

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
- rule 파일의 salt는 정확히 일치해야 함 (대소문자 포함)
- salt가 고정이 아닐 경우 hash 형식에 salt를 포함하는 모드 사용