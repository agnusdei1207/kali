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
| /    | %2F        |
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
```

## 실시간 인코딩/디코딩 도구

OSCP 시험 환경에서는 Burp Suite를 사용할 수 있으며, Burp Suite의 Decoder 기능을 활용하면 실시간으로 인코딩/디코딩을 수행할 수 있습니다.
