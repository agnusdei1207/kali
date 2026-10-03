# XML 파싱 및 처리 가이드

XML 데이터를 파싱, 추출, 검증하는 방법들을 정리합니다.

## 빠른 참고

| 도구 | 용도 | 사용 |
|------|------|------|
| xmllint | XML 검증 및 파싱 | 명령어 라인 |
| xpath | XPath로 요소 추출 | XML 쿼리 |
| Python xml | 프로그래밍적 처리 | 스크립트 |
| grep/sed | 간단한 추출 (번거로움) | 기본 도구 |

## 1. XML 기본 구조

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
  <user id="1">
    <name>John</name>
    <email>john@example.com</email>
  </user>
  <user id="2">
    <name>Jane</name>
    <email>jane@example.com</email>
  </user>
</root>
```

요소 구성:
- `<tag>` 시작 태그
- `</tag>` 종료 태그
- `attribute="value"` 속성
- `<!-- comment -->` 주석

## 2. xmllint 사용법

### XML 유효성 검증

```bash
# 기본 검증
xmllint data.xml

# Well-formed 확인 (파싱만)
xmllint --noout data.xml

# DTD 검증
xmllint --dtdvalid schema.dtd data.xml

# Schema 검증
xmllint --schema schema.xsd data.xml
```

### XML 포맷팅

```bash
# 정렬하여 표시
xmllint --format data.xml

# 컴팩트하게
xmllint --format --noblanks data.xml

# 색상 없이
xmllint --format --nocolor data.xml
```

### XPath로 추출

```bash
# 모든 name 요소 추출
xmllint --xpath '//name' data.xml

# 특정 id 속성 가진 요소
xmllint --xpath '//user[@id="1"]' data.xml

# 텍스트만 추출
xmllint --xpath '//name/text()' data.xml
```

## 3. Python으로 처리

### ElementTree (기본)

```python
import xml.etree.ElementTree as ET

# XML 파일 읽기
tree = ET.parse('data.xml')
root = tree.getroot()

# 모든 user 요소 순회
for user in root.findall('user'):
    name = user.find('name').text
    email = user.find('email').text
    print(f"{name}: {email}")

# 속성 접근
user_id = user.get('id')

# 특정 요소 찾기
user1 = root.find("user[@id='1']")
```

### lxml (더 강력함)

```python
from lxml import etree

# XML 파일 읽기
tree = etree.parse('data.xml')
root = tree.getroot()

# XPath로 쿼리
names = root.xpath('//name/text()')
print(names)  # ['John', 'Jane']

# 속성으로 필터
users = root.xpath('//user[@id="1"]')
```

### XML 생성

```python
import xml.etree.ElementTree as ET

root = ET.Element('root')

user = ET.SubElement(root, 'user', id='1')
name = ET.SubElement(user, 'name')
name.text = 'John'

email = ET.SubElement(user, 'email')
email.text = 'john@example.com'

# 파일로 저장
tree = ET.ElementTree(root)
tree.write('output.xml', encoding='utf-8')

# 또는 문자열로
print(ET.tostring(root, encoding='unicode'))
```

## 4. XPath (쿼리 언어)

### 기본 문법

```
/root           → root 요소
//user          → 모든 user 요소 (깊이 무관)
/root/user      → root 아래의 user
.               → 현재 요소
..              → 부모 요소
@attribute      → 속성
/text()         → 텍스트 내용
```

### 예제

```bash
# 모든 user의 name 추출
xmllint --xpath '//user/name/text()' data.xml

# id 속성이 "1"인 user
xmllint --xpath '//user[@id="1"]' data.xml

# email 텍스트만
xmllint --xpath '//user[@id="1"]/email/text()' data.xml

# 여러 조건
xmllint --xpath '//user[@id="1" or @id="2"]' data.xml

# 이름이 John인 user
xmllint --xpath '//user[name="John"]' data.xml
```

## 5. 보안 취약점 (XXE)

### XML External Entity 공격 감지

```xml
<!-- XXE 공격 시도 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### 방어법

```python
# Python 안전 파싱
from lxml import etree

# XXE 공격 방지
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False
)
tree = etree.parse('data.xml', parser=parser)

# ElementTree도 마찬가지
import xml.etree.ElementTree as ET
ET.XMLParser(resolve_entities=False)
```

## 6. SOAP (웹 서비스)

XML 기반 웹 서비스 요청

```xml
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap-envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.com/">
      <id>1</id>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

### SOAP 요청

```bash
# curl로 SOAP 요청
curl -X POST http://example.com/service \
  -H "Content-Type: text/xml; charset=UTF-8" \
  -H "SOAPAction: GetUser" \
  -d @request.xml
```

## 7. XML과 JSON 변환

### XML → JSON

```python
import xml.etree.ElementTree as ET
import json

def xml_to_dict(element):
    result = {}
    for child in element:
        child_data = xml_to_dict(child)
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_data)
        else:
            result[child.tag] = child_data
    return result or element.text

tree = ET.parse('data.xml')
root = tree.getroot()
json_data = json.dumps(xml_to_dict(root), indent=2)
print(json_data)
```

### JSON → XML

```python
import json
import xml.etree.ElementTree as ET

def dict_to_xml(parent, data):
    if isinstance(data, dict):
        for key, value in data.items():
            child = ET.SubElement(parent, key)
            dict_to_xml(child, value)
    else:
        parent.text = str(data)

with open('data.json') as f:
    data = json.load(f)

root = ET.Element('root')
dict_to_xml(root, data)
ET.ElementTree(root).write('output.xml')
```

## 팁

- XML은 자체 설명적이지만 크기가 크다 (JSON 추천)
- XXE 취약점 주의 (외부 엔티티 비활성화)
- XPath는 XML 쿼리에 매우 강력
- SOAP는 레거시 웹 서비스 (REST 더 일반적)
- XML 파싱은 메모리 효율성 고려 (대용량 파일)
