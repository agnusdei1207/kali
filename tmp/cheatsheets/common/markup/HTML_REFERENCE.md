# HTML 및 마크업 처리 가이드

웹 페이지 구조 분석, 파싱, 조작 방법들을 정리합니다.

## 1. HTML 기본 구조

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Page Title</title>
</head>
<body>
  <h1>Heading</h1>
  <p>Paragraph with <strong>bold</strong> text</p>
  <a href="https://example.com">Link</a>
  <form>
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Login</button>
  </form>
</body>
</html>
```

## 2. Python으로 HTML 파싱

### BeautifulSoup

가장 사용하기 쉬운 HTML 파서

#### 설치

```bash
pip install beautifulsoup4
```

#### 기본 사용

```python
from bs4 import BeautifulSoup
import requests

# URL에서 받기
response = requests.get('https://example.com')
soup = BeautifulSoup(response.content, 'html.parser')

# 파일에서 읽기
with open('page.html') as f:
    soup = BeautifulSoup(f, 'html.parser')

# 문자열에서 파싱
html = '<html><body><h1>Title</h1></body></html>'
soup = BeautifulSoup(html, 'html.parser')
```

#### 요소 선택

```python
# 첫 번째 요소 찾기
title = soup.find('h1')
print(title.text)

# 모든 링크 찾기
links = soup.find_all('a')
for link in links:
    print(link.get('href'))

# CSS 선택자 사용
divs = soup.select('div.container')
input_field = soup.select_one('input[name="username"]')

# 속성 접근
href = link.get('href')
class_name = link.get('class')

# 부모/자식
parent = element.parent
children = element.children
```

#### 폼 데이터 추출

```python
# 모든 폼 찾기
form = soup.find('form')

# 폼의 모든 입력 필드
inputs = form.find_all('input')
for inp in inputs:
    print(f"{inp.get('name')}: {inp.get('type')}")

# 폼 액션
action = form.get('action')
method = form.get('method')
```

#### 조작 및 수정

```python
# 새 요소 추가
new_tag = soup.new_tag('p', string='New paragraph')
soup.body.append(new_tag)

# 요소 제거
tag.decompose()

# 텍스트 수정
tag.string = 'New text'

# 속성 수정
tag['class'] = 'new-class'

# HTML로 저장
with open('output.html', 'w') as f:
    f.write(str(soup))
```

### lxml (더 빠름)

```python
from lxml import html
import requests

# 페이지 가져오기
response = requests.get('https://example.com')
page = html.fromstring(response.content)

# XPath로 선택
titles = page.xpath('//h1/text()')
links = page.xpath('//a/@href')

# CSS 선택자
elements = page.cssselect('div.container')
```

---

## 3. 웹 스크래핑 예제

### 기본 스크래핑

```python
from bs4 import BeautifulSoup
import requests

url = 'https://example.com'
response = requests.get(url)
soup = BeautifulSoup(response.content, 'html.parser')

# 모든 제목 수집
for article in soup.find_all('article'):
    title = article.find('h2').text
    link = article.find('a').get('href')
    print(f"{title}: {link}")
```

### 테이블 파싱

```python
import pandas as pd
from bs4 import BeautifulSoup
import requests

# Pandas로 자동 추출 (가장 쉬움)
url = 'https://example.com'
tables = pd.read_html(url)
df = tables[0]

# 또는 수동으로
response = requests.get(url)
soup = BeautifulSoup(response.content, 'html.parser')

table = soup.find('table')
rows = []
for tr in table.find_all('tr'):
    cols = [td.text.strip() for td in tr.find_all(['td', 'th'])]
    rows.append(cols)

for row in rows:
    print(row)
```

### 로그인이 필요한 페이지

```python
import requests
from bs4 import BeautifulSoup

session = requests.Session()

# 로그인
login_url = 'https://example.com/login'
login_data = {
    'username': 'your_username',
    'password': 'your_password'
}
session.post(login_url, data=login_data)

# 로그인 후 페이지 접근
response = session.get('https://example.com/protected')
soup = BeautifulSoup(response.content, 'html.parser')
print(soup.title.text)
```

---

## 4. 명령어 라인 도구

### curl + grep

```bash
# 제목만 추출
curl -s https://example.com | grep '<title>' | sed 's/<[^>]*>//g'

# 모든 링크 추출
curl -s https://example.com | grep -o 'href="[^"]*"' | cut -d'"' -f2
```

### wget으로 다운로드

```bash
# 페이지 저장
wget https://example.com

# 재귀적 다운로드 (조심!)
wget -r -l 2 https://example.com

# 특정 확장자만
wget -r -A pdf https://example.com
```

---

## 5. HTML 보안

### XSS (Cross-Site Scripting)

위험한 HTML 입력 필터링

```python
from html import escape
from bleach import clean

# 위험한 태그 제거
dirty = '<script>alert("XSS")</script><p>Safe</p>'

# 이스케이프
safe = escape(dirty)

# 또는 bleach로 특정 태그만 허용
safe = clean(dirty, tags=['p', 'a'], attributes={'a': ['href']})
```

### HTML 인젝션 방지

```python
# 절대 하지 말 것
html = f'<div>{user_input}</div>'  # 위험!

# 대신 escape 사용
from html import escape
html = f'<div>{escape(user_input)}</div>'  # 안전
```

---

## 6. 마크다운 변환

### HTML → Markdown

```python
from markdownify import markdownify as md

html = '<h1>Title</h1><p>Some text</p>'
markdown = md(html)
print(markdown)
# # Title
# Some text
```

### Markdown → HTML

```python
import markdown

md_text = '# Title\n\nSome text'
html = markdown.markdown(md_text)
print(html)
# <h1>Title</h1>
# <p>Some text</p>
```

---

## 7. 팁

일반:
- 스크래핑 전 robots.txt 확인
- User-Agent 설정하기
- 너무 많은 요청 주의 (차단당할 수 있음)
- 에러 처리 필수

BeautifulSoup:
- `find()` vs `find_all()` 구분
- `get()` vs `[]` 속성 접근 방법
- `.text` vs `.string` 차이

성능:
- lxml이 BeautifulSoup보다 빠름
- Pandas는 테이블에 최고
- 병렬 처리로 속도 향상 (주의: 차단 위험)
