# Markdown 작성 및 변환 가이드

마크다운 문법, 변환, 활용법을 정리합니다.

## 1. Markdown 기본 문법

### 제목

```markdown
# Heading 1
## Heading 2
### Heading 3
#### Heading 4
##### Heading 5
###### Heading 6

또는 H1, H2는 다음과 같이도 가능:
Heading 1
==========

Heading 2
----------
```

### 텍스트 스타일

```markdown
*이탤릭* 또는 _이탤릭_
볼드 또는 __볼드__
*볼드 이탤릭* 또는 ___볼드 이탤릭___
~~취소선~~
`인라인 코드`
```

### 리스트

```markdown
# 순서 없는 리스트
- 항목 1
- 항목 2
  - 중첩 항목
  - 중첩 항목 2
* 별표도 가능
+ 더하기도 가능

# 순서 있는 리스트
1. 첫 번째
2. 두 번째
3. 세 번째
   1. 중첩 항목
   2. 중첩 항목 2

# 체크리스트
- [x] 완료 항목
- [ ] 미완료 항목
```

### 코드 블록

```markdown
# 인라인 코드
`print("hello")`

# 코드 블록
```python
def hello():
    print("Hello, World!")
```

# 들여쓰기로 코드 블록 만들기
    code here
    more code
```

### 링크와 이미지

```markdown
# 링크
[링크 텍스트](https://example.com)
[링크 텍스트](https://example.com "제목")

# 자동 링크
<https://example.com>

# 참조 링크
[링크][ref]
[ref]: https://example.com

# 이미지
![대체 텍스트](image.jpg)
![대체 텍스트](image.jpg "이미지 제목")

# 링크가 있는 이미지
[![대체 텍스트](image.jpg)](https://example.com)
```

### 인용문

```markdown
> 이것은 인용문입니다.
> 
> 여러 줄도 가능합니다.

> 중첩된 인용문
>> 이렇게
```

### 표 (Github Markdown)

```markdown
| 헤더 1 | 헤더 2 | 헤더 3 |
|--------|--------|--------|
| 셀 1   | 셀 2   | 셀 3   |
| 셀 4   | 셀 5   | 셀 6   |

# 정렬 지정
| 왼쪽 정렬 | 중앙 정렬 | 오른쪽 정렬 |
|:---------|:---------:|----------:|
| 왼쪽     | 중앙      | 오른쪽    |
```

### 수평선

```markdown
---
*
___
```

### HTML

```markdown
Markdown에 직접 HTML 사용 가능:

<div style="color: red;">
This is HTML
</div>
```

---

## 2. 확장 문법

### 주석

```markdown
<!-- 이것은 렌더링되지 않는 주석입니다 -->
```

### 정의 리스트 (확장)

```markdown
용어
: 정의 1
: 정의 2
```

### 각주 (확장)

```markdown
이것은 각주[^1]입니다.

[^1]: 각주의 내용입니다.
```

### 수학 (확장)

```markdown
인라인 수학: $E = mc^2$

블록 수학:
$$
E = mc^2
$$
```

---

## 3. Python으로 변환

### Markdown → HTML

```python
import markdown

md_text = """
# Title
This is bold text.

- Item 1
- Item 2
"""

html = markdown.markdown(md_text)
print(html)
```

### HTML → Markdown

```python
from markdownify import markdownify as md

html = """
<h1>Title</h1>
<p>This is <strong>bold</strong> text.</p>
<ul>
  <li>Item 1</li>
  <li>Item 2</li>
</ul>
"""

md_text = md(html)
print(md_text)
```

### Markdown 파일 처리

```python
import markdown

# 파일 읽기
with open('input.md') as f:
    md_text = f.read()

# HTML로 변환
html = markdown.markdown(md_text)

# HTML 파일로 저장
with open('output.html', 'w') as f:
    f.write(f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body>
    {html}
    </body>
    </html>
    """)
```

---

## 4. 명령어 라인 도구

### Pandoc (가장 강력)

```bash
# 설치
sudo apt install pandoc

# Markdown → HTML
pandoc input.md -o output.html

# Markdown → PDF
pandoc input.md -o output.pdf

# Markdown → Word
pandoc input.md -o output.docx

# HTML → Markdown
pandoc input.html -o output.md

# 포맷 확인
pandoc input.md -t plain
```

### Markdown to PDF

```bash
# markdown-pdf 사용
npm install -g markdown-pdf
markdown-pdf input.md

# 또는 python
python3 -m pip install markdown2pdf
markdown2pdf input.md
```

---

## 5. Git & GitHub 마크다운

### README.md

```markdown
# 프로젝트 이름

프로젝트 설명

## 설치

```bash
pip install mypackage
```

## 사용 예시

```python
import mypackage
mypackage.hello()
```

## 라이센스

MIT License

## 기여

PR 환영합니다!
```

### 이슈 & PR 템플릿

```markdown
## 설명
이 변경의 목적을 설명합니다.

## 관련 이슈
Closes #123

## 테스트 방법
이렇게 테스트할 수 있습니다:
1. 단계 1
2. 단계 2

## 체크리스트
- [x] 코드 리뷰 받음
- [x] 테스트 통과
- [ ] 문서 업데이트
```

---

## 6. 마크다운 리플레이버 비교

| 플레이버 | 특징 | 사용처 |
|---------|------|------|
| CommonMark | 표준 | 보편적 |
| GitHub Flavored | 테이블, 체크리스트, 이모지 | GitHub |
| MultiMarkdown | 각주, 메타데이터 | 프로 문서작성 |
| Pandoc | 매우 강력, 변환 | 변환 도구 |

---

## 7. 스타일 팁

작성 시 주의사항:

공백:
- 코드 블록 전후로 빈 줄
- 리스트 항목들 사이 빈 줄 (복잡할 때)

정렬:
- 일관된 제목 레벨 (h1부터 시작)
- 일관된 리스트 마커 (- 또는 *)

가독성:
- 문단을 짧게 유지
- 코드는 항상 블록으로
- 중요한 것은 볼드로

---

## 8. 일반적인 패턴

### 문서 구조

```markdown
# 주제

간단한 설명

## 섹션 1

내용

### 소섹션

더 자세한 내용

## 섹션 2

다른 내용

## 참고

- 링크 1
- 링크 2
```

### 튜토리얼 구조

```markdown
# [도구명] 튜토리얼

## 설치

## 기본 사용법

## 실제 예제

## 고급 기능

## 팁과 주의사항
```

### 문제 해결

```markdown
## 자주 묻는 질문 (FAQ)

### Q: 질문?
A: 답변

### Q: 다른 질문?
A: 다른 답변
```
