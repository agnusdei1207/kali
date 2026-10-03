# JSON 파싱 및 처리 가이드

JSON 데이터를 파싱, 필터링, 변환하는 방법들을 정리합니다.

## 빠른 참고

| 도구 | 용도 | 설치 |
|------|------|------|
| jq | JSON 파싱 및 필터링 (가장 강력) | `sudo apt install jq` |
| python3 | JSON 처리 (유연함) | 기본 설치 |
| curl | API 응답 JSON 받기 | 기본 설치 |
| grep/sed/awk | 간단한 추출 (번거로움) | 기본 설치 |

## 1. jq 사용법

### 기본 파싱

```bash
# JSON 파일 정렬 및 표시
jq . data.json

# 컴팩트 형식 (한 줄)
jq -c . data.json

# 색상 제거
jq -M . data.json
```

### 필드 추출

```bash
# 특정 필드 추출
echo '{"name":"John", "age":30}' | jq .name
# 결과: "John"

# 중첩된 필드
echo '{"user":{"name":"John"}}' | jq .user.name
# 결과: "John"

# 배열 요소
echo '[1,2,3]' | jq .[0]
# 결과: 1

# 모든 배열 요소 반복
echo '[1,2,3]' | jq .[]
# 결과: 1 2 3
```

### 필터링

```bash
# 특정 조건으로 필터
echo '[{"name":"John","age":30}, {"name":"Jane","age":25}]' | jq '.[] | select(.age > 26)'

# 특정 필드만 선택
echo '[{"name":"John","age":30}]' | jq '.[] | {name}'

# 이름 바꾸기 (rename)
echo '{"old_name":"value"}' | jq '{new_name: .old_name}'
```

### 변환 및 조작

```bash
# 배열을 객체로
echo '[{"key":"a","value":1}]' | jq 'map({(.key): .value}) | add'

# 필드 추가
echo '{"name":"John"}' | jq '. + {age: 30}'

# 필드 삭제
echo '{"name":"John", "secret":"xxx"}' | jq 'del(.secret)'

# 필드 업데이트
echo '{"count":5}' | jq '.count += 1'
```

### 집계

```bash
# 배열 길이
echo '[1,2,3]' | jq 'length'

# 배열 요소 개수
echo '[1,2,3]' | jq '.[] | length'

# 합계
echo '[1,2,3]' | jq 'add'

# 최대값
echo '[3,1,2]' | jq 'max'

# 최소값
echo '[3,1,2]' | jq 'min'

# 그룹화
echo '[{"type":"a","val":1}, {"type":"b","val":2}]' | jq 'group_by(.type)'
```

## 2. Python으로 처리

### JSON 읽기

```python
import json

# 문자열에서 파싱
data = json.loads('{"name":"John","age":30}')
print(data['name'])  # John

# 파일에서 읽기
with open('data.json') as f:
    data = json.load(f)
```

### JSON 쓰기

```python
import json

data = {"name":"John", "age":30}

# 문자열로 변환
json_str = json.dumps(data)
print(json_str)

# 파일에 저장
with open('data.json', 'w') as f:
    json.dump(data, f, indent=2)
```

### 필터링 및 변환

```python
import json

data = json.loads('[{"name":"John","age":30}, {"name":"Jane","age":25}]')

# 필터링
adults = [person for person in data if person['age'] >= 18]

# 변환
names = [person['name'] for person in data]

# 정렬
sorted_data = sorted(data, key=lambda x: x['age'])
```

## 3. curl로 API 응답 받기

```bash
# 기본 GET 요청
curl https://api.example.com/users

# 포맷팅된 결과 (jq 필요)
curl -s https://api.example.com/users | jq .

# 특정 필드만 추출
curl -s https://api.example.com/users | jq '.[] | .name'

# POST 요청
curl -X POST https://api.example.com/users \
  -H "Content-Type: application/json" \
  -d '{"name":"John","age":30}'

# Authorization 헤더 추가
curl -H "Authorization: Bearer TOKEN" https://api.example.com/users | jq .
```

## 4. 빠른 변환

### JSON → CSV

```bash
# jq 사용
echo '[{"name":"John","age":30},{"name":"Jane","age":25}]' | jq -r '.[] | [.name, .age] | @csv'

# Python
import json, csv
data = json.load(open('data.json'))
writer = csv.DictWriter(open('out.csv', 'w'), fieldnames=['name', 'age'])
writer.writerows(data)
```

### JSON → 테이블 형식

```bash
# jq 테이블 형식
echo '[{"name":"John","age":30},{"name":"Jane","age":25}]' | jq -r '.[] | [.name, .age] | @tsv'
```

### JSON 유효성 검증

```bash
# jq로 유효성 확인
jq empty < data.json && echo "Valid" || echo "Invalid"

# Python
try:
    json.load(open('data.json'))
    print("Valid")
except:
    print("Invalid")
```

## 팁

- jq는 강력하지만 초기 학습곡선이 있음
- 간단한 작업은 Python이 더 직관적
- curl + jq 조합이 API 작업에 최고
- JSON 포맷팅: `jq .` 또는 `python3 -m json.tool`
