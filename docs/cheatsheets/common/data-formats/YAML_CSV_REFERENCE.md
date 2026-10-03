# YAML & CSV 처리 가이드

설정 파일과 데이터 포맷 처리 방법들을 정리합니다.

## 1. YAML

설정 파일, Kubernetes 매니페스트 등에 사용되는 데이터 형식

### YAML 기본 구조

```yaml
# 주석
name: John Doe
age: 30

# 중첩
user:
  name: John
  email: john@example.com

# 리스트
hobbies:
  - reading
  - gaming
  - coding

# 혼합
team:
  - name: John
    role: Developer
  - name: Jane
    role: Manager
```

### Python으로 처리

#### 읽기

```python
import yaml

# 파일에서 읽기
with open('config.yaml') as f:
    data = yaml.safe_load(f)
    print(data['name'])  # John Doe

# 문자열에서 읽기
yaml_str = """
name: John
age: 30
"""
data = yaml.safe_load(yaml_str)
```

#### 쓰기

```python
import yaml

data = {
    'name': 'John',
    'age': 30,
    'hobbies': ['reading', 'coding']
}

# 파일로 저장
with open('output.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False)

# 문자열로
yaml_str = yaml.dump(data)
print(yaml_str)
```

#### 조작

```python
import yaml

data = yaml.safe_load(open('config.yaml'))

# 값 업데이트
data['age'] = 31

# 키 추가
data['city'] = 'Seoul'

# 리스트에 추가
data['hobbies'].append('painting')

# 파일에 저장
with open('config.yaml', 'w') as f:
    yaml.dump(data, f)
```

### Kubernetes YAML 예제

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  containers:
  - name: web
    image: nginx:latest
    ports:
    - containerPort: 80
  - name: app
    image: myapp:v1
    env:
    - name: ENV_VAR
      value: "production"
```

### 유효성 검증

```bash
# Python으로 YAML 검증
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"

# 성공하면 에러 없음, 실패하면 에러 출력
```

---

## 2. CSV (쉼표로 구분된 값)

### CSV 기본 구조

```csv
name,email,age
John Doe,john@example.com,30
Jane Smith,jane@example.com,28
Bob Johnson,bob@example.com,35
```

특수문자 포함 시:

```csv
name,email,description
"Smith, John",john@example.com,"Works at ""Acme"" Corp"
Jane Doe,jane@example.com,"Lives in Seoul, Korea"
```

### Python으로 처리

#### 읽기

```python
import csv

# 파일 읽기
with open('data.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(f"{row['name']}: {row['email']}")

# 또는 리스트로
with open('data.csv') as f:
    reader = csv.reader(f)
    for row in reader:
        print(row)  # ['name', 'email', 'age']
```

#### 쓰기

```python
import csv

data = [
    {'name': 'John', 'email': 'john@example.com', 'age': 30},
    {'name': 'Jane', 'email': 'jane@example.com', 'age': 28}
]

# 파일에 쓰기
with open('output.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['name', 'email', 'age'])
    writer.writeheader()
    writer.writerows(data)
```

#### 필터링 및 변환

```python
import csv

# 읽기 및 필터
with open('data.csv') as f:
    reader = csv.DictReader(f)
    data = [row for row in reader if int(row['age']) > 25]

# 특정 열만 추출
with open('data.csv') as f:
    reader = csv.DictReader(f)
    names = [row['name'] for row in reader]

# 변환하여 저장
with open('data.csv') as f, open('output.csv', 'w', newline='') as out:
    reader = csv.DictReader(f)
    writer = csv.DictWriter(out, fieldnames=['name', 'email'])
    writer.writeheader()
    for row in reader:
        if int(row['age']) > 25:
            writer.writerow({'name': row['name'], 'email': row['email']})
```

### 명령어 라인 처리

```bash
# 특정 열만 보기
cut -d, -f1,2 data.csv

# 헤더 건너뛰고 보기
tail -n +2 data.csv

# 정렬
sort -t, -k1 data.csv

# 필터링
grep "John" data.csv

# 계수
wc -l data.csv
```

### TSV (탭으로 구분)

```bash
# TSV 읽기
cut -f1,2 data.tsv

# CSV를 TSV로
tr ',' '\t' < data.csv > data.tsv

# TSV를 CSV로
tr '\t' ',' < data.tsv > data.csv
```

---

## 3. JSON ↔ YAML ↔ CSV 변환

### JSON → YAML

```bash
# Python 사용
python3 -c "import json, yaml; print(yaml.dump(json.load(open('data.json'))))"
```

### YAML → JSON

```bash
# Python 사용
python3 -c "import json, yaml; print(json.dumps(yaml.safe_load(open('data.yaml'))))"
```

### CSV → JSON

```bash
# Python
python3 << 'EOF'
import csv, json
data = []
with open('data.csv') as f:
    for row in csv.DictReader(f):
        data.append(row)
print(json.dumps(data, indent=2))
EOF
```

### JSON → CSV

```bash
# Python
python3 << 'EOF'
import json, csv
data = json.load(open('data.json'))
keys = data[0].keys()
with open('output.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=keys)
    writer.writeheader()
    writer.writerows(data)
EOF
```

---

## 4. 설정 파일 작업

### YAML 설정 읽기

```python
import yaml

# 기본 설정
default_config = {
    'debug': False,
    'port': 8080,
    'database': 'sqlite'
}

# 사용자 설정 로드
with open('config.yaml') as f:
    user_config = yaml.safe_load(f) or {}

# 병합 (사용자 설정이 기본값을 덮어씀)
config = {**default_config, **user_config}
```

### .env 파일 (KEY=VALUE)

```bash
# .env 파일 읽기
python3 << 'EOF'
import os
with open('.env') as f:
    for line in f:
        if line.strip() and not line.startswith('#'):
            key, value = line.strip().split('=', 1)
            os.environ[key] = value
EOF

# 또는 python-dotenv 사용
from dotenv import load_dotenv
load_dotenv()
```

---

## 5. 팁

YAML:
- 공백이 의미를 가짐 (들여쓰기 중요)
- 안전하게 파싱: `yaml.safe_load()` 사용
- 순환 참조 주의

CSV:
- 특수문자는 따옴표로 감싸기
- 인코딩 명시 (UTF-8 기본)
- 큰 파일은 청크 단위로 읽기

변환:
- 데이터 손실 가능성 확인
- 타입 정보 확인 (모두 문자열이 됨)
- 중첩 구조 유의
