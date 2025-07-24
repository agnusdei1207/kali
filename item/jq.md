jq 설치 및 사용법을 간단히 정리하면 다음과 같습니다.

---

### 1. 설치

```bash
sudo apt update
sudo apt install jq
```

---

### 2. 기본 사용법

- json 파일 보기

```bash
cat ffuf.txt | jq
```

- JSON 파일에서 특정 키 값 추출:

```bash
cat data.json | jq '.key'
```

- 여러 계층 접근:

```bash
jq '.user.name' data.json
```

- 배열에서 값 추출:

```bash
jq '.items[]' data.json
```

- 필터링:

```bash
jq '.[] | select(.age > 20)' data.json
```

- 여러 키 추출:

```bash
jq '{name: .name, email: .email}' data.json
```
