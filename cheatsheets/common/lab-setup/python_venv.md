# 파이썬 가상환경(venv) 실전 치트시트

## 목적

- OSCP 시험장 등에서 impacket 등 파이썬 도구 설치/실행 시, 시스템 환경 오염 없이 독립적으로 패키지 관리 및 실행.
- 여러 버전/패키지 충돌 방지, 실습 환경 분리.

## 주요 명령어 및 옵션

### 1. 가상환경 생성

```bash
apt install python3
apt install python3-venv

python3 -m venv <디렉토리명>
```

- **필수**: O
- **파라미터**: 디렉토리명 (예: `impacket-env`, `test`)

### 2. 가상환경 활성화

```bash
source <디렉토리명>/bin/activate
```

- **필수**: O
- **파라미터**: 디렉토리명

### 3. 가상환경 비활성화(종료)

```bash
deactivate
```

- **필수**: O
- **파라미터**: 없음

### 4. pip 최신화

```bash
pip install --upgrade pip
```

- **필수**: O
- **파라미터**: 없음

### 5. 패키지 설치

```bash
pip install <패키지명>
pip install -r requirements.txt   # requirements.txt 파일 내 패키지 일괄 설치
pip install .                    # 현재 디렉토리(소스) 설치 (setup.py/pyproject.toml 필요)
```

- **필수**: O
- **파라미터**: 패키지명, 파일명(`.txt`), 디렉토리(`.`)

### 6. 설치된 패키지 목록 확인

```bash
pip list
```

- **필수**: X
- **파라미터**: 없음

### 7. 가상환경 삭제

```bash
rm -rf <디렉토리명>
```

- **필수**: O
- **파라미터**: 디렉토리명

---

## 실전 사용 예시 (impacket 설치)

```bash
# 1. impacket 소스 다운로드
git clone https://github.com/fortra/impacket.git
cd impacket

# 2. 가상환경 생성 및 활성화
python3 -m venv test
source test/bin/activate

# 3. pip 최신화 및 impacket 설치
pip install --upgrade pip
pip install .

# 4. impacket 예제 실행
python examples/secretsdump.py -h

# 5. 작업 종료 시
deactivate
```

---

## 언제 사용하는가?

- OSCP 시험장, 실습 환경에서 파이썬 기반 공격/분석 도구 설치 시
- 시스템 전체에 영향 없이 독립적으로 패키지 관리 필요할 때
- 여러 프로젝트/도구별로 환경 분리 필요할 때

---

## 프롬프트 해석

- `(test)` : 현재 활성화된 가상환경 이름
- `[impenv]` : 현재 작업 중인 디렉토리 경로 (`pwd`로 확인)
- `deactivate` 입력 시 `(test)` 사라짐 → 시스템 기본 쉘로 복귀

---

## 주의사항

- `pip install .` 명령은 반드시 `setup.py` 또는 `pyproject.toml`이 있는 소스 디렉토리에서 실행
- 오타 주의: `deactivate` (정확히 입력)
- 가상환경 내에서만 설치된 패키지 사용 가능

---

## 핵심만 요약

- 가상환경 생성/활성화/종료: `python3 -m venv`, `source .../activate`, `deactivate`
- 패키지 설치: `pip install <패키지명>` 또는 `pip install .`
- impacket 등 OSCP 실전 도구 설치/실행 시
