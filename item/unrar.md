## 🔹 1. Linux / macOS 환경

### (1) `unrar` 사용

먼저 설치 (Ubuntu 기준):

```bash
sudo apt update
sudo apt install unrar
```

압축 해제:

```bash
unrar x archive.rar
```

- `x` 옵션: 원래의 디렉터리 구조 보존하여 압축 해제

파일 목록만 보고 싶으면:

```bash
unrar l archive.rar
```

비밀번호 걸린 경우:

```bash
unrar x archive.rar
# 비밀번호 입력 요청됨
```

---

### (2) `7zip (p7zip)` 사용

설치:

```bash
sudo apt install p7zip-full
```

압축 해제:

```bash
7z x archive.rar
```

---

## 🔹 2. Windows 환경

- **WinRAR** (공식 프로그램, 유료/체험판) → `.rar` 파일 생성 및 해제 가능
- **7-Zip** (무료, 오픈소스) → `.rar` 해제 가능 (생성은 불가)

  - 설치 후: 압축 파일 우클릭 → `7-Zip` → `Extract Here` 또는 `Extract to folder/`

---

## 🔹 3. macOS GUI 환경

- **The Unarchiver** (무료 앱) → `.rar` 파일 해제 지원
- **Keka** → macOS에서 많이 쓰는 무료 압축 프로그램

---

✅ 요약:

- **Linux/CLI** → `unrar x archive.rar` 또는 `7z x archive.rar`
- **Windows** → WinRAR 또는 7-Zip
- **macOS** → The Unarchiver, Keka
