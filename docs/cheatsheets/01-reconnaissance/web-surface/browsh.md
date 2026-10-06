```bash
sudo apt update
sudo apt install firefox-esr
```

```bash
wget https://github.com/browsh-org/browsh/releases/download/v1.8.0/browsh_1.8.0_linux_amd64.deb
sudo apt install ./browsh_1.8.0_linux_amd64.deb
```

- `.deb` 포맷으로 간단하게 배포 설치 가능 ([Browsh][1], [Ask Ubuntu][3])
- 설치 중 의존성 깨짐 발생 시:

  ```bash
  sudo apt --fix-broken install
  ```

설치 후 `.deb` 파일은 정리:

```bash
rm browsh_1.8.0_linux_amd64.deb
```

---

## 🔁 3. 실행 테스트

터미널에서:

```bash
browsh
```

정상 실행되면, Firefox를 백그라운드에서 헤드리스(headless) 모드로 시작한 후, TTY 기반 브라우징 환경이 실행됩니다 ([Ubunlog][4]).

### 키보드 입력 문제 해결

키보드 입력이 작동하지 않는 경우:

```bash
# 터미널 세션 문제 해결
TERM=xterm-256color browsh

# 또는 다른 방식 시도
export TERM=xterm-256color
browsh

```

특정 터미널에서 키 입력 인식 문제가 발생할 수 있으며, `TERM` 환경변수 설정으로 해결되는 경우가 많습니다.

---

## 🖥 4. 사용 방법 & 키 바인딩

- URL 입력: `Ctrl + l` 또는 `g`
- 링크 클릭/선택: `Tab` / `Enter`
- 스크롤: `↓` / `j`, `↑` / `k`
- 탭 열기: `Ctrl + t`
- 탭 닫기: `Ctrl + w`
- 페이지 새로고침: `Ctrl + r`
- 뒤로 가기: `Backspace` or `h`
- 종료: `Ctrl + q`
- 기타 기능

  - 스크린샷: `Alt + Shift + p`
  - 흑백 토글: `Alt + m`
  - User-Agent 토글: `Alt + u` ([LFCS 인증서 준비 eBook][5], [CONNECTwww.com][6])

## 🛠 5. 대안: Static Binary 또는 Docker 방식

### A. Static 실행 파일 (.bin)

```bash
wget https://github.com/browsh-org/browsh/releases/download/v1.8.0/browsh_1.8.0_linux_amd64
chmod a+x browsh_1.8.0_linux_amd64
./browsh_1.8.0_linux_amd64
sudo apt install firefox-esr
```

→ `.deb` 없이도 실행 가능 ([Ubunlog][4])

### B. Docker

```bash
docker pull browsh/browsh
docker run --rm -it browsh/browsh
```

→ Firefox 포함, 컨테이너 기반으로 즉시 실행 가능 ([SSD Nodes][7])

---

## ⚙️ 6. 문제 해결 팁

- `A headless Firefox is already running` 오류
  → 이전 인스턴스가 제대로 종료되지 않았을 수 있음.
  종료 후 재실행하거나 프로세스 확인 후 수동 종료 ([GitHub][8]).
- 터미널 색상 지원 문제
  → True colour 미지원 터미널에서는 이미지/그래픽이 깨질 수 있음 ([Browsh][9]).

---
