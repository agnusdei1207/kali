# docker install

> 무엇: Ubuntu 계열에 Docker Engine(docker-ce)과 Compose 플러그인을 공식 apt 저장소로 설치하는 절차 문서다. 구버전 제거 → 필수 패키지 → GPG 키 추가 → 저장소 등록 → 설치 → 확인 순서다.
> 언제: Docker가 없는 호스트에서 compose로 Kali 실습 이미지를 띄우기 전, 실습 환경(lab-setup)을 새로 구성할 때 쓴다.
> 조건: sudo 권한과 download.docker.com 접근이 필요하다(우분투 계열, lsb_release로 codename 지정). sudo 없이 쓰려면 `usermod -aG docker $USER` 후 재로그인 또는 newgrp docker가 필요하다.

## 1. 기존 Docker 패키지 제거

```bash
sudo apt remove docker docker-engine docker.io containerd runc
```

---

## 2. 필수 패키지 설치

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release
```

---

## 3. Docker GPG 키 추가

```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
```

---

## 4. Docker APT 저장소 등록

```bash
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

---

## 5. 패키지 목록 갱신

```bash
sudo apt update
```

---

## 6. Docker 및 Compose 플러그인 설치

```bash
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

---

## 7. 설치 확인

### Docker 버전:

```bash
docker --version
```

### Docker Compose 플러그인 버전:

```bash
docker compose version
```

---

## 8. (선택) sudo 없이 Docker 사용

```bash
sudo usermod -aG docker $USER
```

변경 적용을 위해 로그아웃 후 재로그인하거나 다음 명령어 사용:

```bash
newgrp docker
```

---
