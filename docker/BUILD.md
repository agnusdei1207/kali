# Kali 이미지 빌드 & 푸시

## 이미지 정보

- 이미지: `agnusdei1207/kali:latest`
- Dockerfile: `docker/Dockerfile.kali`
- 볼륨: `kali-volume`

## 빌드 + 푸시 (이미지 내용 수정 시에만)

저장소 루트에서 실행:

```bash
bash docker/push.sh
```

이전 이미지/볼륨 삭제 → 빌드 → 푸시까지 수행. 중간에 실패하면 거기서 중단됨.

### 수동 명령어

```bash
# 빌드 (루트에서 실행, 컨텍스트는 docker/)
docker build --platform linux/amd64 -t agnusdei1207/kali:latest -f docker/Dockerfile.kali docker/ --no-cache

# 푸시
docker push agnusdei1207/kali:latest
```

## 매일 쓰는 컨테이너 명령어 (Docker Hub에서 pull 받아 씀)

```bash
docker compose pull           # 최신 이미지로 갱신
docker compose up -d          # 실행 (로컬에 없으면 자동 pull)
docker exec -it kali bash     # 진입
docker compose stop           # 정지 (볼륨 유지)
docker compose down           # 정지 + 컨테이너 삭제 (볼륨은 유지)
```

흐름: 도구 추가/변경은 Dockerfile 수정 → `push.sh` → 다른 곳에선 `docker compose pull`로 최신본 수신.

## 초기화

```bash
docker rmi -f agnusdei1207/kali:latest
docker volume rm -f kali-volume
```
