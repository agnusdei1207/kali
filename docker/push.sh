#!/bin/bash

# 변수 설정
IMAGE_NAME="kali"
DOCKER_VOLUME="$IMAGE_NAME-volume"
TAG="latest"
DOCKER_USERNAME="agnusdei1207"
DOCKER_IMAGE="$DOCKER_USERNAME/$IMAGE_NAME:$TAG"
DOCKERFILE="docker/Dockerfile.kali"

OS=$(uname -s)
echo "🖥️ 현재 OS: $OS"

echo "🗑️ 이전 이미지 삭제 중..."
docker rmi -f $DOCKER_IMAGE 2>/dev/null || true

echo "🗑️ 이전 볼륨 삭제 중..."
docker volume rm -f $DOCKER_VOLUME 2>/dev/null || true

echo "🔨 이미지 빌드 중..."
if [ ! -f $DOCKERFILE ]; then
    echo "❌ $DOCKERFILE 파일을 찾을 수 없습니다."
    exit 1
fi

# 빌드 컨텍스트는 docker/ (Dockerfile과 keyring 위치)
docker build --progress=auto --platform linux/amd64 -t $DOCKER_IMAGE -f $DOCKERFILE docker/ --no-cache || { echo "❌ 빌드 실패"; exit 1; }

IMAGE_SIZE=$(docker images $DOCKER_IMAGE --format "{{.Size}}")
HUMAN_READABLE_SIZE=$(echo $IMAGE_SIZE | numfmt --to=iec)

echo "📏 이미지 사이즈: $HUMAN_READABLE_SIZE"

echo "📤 이미지 푸시 중..."
docker push $DOCKER_IMAGE || { echo "❌ 푸시 실패"; exit 1; }

echo "✅ 이미지가 성공적으로 푸시되었습니다: $DOCKER_IMAGE"
