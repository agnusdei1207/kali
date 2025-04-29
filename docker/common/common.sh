#!/bin/bash

# 현재 OS 확인
OS=$(uname -s)
echo "🖥️ 현재 OS: $OS"

# 이전 빌드된 이미지가 있다면 삭제
echo "🗑️ 이전 이미지 삭제 중..."
docker rmi -f $DOCKER_IMAGE

# Docker 이미지 빌드
echo "🔨 이미지 빌드 중..."
if [ ! -f $DOCKERFILE ]; then
    echo "❌ $DOCKERFILE 파일을 찾을 수 없습니다."
    exit 1
fi

docker build --progress=auto --platform linux/amd64 -t $DOCKER_IMAGE -f $DOCKERFILE . --no-cache

# 빌드된 이미지 푸시
echo "📤 이미지 푸시 중..."
docker push $DOCKER_IMAGE

# 푸시 완료 후 메시지 출력
echo "✅ 이미지가 성공적으로 푸시되었습니다: $DOCKER_IMAGE"