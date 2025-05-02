# 컨테이너/이미지/네트워크/볼륨 이름 설정
CONTAINER_NAME=offensive-security
IMAGE_NAME=agnusdei1207/offensive-security:latest
NETWORK_NAME=offensive-net
VOLUME_NAME=offensive-vol

docker-run:
	docker run --platform linux/amd64 -d \
	--name=$(CONTAINER_NAME) \
	--network=$(NETWORK_NAME) \
	-v $(VOLUME_NAME):/data \
	$(IMAGE_NAME)

docker-stop:
	docker stop $(CONTAINER_NAME) || true

docker-rm:
	docker rm $(CONTAINER_NAME) || true

docker-rmi:
	docker rmi $(IMAGE_NAME) || true

docker-push:
	docker/offensive-security/push.sh

docker-exe:
	docker exec -it $(CONTAINER_NAME) bash

docker-net:
	docker network create $(NETWORK_NAME) || true

docker-net-rm:
	docker network rm $(NETWORK_NAME) || true

docker-vol:
	docker volume create $(VOLUME_NAME) || true

docker-vol-rm:
	docker volume rm $(VOLUME_NAME) || true

docker-refresh:
	make docker-stop
	make docker-rm
	make docker-rmi
	make docker-net-rm
	make docker-vol-rm
	make docker-push
	make docker-net
	make docker-vol
	make docker-run
