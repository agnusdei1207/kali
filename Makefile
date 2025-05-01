docker-run:
	docker run --platform linux/amd64 -d --name=offensive-security agnusdei1207/offensive-security:latest
docker-push:
	docker/offensive-security/push.sh
docker-exe:
	docker exec -it offensive-security bash
