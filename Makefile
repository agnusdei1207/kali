docker-run:
	docker run -d --progress=auto --platform linux/amd64 -t agnusdei1207:offensive-security:latest
docker-push:
	docker/offensive-security/push.sh