docker-build:
	docker build --progress=auto --platform linux/amd64 -t agnusdei1207:offensive-security:latest -f docker/Dockerfile . --no-cache
