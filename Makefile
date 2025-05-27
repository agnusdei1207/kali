DOCKER_IMAGE=oscp
docker push:
	docker/$(DOCKER_IMAGE)/push.sh