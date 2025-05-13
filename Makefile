DOCKER_IMAGE=offensive-security

docker-exec:
	docker exec -it $(DOCKER_IMAGE) /bin/bash

docker-push:
	docker/$(DOCKER_IMAGE)/push.sh

docker-vpn:
	docker exec -it $(DOCKER_IMAGE) /bin/bash -c "openvpn --config *.ovpn --daemon"

ssh:
	ssh -i test.pem ubuntu@216.47.96.64