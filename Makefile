DOCKER_IMAGE=oscp

docker-exec:
	docker exec -it $(DOCKER_IMAGE) /bin/bash

docker-push:
	docker/$(DOCKER_IMAGE)/push.sh

docker-vpn:
	docker exec -it $(DOCKER_IMAGE) /bin/bash -c "openvpn --config *.ovpn --daemon"

ssh:
	ssh -i test.pem ubuntu@216.47.96.64
setting-vpn:
	scp -i test.pem ubuntu@216.47.96.34:/etc/openvpn/client1.ovpn .
cp-vpn:
	docker cp client1.ovpn $(DOCKER_IMAGE):/client1.ovpn
