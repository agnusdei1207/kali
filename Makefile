REMOTE_IP=216.47.98.191
REMOTE_USERNAME=ubuntu
DOCKER_IMAGE=offensive-security

docker-exec:
	docker exec -it $(DOCKER_IMAGE) /bin/bash
	
docker-push:
	docker/$(DOCKER_IMAGE)/push.sh

install-vpn:
	make docker-exec
	apt update
	apt install -y kali-linux-headless iputils-ping netcat-openbsd openvpn

ssh:
	ssh -i test.pem $(REMOTE_USERNAME)@$(REMOTE_IP)
scp:
	scp -i test.pem docker/common/provisioning.sh $(REMOTE_USERNAME)@$(REMOTE_IP):/home/$(REMOTE_USERNAME)/
	scp -i test.pem docker-compose.yml $(REMOTE_USERNAME)@$(REMOTE_IP):/home/$(REMOTE_USERNAME)/
provisioning: 
	ssh -i test.pem $(REMOTE_USERNAME)@$(REMOTE_IP) 'bash /home/$(REMOTE_USERNAME)/provisioning.sh'