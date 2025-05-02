REMOTE_IP=216.47.98.191
REMOTE_USERNAME=ubuntu

docker-exec:
	docker exec -it offensive-security /bin/bash
	
docker-push:
	docker/offensive-security/push.sh

install-vpn:
	make docker-exec
	apt update
	apt -y install kali-linux-headless

ssh:
	ssh -i test.pem $(REMOTE_USERNAME)@$(REMOTE_IP)
scp:
	scp -i test.pem docker/common/provisioning.sh $(REMOTE_USERNAME)@$(REMOTE_IP):/home/$(REMOTE_USERNAME)/
provisioning: 
	ssh -i test.pem $(REMOTE_USERNAME)@$(REMOTE_IP) 'bash /home/$(REMOTE_USERNAME)/provisioning.sh'