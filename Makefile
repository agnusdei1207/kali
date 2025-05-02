
docker-exec:
	docker exec -it offensive-security /bin/bash
	
docker-push:
	docker/offensive-security/push.sh

install-vpn:
	make docker-exec
	apt update
	apt -y install kali-linux-headless

ssh:
	ssh -i test.pem ubuntu@216.47.98.191

provisioning: 
	ssh -i test.pem ubuntu@216.47.98.191 'bash docker/common/provisioning.sh'