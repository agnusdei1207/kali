
docker-exec:
	docker exec -it offensive-security /bin/bash
	
docker-push:
	docker/offensive-security/push.sh

install-vpn:
	make docker-exec
	apt update
	apt -y install kali-linux-headless
