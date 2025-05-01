docker-run:
	docker run --platform linux/amd64 -d --name=offensive-security agnusdei1207/offensive-security:latest
docker-stop:
	docker stop offensive-security
docker-rm:
	docker rm offensive-security
docker-rmi:
	docker rmi agnusdei1207/offensive-security:latest
docker-push:
	docker/offensive-security/push.sh
docker-exe:
	docker exec -it offensive-security bash
docker-refresh:
	make docker-stop
	make docker-rm
	make docker-rmi
	make docker-push
	make docker-run
