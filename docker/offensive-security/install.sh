#!/bin/bash

apt-get update && \
    apt-get install -y --fix-missing \
    openvpn \
    iputils-ping \
    netcat-openbsd \
    nmap \
    openssh-client \
    procps \
    psmisc \
	vim	\
	net-tools \
	tmux