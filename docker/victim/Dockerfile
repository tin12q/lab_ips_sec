FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server apache2 php php-mysql mysql-server \
    iproute2 net-tools curl wget git \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /var/run/sshd

COPY init-dvwa.sh /usr/local/bin/init-dvwa.sh
RUN chmod +x /usr/local/bin/init-dvwa.sh

CMD ["/bin/bash", "-lc", "service mysql start && service apache2 start && service ssh start && ip route del default 2>/dev/null || true && ip route add default via 172.21.0.2 || true && /usr/local/bin/init-dvwa.sh && tail -f /dev/null"]
