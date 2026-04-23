FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    openssh-server \
    python3 \
    rsyslog \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /var/run/sshd /opt/lab-target /etc/supervisor/conf.d

COPY lab/target/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY lab/target/sshd_config /etc/ssh/sshd_config
COPY lab/target/rsyslog-auth.conf /etc/rsyslog.d/10-auth.conf
COPY lab/target/nginx-default.conf /etc/nginx/sites-available/default
COPY lab/target/index.html /var/www/html/index.html
COPY lab/target/firewall_logger.py /opt/lab-target/firewall_logger.py
COPY lab/target/start.sh /opt/lab-target/start.sh

RUN chmod +x /opt/lab-target/start.sh

EXPOSE 22 80 2201 2202 2203 2204 2205 2206 2207 2208

CMD ["/opt/lab-target/start.sh"]
