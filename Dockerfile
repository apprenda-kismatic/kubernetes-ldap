FROM alpine

MAINTAINER christian.huening@haw-hamburg.de

# K8s LDAP Connector runs on 8080
EXPOSE 8080

ENV DOCKER_HOST=unix:///host/run/docker.sock
ENV DOCKER_API_VERSION=1.24

ADD ./TI-DepRootCert.pem /app/
ADD ./icc-k8s-ldap /app/

WORKDIR /app

CMD ["./icc-k8s-ldap"]