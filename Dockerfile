FROM alpine

MAINTAINER christian.huening@haw-hamburg.de

# K8s LDAP Connector runs on 8080
EXPOSE 8080

ADD cert /app/cert/
ADD icc-k8s-ldap /app/

WORKDIR /app

ENTRYPOINT ["./icc-k8s-ldap"]