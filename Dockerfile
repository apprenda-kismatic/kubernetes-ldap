FROM alpine:3.6

MAINTAINER christian.huening@haw-hamburg.de

# K8s LDAP Connector runs on 8080
EXPOSE 8080

RUN apk add --no-cache ca-certificates

ADD icc-k8s-ldap /app/

WORKDIR /app

ENTRYPOINT ["./icc-k8s-ldap"]