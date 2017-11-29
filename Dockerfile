FROM golang:1.9-stretch

ADD . /go/src/github.com/apprenda-kismatic/kubernetes-ldap
WORKDIR /go/src/github.com/apprenda-kismatic/kubernetes-ldap

EXPOSE 4000
RUN make build
ENTRYPOINT ./bin/kubernetes-ldap
