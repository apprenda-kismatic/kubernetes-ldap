# Builds an image for use running this service inside the cluster.
FROM debian

RUN apt-get update && apt-get install -y ca-certificates

COPY kubernetes-ldap /

EXPOSE 4000

ENTRYPOINT [ "/kubernetes-ldap" ]
