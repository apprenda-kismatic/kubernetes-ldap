# kubernetes-ldap
[![Build Status](https://travis-ci.org/kismatic/kubernetes-ldap.svg?branch=master)](https://travis-ci.org/kismatic/kubernetes-ldap)
[![Go Report Card](https://goreportcard.com/badge/github.com/kismatic/kubernetes-ldap)](https://goreportcard.com/report/github.com/kismatic/kubernetes-ldap)
[![GoDoc](https://godoc.org/github.com/kismatic/kubernetes-ldap?status.svg)](https://godoc.org/github.com/kismatic/kubernetes-ldap)

Lightweight Directory Access Protocol (LDAP) for Kubernetes™

Getting Started
===============
This project provides an LDAP authentication webhook for Kubernetes. 
The current implementation exposes two endpoints:
- /authenticate: Handles token authentication requests coming from Kubernetes
- /ldapAuth: Issues token to be used when interacting with the Kubernetes API

Pre-requisites
--------------
- Certificate and corresponding private key for the webhook server
- Certificate and corresponding private key for the Kubernetes webhook client

Starting the webhook server
----------------
Run the following to start the server
```
kubernetes-ldap --ldap-host ldap.example.com \
    --ldap-base-dn "DC=example,DC=com" \
    --tls-cert-file pathToCert \
    --tls-private-key-file pathToKey \
    --ldap-user-attribute userPrincipalName \
    --ldap-search-user-dn "OU=engineering,DC=example,DC=com" (optional) \
    --ldap-search-user-password pwd (optional)
```

Configuring the Kubernetes Webhook
----------------------------------
Create a yaml file to define the webhook:
```
# clusters refers to the remote service.
clusters:
  - name: ldap-auth-webhook
    cluster:
      certificate-authority: ~/ldap.example.com.cert      # CA for verifying the remote service.
      server: https://ldap-webhook:4000/authenticate # URL of remote service to query. Must use 'https'.

# users refers to the API Server's webhook configuration.
users:
  - name: ldap-auth-webhook-client
    user:
      client-certificate: ~/k8s-webhook-client.cert # cert for the webhook plugin to use
      client-key: ~/k8s-webhook-client.key          # key matching the cert

# kubeconfig files require a context. Provide one for the API Server.
current-context: webhook
contexts:
- context:
    cluster: ldap-auth-webhook
    user: ldap-auth-webhook-client
  name: webhook
```

Set the following flags to configure the authentication webhook when starting the Kubernetes API Server:
```
--authentication-token-webhook-cache-ttl=30m0s # Set appropriate cache TTL 
--authentication-token-webhook-config-file=/root/webhook-config.yaml # Path to file where the webhook is defined
```

Authenticating and using `kubectl`
---------------------------------
Once the webhook and API servers are running, we are ready to authenticate using LDAP.

1. Obtain an authentication token from the webhook server
```
AUTH_TOKEN=$(curl https://ldap-webhook:4000/ldapAuth --user alice@example.com:password)
```
2. Store the auth token in `kubectl`'s configuration
```
kubectl config set-credentials alice --token=$AUTH_TOKEN
```
3. Start using `kubectl` with the authenticated user
```
kubectl -s="https://localhost:6443" --user=alice get nodes
```

## Contributing to Kubernetes LDAP

Kubernetes LDAP is an open source project and contributors are welcome!
Join us on IRC at [#kismatic on freenode.net](http://webchat.freenode.net/?channels=%23kismatic&uio=d4), [file an issue](https://github.com/kismatic/kubernetes-ldap/issues) here on Github.

## Licensing

Unless otherwise noted, all code in the Kubernetes LDAP repository is licensed under the [Apache 2.0 license](LICENSE). Some portions of the codebase are derived from other projects under different licenses; the appropriate information can be found in the header of those source files, as applicable.
