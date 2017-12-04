# kubernetes-ldap
[![Build Status](https://travis-ci.org/kismatic/kubernetes-ldap.svg?branch=master)](https://travis-ci.org/kismatic/kubernetes-ldap)
[![Go Report Card](https://goreportcard.com/badge/github.com/kismatic/kubernetes-ldap)](https://goreportcard.com/report/github.com/kismatic/kubernetes-ldap)
[![GoDoc](https://godoc.org/github.com/kismatic/kubernetes-ldap?status.svg)](https://godoc.org/github.com/kismatic/kubernetes-ldap)

Lightweight Directory Access Protocol (LDAP) for Kubernetes™

Getting Started
===============
This project provides an LDAP authentication webhook for Kubernetes. 
This version is meant to run inside your K8s Cluster, which is why it exposes two endpoints:
- <b>/authenticate</b>: Handles token authentication requests coming from Kubernetes API Server. Served via SSL on Port 8443.
- <b>/ldapAuth</b>: Issues token to be used when interacting with the Kubernetes API. Served w/out SSL on Port 8080 as it's meant
to be exposed via Ingress to the outside. 

The service will issue RSASSA-PSS (SHA512) signed tokens with a length of 4096 bits. The tokens have an expiry date of 12h
after which they will be invalidated by the server.


Pre-requisites
--------------
- Certificate and corresponding private key for the webhook server
- Certificate and corresponding private key for the Kubernetes webhook client

Starting the webhook server
----------------
Run the following to start the server
```
kubernetes-ldap --ldap-host ldap.example.com \
    --ldap-port 636
    --ldap-base-dn "DC=example,DC=com" \
    --tls-cert-file pathToCert (optional)\
    --tls-private-key-file pathToKey (optional)\
    --ldap-user-attribute userPrincipalName \
    --ldap-search-user-dn "OU=engineering,DC=example,DC=com" (optional) \
    --ldap-search-user-password pwd (optional) \
    --authn-tls-cert-file pathToCert \
    --authn-tls-private-key-file pathToKey
    
```

#### Environment Variables

| ENV        | Required? | Description           | 
|:-------------:|:-------------:|:-------------:|
|MY_NAMESPACE|no (default: default)|set to the namespace this service is running in|
|SIGNING_CERT_SECRET_NAME|no (default: ldap-signing-cert-secret)| Specifies the name of the secret which gets created




Deploying the Kubernetes LDAP Service
----------------------------------
Deploy the service into the kube-system namespace of your cluster:
```yaml
kind: Deployment
apiVersion: extensions/v1beta1
metadata:
  name: k8s-ldap
  namespace: kube-system
spec:
  replicas: 1
  template:
    metadata:
      labels:
        service: k8s-ldap
    spec:
      volumes:
        - name: authn-tls-secret
          secret:
            secretName: kubernetes-ldap-server-my-awesome-company
      containers:
      - name: icc-k8s-ldap
        image: <REGISTRY>/<IMAGE_NAME>:<TAG>
        args: ["--ldap-host", "ldap.example.com",
               "--ldap-port", "636",
               "--ldap-base-dn", "DC=example,DC=com",
               "--ldap-user-attribute", "userPrincipalName",
               "--ldap-search-user-dn", "$(SECRET_LDAP_USERNAME)",
               "--ldap-search-user-password", "$(SECRET_LDAP_PASSWORD)",
               "--authn-tls-cert-file", "/etc/kubernetes/ssl/tls.crt",
               "--authn-tls-private-key-file", "/etc/kubernetes/ssl/tls.key"]
        ports:
        - containerPort: 8080
        - containerPort: 8443
        resources:
          limits:
            cpu: 100m
            memory: 150Mi
          requests:
            cpu: 50m
            memory: 90Mi
        env:
        - name: SECRET_LDAP_USERNAME
          valueFrom:
            secretKeyRef:
              name: k8s-ldap-credentials
              key: username
        - name: SECRET_LDAP_PASSWORD
          valueFrom:
            secretKeyRef:
              name: k8s-ldap-credentials
              key: password
        volumeMounts:
          - name: authn-tls-secret
            mountPath: /etc/kubernetes/ssl
            readOnly: true
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10

```
And add a Service with a static cluster IP set:
```yaml
kind: Service
apiVersion: v1
metadata:
  name:  k8s-ldap
  namespace: kube-system
  labels:
    service:  k8s-ldap
spec:
  ports:
  -   name: http
      protocol: TCP
      port: 80
      targetPort: 8080
  -   name: https
      protocol: TCP
      port: 8443
      targetPort: 8443
  selector:
    service:  k8s-ldap
  clusterIP: 10.32.0.15
 
```
Finally expose the service's public endpoint to the world via Ingress (assumes nginx ingress):
```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: "nginx"
  name: kube-system-ingress
  namespace: kube-system
spec:
  tls:
  - hosts:
    - k8s-login.my-awesome-company.com
    secretName: k8s-login-my-awesome-company-com
  backend:
        serviceName: icc-k8s-ldap
        servicePort: http
  rules:
  - host: k8s-login.my-awesome-company.com
    http:
      paths:
      - path: /ldapAuth
        backend:
            serviceName: k8s-ldap
            servicePort: http
```

Configuring the Kubernetes Webhook
----------------------------------
Create a yaml file to define the webhook:
```yaml
# Docs here: https://kubernetes.io/docs/admin/authentication/#webhook-token-authentication
# clusters refers to the remote service.
clusters:
  - name: ldap-auth-webhook
    cluster:
      certificate-authority: /etc/kubernetes/ssl/ca.pem      # Cluster Root CA 
      server: https://10.32.0.15:8443/authenticate # URL of remote service to query. Must use 'https'. Set to static service IP

# users refers to the API Server's webhook configuration.
users:
  - name: ldap-auth-webhook-client
    user:
      client-certificate: /etc/kubernetes/ssl/kubernetes-ldap-client.pem  # cert for the webhook plugin to use
      client-key: /etc/kubernetes/ssl/kubernetes-ldap-client.key          # key matching the cert

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
AUTH_TOKEN=$(curl https://k8s-login.my-awesome-company.com/ldapAuth --user alice@example.com:password)
```
2. Store the auth token in `kubectl`'s configuration
```
kubectl config set-credentials alice --token=$AUTH_TOKEN
```
3. Start using `kubectl` with the authenticated user
```
kubectl -s="https://localhost:6443" --user=alice get nodes
```

## Project Status

Kubernetes LDAP is at an early stage and under active development. We do not recommend its use in production, but we encourage you to try out Kubernetes LDAP and provide feedback via issues and pull requests.

## Contributing to Kubernetes LDAP

Kubernetes LDAP is an open source project and contributors are welcome!
Join us on IRC at [#kismatic on freenode.net](http://webchat.freenode.net/?channels=%23kismatic&uio=d4), [file an issue](https://github.com/kismatic/kubernetes-ldap/issues) here on Github.

### Are you ready to add to the discussion?

We have presence on:

 * [Twitter](https://twitter.com/kismatic)

For Q&A, our threads are at:

 * [Stack Overflow](http://stackoverflow.com/questions/tagged/kismatic)
 * [Slack](http://slack.k6c.io/)


## Licensing

Unless otherwise noted, all code in the Kubernetes LDAP repository is licensed under the [Apache 2.0 license](LICENSE). Some portions of the codebase are derived from other projects under different licenses; the appropriate information can be found in the header of those source files, as applicable.
