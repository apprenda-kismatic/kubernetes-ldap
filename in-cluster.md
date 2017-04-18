# In-cluster installation

These instructions will install kubernetes-ldap as a service in the cluster that it's providing authentication for.

## Prerequisites

- Kubernetes cluster with an ingress controller or external load balancer.
- A public DNS name, dedicated to this service, pointing to your ingress or LB.
- A public certificate matching the DNS name.
- A working Go environment, so you can compile this code.
- A Docker registry you can upload kubernetes-ldap to.

## Build the container

1. Clone this repo into `$GOCODE/src/github.com/kismatic/kubernetes-ldap`
2. `cd $GOCODE/src/github.com/kismatic/kubernetes-ldap`
3. `go build cmd/kubernetes-ldap.go`
4. `docker build -t kubernetes-ldap .`
5. Push the container to your Docker registry.

## Install in the cluster

1. (Optional) Create a secret to use for LDAP binding, if your LDAP server requires it.
    1. Get the DN and password of your LDAP service account. Put the DN in a file named `username` and the password
        in a file named `password`. **Make sure there is no trailing whitespace or newline.**
    2. `kubectl create secret generic --namespace=kube-system ldap-service-user --from-file=username --from-file=password`
2. Create a secret with your public TLS certificate and key. If you have an intermediate CA certificate, append it
    to your host's certificate before creating the secret in Kubernetes.
    ```
    kubectl create secret tls --namespace=kube-system kubernetes-ldap.example.com --cert=cert.pem --key=key.pem
    ```
3. Build a YAML file `kubernetes-ldap.yaml` for the deployment, service, and ingress. Here's a template.
    ```
    apiVersion: extensions/v1beta1
    kind: Deployment
    metadata:
      name: kubernetes-ldap
      namespace: kube-system
    spec:
      template:
        metadata:
          labels:
            app: kubernetes-ldap
        spec:
          containers:
            - image: your.docker.registry.com/kubernetes-ldap
              name: kubernetes-ldap
              args:
              - --ldap-host=ldap.example.com
              - --ldap-base-dn=ou=people,dc=example,dc=com
              - --ldap-user-attribute=sAMAccountName
              - --ldap-port=636
              - --ldap-search-user-dn=$(BIND_USERNAME)
              - --ldap-search-user-password=$(BIND_PASSWORD)
              - --logtostderr
              ports:
                - containerPort: 4000
              env:
                - name: BIND_USERNAME
                  valueFrom:
                    secretKeyRef:
                      name: ldap-service-user
                      key: username
                - name: BIND_PASSWORD
                  valueFrom:
                    secretKeyRef:
                      name: ldap-service-user
                      key: password
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: kubernetes-ldap
      namespace: kube-system
      labels:
        app: kubernetes-ldap
    spec:
      selector:
        app: kubernetes-ldap
      ports:
        - targetPort: 4000
          port: 4000
          protocol: TCP
    ---
    apiVersion: extensions/v1beta1
    kind: Ingress
    metadata:
      name: kubernetes-ldap
      namespace: kube-system
    spec:
      rules:
      - host: kubernetes-ldap.example.com
        http:
          paths:
          - backend:
              serviceName: kubernetes-ldap
              servicePort: 4000
            path: /
      tls:
      - hosts:
        - kubernetes-ldap.example.com
        secretName: kubernetes-ldap.example.com

    ```
4. `kubectl create -f kubernetes-ldap.yaml`

# Configure the Kubernetes webhook

See [README.md](README.md) for instructions.
