# k8s-dashboard-auth-proxy

This is an reverse authentication proxy for Kubernetes dashboard hosted in managed **VMware Tanzu** clusters.

## How To Use

You can start by downloading the official kubernetes dashboard YAML
```
curl -LO https://raw.githubusercontent.com/kubernetes/dashboard/master/aio/deploy/recommended.yaml
```

### Change dashboard container args

In the *kubernetes-dashboard* deployment definition you have to replace the args of the *kubernetes-dashboard* container
```
          args:
            - --auto-generate-certificates
            - --namespace=kubernetes-dashboard
```
by
```
            - --namespace=kubernetes-dashboard
            - --insecure-port=9090
            - --insecure-bind-address=127.0.0.1
            - --enable-insecure-login
```

### Add proxy container

In the *kubernetes-dashboard* deployment definition you have to add the *proxy* container (update your supervisor address and guest cluster name):

```
        - args:
            - -login-url=https://supervisor.yourvcenter.fr/wcp/login
            - -guest-cluster-name=your-guest-cluster
          image: ouestfrance/k8s-dashboard-auth-proxy:0.2.0
          imagePullPolicy: Always
          name: proxy
          ports:
            - containerPort: 8080
              protocol: TCP
```

### Update service

In the *kubernetes-dashboard* service definition you have to replace ports
```
  ports:
    - port: 443
      targetPort: 8443
```
by
```
  ports:
    - port: 80
      targetPort: 8080
```

### Add ingress

To access the protected dashboard you have expose the *kubernetes-dashboard* service by adding an ingress definition (replace URL and TLS secret):
```
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: kubernetes-dashboard
  labels:
    app: kubernetes-dashboard
  annotations:
    ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
    - hosts:
        - dashbaord.yourguestcluster.com
      secretName: yourTLSsecret
  rules:
    - host: dashbaord.yourguestcluster.com
      http:
        paths:
          - path: /
            backend:
              serviceName: kubernetes-dashboard
              servicePort: 80
```
