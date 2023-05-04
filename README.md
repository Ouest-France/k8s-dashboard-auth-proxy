# k8s-dashboard-auth-proxy

This is an reverse authentication proxy for Kubernetes dashboard hosted in **AWS** or **VMware Tanzu** clusters.

## How it works

### AWS ADFS

When you enter your credentials on the login page, a call to ADFS idp initiated login-on page is done with them, and the SAML response is captured. This SAML response is then used to authenticate to AWS and get temporary credentials. After the role selection, those temporary credentials are used to issue an "assume role" request that returns a new set of temporary credentials. Those assume role credentials are finally used to create a Kubernetes token that is stored in one or more cookies (token is splitted if too large > 4000Bytes) and redirect to the dashboard.

If there is no token or your token is expired you are automaticaly redirected to login page.

### Tanzu

When you enter your credentials on the login page, a basic auth request is sent to the supervisor WCP. If credentials are valid the supervisor WCP returns back a JWT token. This proxy stores this JWT token in one or more cookies (token is splitted if too large > 4000Bytes) and redirect to the dashboard.

If there is no token or your token is expired you are automaticaly redirected to login page.

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

* For **AWS-ADFS** - [docs for AWS-ADFS flags](#aws-adfs):
```
        - args:
            - -auth aws-adfs
            - -login-url https://fs.mycorp.org/adfs/ls/idpinitiatedsignon.aspx
            - -cluster-id my-k8s-cluster-id
          image: ouestfrance/k8s-dashboard-auth-proxy:0.3.0
          imagePullPolicy: Always
          name: proxy
          ports:
            - containerPort: 8080
              protocol: TCP
```

* For **Tanzu** ([docs for Tanzu flags](#tanzu)):
```
        - args:
            - -auth tanzu
            - -login-url=https://supervisor.mycorp.org/wcp/login
            - -guest-cluster-name=your-guest-cluster
          image: ouestfrance/k8s-dashboard-auth-proxy:0.3.0
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

## Flags

### AWS-ADFS

* ADFS authentication to AWS must be configured on the accounting hosting the Kubernetes cluster: [tutorial](https://aws.amazon.com/blogs/security/aws-federated-authentication-with-active-directory-federation-services-ad-fs/)
* aws-iam-authenticator must be configured in the Kubernetes cluster: [docs for kops](https://kops.sigs.k8s.io/authentication/#aws-iam-authenticator)
* ADFS must be configure to allow IDP initiated Sign-On: [docs](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-initiatedsignon)
* "--login-url" must match the ADFS IDP initiated Sign-On page, for an ADFS exposed on "fs.mycorp.org" the URL will be: "https://fs.mycorp.org/adfs/ls/idpinitiatedsignon.aspx"
* Dashboard URL can be localhost if the Dashboard is in the same deployment that the proxy, or can be an external name if hosted in another deployment
* "--cluster-id" must match the clusterID field of the aws-iam-authenticator configuration

```bash
  -auth aws-adfs \
  -login-url https://fs.mycorp.org/adfs/ls/idpinitiatedsignon.aspx \
  -dashboard-url http://127.0.0.1:9090/ \
  -cluster-id my-k8s-cluster-id
```

### Tanzu

* "--login-url" must match the supervisor address of the guest cluster where the dashboard is deployed, suffixed with "/wcp/login". For example: https://supervisor.mycorp.org/wcp/login
* "--tanzu-guest-cluster" must match the value of flag "--tanzu-kubernetes-cluster-name" when using "kubectl vsphere login" command
* Dashboard URL can be localhost if the Dashboard is in the same deployment that the proxy, or can be an external name if hosted in another deployment

```bash
  -auth tanzu \
  -login-url https://my-tanzu-login-url.com \
  -dashboard-url http://127.0.0.1:9090/ \
  -tanzu-guest-cluster my-tanzu-guest-cluster
```
