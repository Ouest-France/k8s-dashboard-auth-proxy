FROM alpine AS certs

FROM scratch

# Import CA certificates
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy compiled static binary
COPY k8s-dashboard-auth-proxy /k8s-dashboard-auth-proxy

# Expose default port
EXPOSE 8443

ENTRYPOINT ["/k8s-dashboard-auth-proxy"]