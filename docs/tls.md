# TLS and mTLS

When the upstream MCP endpoint uses HTTPS, mcp-policy-guard can be configured with client certificates for mutual TLS (mTLS) and custom CA certificates.

## Flags

```
--tls-cert <path>      Client certificate PEM file
--tls-key <path>       Client private key PEM file
--tls-ca <path>        CA certificate PEM to verify the upstream server
--tls-insecure         Skip upstream TLS verification (development only)
```

## mTLS to upstream

When the upstream requires client certificate authentication:

```bash
mcp-policy-guard \
  --policy policy.yaml \
  --upstream https://mcp-gateway.internal:8443/mcp \
  --tls-cert /etc/certs/client.pem \
  --tls-key /etc/certs/client-key.pem
```

## Custom CA

When the upstream uses a private CA not in the system trust store:

```bash
mcp-policy-guard \
  --policy policy.yaml \
  --upstream https://mcp-gateway.internal:8443/mcp \
  --tls-ca /etc/certs/ca.pem
```

## Both (mTLS + custom CA)

```bash
mcp-policy-guard \
  --policy policy.yaml \
  --upstream https://mcp-gateway.internal:8443/mcp \
  --tls-cert /etc/certs/client.pem \
  --tls-key /etc/certs/client-key.pem \
  --tls-ca /etc/certs/ca.pem
```

## Kubernetes deployment

Mount certificates from Secrets:

```yaml
containers:
  - name: policy-guard
    args:
      - --policy=/etc/policy/policy.yaml
      - --upstream=https://mcp-gateway:8443/mcp
      - --listen=:8081
      - --tls-cert=/etc/certs/tls.crt
      - --tls-key=/etc/certs/tls.key
      - --tls-ca=/etc/certs/ca.crt
    volumeMounts:
      - name: certs
        mountPath: /etc/certs
        readOnly: true
      - name: policy
        mountPath: /etc/policy

volumes:
  - name: certs
    secret:
      secretName: policy-guard-mtls
  - name: policy
    configMap:
      name: agent-policy
```

## Scope

The TLS configuration applies to all outbound HTTP connections:
- Upstream MCP server (stdio-to-HTTP bridge and HTTP proxy modes)

It does not apply to:
- Webhook approval endpoints (these use their own TLS from the system trust store)
- Escalation webhook endpoints
- Audit webhook endpoints

If you need mTLS for those endpoints, configure them at the network/service mesh level.

## Skip verification

For development environments with self-signed certificates:

```bash
mcp-policy-guard \
  --policy policy.yaml \
  --upstream https://localhost:8443/mcp \
  --tls-insecure
```

Do not use `--tls-insecure` in production.
