# Hot-Reload

mcp-policy-guard watches the policy file for changes and reloads automatically. No restart needed.

## How it works

A file watcher (fsnotify) monitors the policy file. When a change is detected:

1. The new file is loaded and validated against the JSON Schema
2. If validation passes, the policy engine swaps to the new rules atomically
3. In-flight requests complete under the old policy; new requests use the new policy

## Regular files

Save the file. The watcher detects the `WRITE` event and reloads.

```
level=INFO msg="policy file changed, reloading" path=policy.yaml event=WRITE
level=INFO msg="policy reloaded" rules=5
```

## Kubernetes ConfigMap mounts

Kubernetes updates ConfigMap-mounted volumes by replacing the `..data` symlink target rather than modifying files in place. The watcher detects the `CREATE` event on the new symlink.

This means you can update the policy by editing the ConfigMap:

```bash
kubectl edit configmap agent-policy
```

or applying a new version:

```bash
kubectl apply -f updated-policy-configmap.yaml
```

The sidecar picks up the change within seconds.

## What reloads on the fly

- Rules (add, remove, reorder, change actions)
- Defaults (action, deny message, audit flag)
- Rate limit parameters (requests, window, keys)
- Content filter patterns and actions
- Escalation trigger configuration

## What requires a restart

- Audit emitters (adding/removing output targets like file, webhook, OTel)
- Approval channels (adding new channel types)
- Rate limit backend (switching between in-memory and Redis)
- Transport mode (stdio, stdio-to-HTTP, HTTP proxy)
- TLS configuration (certificates, CA)

These are constructed once at startup from the initial policy and CLI flags.

## Validation on reload

If the new policy file fails validation (schema error, semantic error), the reload is rejected and the previous policy remains in effect:

```
level=ERROR msg="failed to reload policy" error="policy schema validation: ..."
```

The proxy continues operating normally with the last valid policy.
