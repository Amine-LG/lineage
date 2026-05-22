# Performance

Lineage v1 favors simple, auditable reads over a complex client.

## Cache

A live refresh performs a small set of `oc get ... -o json` calls and
builds an in-memory index. Results are cached for 5 minutes.

```text
CACHE_TTL_SECONDS = 300
```

Use **Refresh** when you need a fresh view.

## In-Cluster Resources

The Deployment ships with modest requests and limits for CRC-sized labs.
For larger clusters, tune with normal OpenShift controls:

```bash
oc set resources deploy/lineage -n lineage-incluster \
  --requests=cpu=<n>,memory=<m> \
  --limits=cpu=<n>,memory=<m>
```

## V1 Notes

- Cold refresh time is mostly `oc` round trips.
- Warm page loads reuse the cached index.
- Concurrent fetching and Kubernetes Python client support are not v1
  goals.
