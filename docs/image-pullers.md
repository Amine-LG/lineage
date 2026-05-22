# Image Puller And Builder Grants

OpenShift uses two ClusterRoles for internal registry access:

| ClusterRole | Meaning |
| --- | --- |
| `system:image-puller` | can pull images from a namespace |
| `system:image-builder` | can push image layers into a namespace |

Default project bindings are common and usually not interesting. Lineage
focuses on grants that look manually added or cross-namespace.

## What To Review

- A ServiceAccount from namespace A can pull images from namespace B.
- A ServiceAccount from namespace A can push into namespace B.
- A User or Group has image puller/builder access.
- Image drift appears for a mutable tag used by running pods.

The risky case is usually `system:image-builder`: pushing into another
namespace can change what other workloads later run.

## Where To Look

- `/cross-namespace` for image-puller and image-builder grants.
- `/images` for running images, registries, ImageStreams, and drift.
- `/subject/ServiceAccount/<name>?namespace=<ns>` for bindings that
  reference a specific ServiceAccount.
