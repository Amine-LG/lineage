"""Image page view models."""

from ... import engine
from ..buckets import image_page_bucket_counts

def images_context(args):
    idx = engine.index()
    inventory = engine.image_inventory(idx)
    registries = engine.registry_summary(inventory)
    streams = engine.imagestream_usage(idx)
    drift = engine.image_drift(idx)

    bucket = args.get("bucket", "yours")
    image_counts = image_page_bucket_counts(inventory, streams)
    if bucket == "yours":
        inventory_filtered = [i for i in inventory if i.get("user_used")]
        registries_filtered = [r for r in registries if r.get("user_used")]
        streams_filtered = [s for s in streams if not s.get("baseline")
                              and not s.get("unknown")]
        drift_filtered = [d for d in drift if d.get("user_used")]
    elif bucket == "unknown":
        inventory_filtered = [i for i in inventory if i.get("unknown_used")
                                and not i.get("user_used")
                                and not i.get("baseline_used")]
        registries_filtered = [r for r in registries if r.get("unknown_used")
                                 and not r.get("user_used")
                                 and not r.get("baseline_used")]
        streams_filtered = [s for s in streams if s.get("unknown")]
        drift_filtered = [d for d in drift if d.get("unknown_used")
                            and not d.get("user_used")]
    elif bucket == "baseline":
        inventory_filtered = [i for i in inventory if i.get("baseline_used")]
        registries_filtered = [r for r in registries if r.get("baseline_used")]
        streams_filtered = [s for s in streams if s.get("baseline")]
        drift_filtered = [d for d in drift if d.get("baseline_used")]
    else:
        inventory_filtered = inventory
        registries_filtered = registries
        streams_filtered = streams
        drift_filtered = drift

    q = (args.get("q") or "").strip().lower()
    if q:
        inventory_filtered = [i for i in inventory_filtered
                              if q in i["image"].lower()
                              or q in i["registry"].lower()]

    return {
        "inventory": inventory_filtered,
        "registries": registries_filtered,
        "streams": streams_filtered,
        "drift": drift_filtered,
        "bucket": bucket,
        "counts": image_counts,
        "total_count": len(inventory),
        "total_registries": len(registries),
        "total_streams": len(streams),
        "total_drift": len(drift),
        "q": q,
    }

def image_detail_context(ref):
    idx = engine.index()
    image = next((row for row in engine.image_inventory(idx)
                  if row["image"] == ref), None)
    if image is None:
        return None
    pods = sorted(image["pods"],
                  key=lambda p: (p["baseline_ns"], p["namespace"] or "",
                                 p["name"] or "", p["container"] or ""))
    return {
        "image": image,
        "pods": pods,
        "namespaces": sorted({p["namespace"] for p in pods
                              if p.get("namespace")}),
        "ns_summary": engine.image_pods_by_namespace(pods),
        "imagestream": engine.imagestream_for_image(ref, idx),
        "digest_siblings": engine.digest_siblings_for_image(ref, idx),
    }
