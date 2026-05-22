"""Shared bucket/count helpers for the Flask views."""


def bucket_filter(items, bucket, baseline_key="baseline",
                  unknown_key="unknown"):
    """Filter rows for the Yours / Unknown / Baseline / All toggle."""
    if bucket == "all":
        return list(items)
    if bucket == "baseline":
        return [i for i in items if i.get(baseline_key)]
    if bucket == "unknown":
        return [i for i in items if i.get(unknown_key)
                and not i.get(baseline_key)]
    return [i for i in items if not i.get(baseline_key)
            and not i.get(unknown_key)]


def bucket_counts(items, baseline_key="baseline", unknown_key="unknown"):
    """Per-bucket counts for the bucket-toggle UI."""
    yours = unknown = baseline = 0
    for item in items:
        if item.get(baseline_key):
            baseline += 1
        elif item.get(unknown_key):
            unknown += 1
        else:
            yours += 1
    return {"yours": yours, "unknown": unknown,
            "baseline": baseline, "all": yours + unknown + baseline}


def review_rows(items, baseline_key="baseline"):
    return [i for i in items if not i.get(baseline_key)]


def bucket_for_card(yours_count, unknown_count):
    if unknown_count and not yours_count:
        return "unknown"
    if yours_count and not unknown_count:
        return "yours"
    return "all" if unknown_count else "yours"


def namespace_category_for_card(project_count, unknown_count):
    if unknown_count and not project_count:
        return "unknown"
    if project_count and not unknown_count:
        return "project"
    return "all" if unknown_count else "project"


def image_page_bucket_counts(inventory, streams):
    image_yours = sum(1 for i in inventory if i.get("user_used"))
    image_unknown = sum(1 for i in inventory if i.get("unknown_used")
                        and not i.get("user_used")
                        and not i.get("baseline_used"))
    image_baseline = sum(1 for i in inventory if i.get("baseline_used"))
    stream_yours = sum(1 for s in streams
                       if not s.get("baseline") and not s.get("unknown"))
    stream_unknown = sum(1 for s in streams if s.get("unknown"))
    stream_baseline = sum(1 for s in streams if s.get("baseline"))
    return {
        "yours": image_yours + stream_yours,
        "unknown": image_unknown + stream_unknown,
        "baseline": image_baseline + stream_baseline,
        "all": len(inventory) + len(streams),
    }
