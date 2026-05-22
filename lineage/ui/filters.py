"""Presentation-only formatting helpers used by templates."""

from datetime import datetime, timezone


def cache_ttl_label(seconds):
    """Render the cache TTL as a short human label."""
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    return f"{minutes} min"


def ago(seconds):
    if seconds is None:
        return "—"
    value = int(seconds)
    if value < 60:
        return f"{value}s ago"
    if value < 3600:
        return f"{value // 60}m ago"
    return f"{value // 3600}h ago"


def humantime(ts):
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return str(ts)
    now = datetime.now(timezone.utc)
    delta = (now - dt).total_seconds()
    if delta < 0:
        rel = "future"
    elif delta < 60:
        rel = f"{int(delta)}s ago"
    elif delta < 3600:
        rel = f"{int(delta // 60)}m ago"
    elif delta < 86400:
        rel = f"{int(delta // 3600)}h ago"
    else:
        rel = f"{int(delta // 86400)}d ago"
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} ({rel})"


def humanage(ts):
    """Compact age: '2d', '15m', '4h', '30s'. Empty string for None."""
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return str(ts)
    delta = (datetime.now(timezone.utc) - dt).total_seconds()
    if delta < 0:
        return "future"
    if delta < 60:
        return f"{int(delta)}s"
    if delta < 3600:
        return f"{int(delta // 60)}m"
    if delta < 86400:
        return f"{int(delta // 3600)}h"
    if delta < 86400 * 30:
        return f"{int(delta // 86400)}d"
    if delta < 86400 * 365:
        return f"{int(delta // (86400 * 30))}mo"
    return f"{int(delta // (86400 * 365))}y"


def category_label(value):
    """Display label for internal namespace/category bucket names."""
    return "unclassified" if value == "unknown" else value


def short_image(image):
    if not image or len(image) < 60:
        return image
    return "…" + image[-58:]
