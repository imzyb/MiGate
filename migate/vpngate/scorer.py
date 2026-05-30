from __future__ import annotations


def score_node(*, latency_ms: int | None, speed: int, uptime: int, failure_count: int) -> int:
    """Return a stable 0-100 quality score for a VPNGate candidate."""
    score = 50.0

    latency = latency_ms if latency_ms is not None and latency_ms > 0 else 9999
    if latency <= 100:
        score += 25
    elif latency <= 250:
        score += 18
    elif latency <= 500:
        score += 8
    elif latency <= 1000:
        score -= 10
    else:
        score -= 25

    if speed >= 10_000_000:
        score += 15
    elif speed >= 1_000_000:
        score += 10
    elif speed >= 100_000:
        score += 3
    else:
        score -= 10

    if uptime >= 300_000:
        score += 10
    elif uptime >= 100_000:
        score += 6
    elif uptime >= 10_000:
        score += 2

    score -= max(failure_count, 0) * 15
    return max(0, min(100, int(round(score))))


def classify_score(score: int | float) -> str:
    if score >= 85:
        return "excellent"
    if score >= 65:
        return "good"
    if score >= 40:
        return "usable"
    if score > 0:
        return "unstable"
    return "blocked"
