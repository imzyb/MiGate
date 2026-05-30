from migate.vpngate.scorer import classify_score, score_node


def test_score_penalizes_high_latency_and_failures():
    fast = score_node(latency_ms=80, speed=1_000_000, uptime=100_000, failure_count=0)
    slow_failed = score_node(latency_ms=900, speed=1_000_000, uptime=100_000, failure_count=3)

    assert fast > slow_failed


def test_score_rewards_speed_and_uptime():
    strong = score_node(latency_ms=120, speed=10_000_000, uptime=300_000, failure_count=0)
    weak = score_node(latency_ms=120, speed=100_000, uptime=1_000, failure_count=0)

    assert strong > weak


def test_score_never_goes_below_zero():
    score = score_node(latency_ms=9_999, speed=0, uptime=0, failure_count=99)

    assert score == 0


def test_classify_score_maps_quality_bands():
    assert classify_score(90) == "excellent"
    assert classify_score(70) == "good"
    assert classify_score(45) == "usable"
    assert classify_score(20) == "unstable"
    assert classify_score(0) == "blocked"
