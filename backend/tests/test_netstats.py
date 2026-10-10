"""
core.netstats — live network throughput + gateway ping.

The maths and ping-parsing are tested purely (mocked psutil/subprocess), so no
real packets are sent and the background sampler thread never starts.
"""
import types

import core.netstats as ns


# --- human units ------------------------------------------------------------
def test_human_bps_units():
    assert ns._human_bps(0) == "0 b/s"
    assert ns._human_bps(10) == "80 b/s"           # 10 B/s * 8 = 80 b/s
    assert ns._human_bps(125_000) == "1.0 Mb/s"    # 125 kB/s * 8 = 1 Mb/s


# --- ping parsing (locale-independent "<n>ms") ------------------------------
def test_measure_ping_parses_time(monkeypatch):
    monkeypatch.setattr(ns.subprocess, "run", lambda *a, **k: types.SimpleNamespace(
        stdout="Reply from 192.168.1.1: bytes=32 time=7ms TTL=64"))
    assert ns.measure_ping("192.168.1.1") == 7


def test_measure_ping_sub_millisecond(monkeypatch):
    monkeypatch.setattr(ns.subprocess, "run", lambda *a, **k: types.SimpleNamespace(
        stdout="Reply from 10.0.0.1: bytes=32 time<1ms TTL=128"))
    assert ns.measure_ping("10.0.0.1") == 1


def test_measure_ping_none_when_unreachable(monkeypatch):
    monkeypatch.setattr(ns.subprocess, "run", lambda *a, **k: types.SimpleNamespace(
        stdout="Request timed out."))
    assert ns.measure_ping("10.0.0.9") is None
    assert ns.measure_ping(None) is None


# --- throughput deltas ------------------------------------------------------
def test_sample_once_computes_rates(monkeypatch):
    counters = iter([
        types.SimpleNamespace(bytes_sent=1000, bytes_recv=5000),
        types.SimpleNamespace(bytes_sent=1200, bytes_recv=5800),   # +200 up, +800 down
    ])
    clock = iter([100.0, 101.0])                                   # dt = 1.0 s
    monkeypatch.setattr(ns.psutil, "net_io_counters", lambda: next(counters))
    monkeypatch.setattr(ns.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(ns, "_current_gateway", lambda: "192.168.1.1")
    monkeypatch.setattr(ns, "measure_ping", lambda host, **k: 4)

    ns._last_io = None
    ns._sample_once()                       # first sample only sets a baseline
    assert ns._cache["up_bps"] == 0 and ns._cache["down_bps"] == 0
    ns._sample_once()                       # second: rates over the 1 s gap
    assert ns._cache["up_bps"] == 200 and ns._cache["down_bps"] == 800
    assert ns._cache["ping_ms"] == 4 and ns._cache["gateway"] == "192.168.1.1"


# --- route ------------------------------------------------------------------
def test_api_netstats_requires_login(client):
    assert client.get("/api/netstats").status_code == 302   # anon -> login


def test_api_netstats_returns_json(client, seeded_db, login, monkeypatch):
    # Patch snapshot so the real background sampler/ping never runs in tests.
    monkeypatch.setattr(ns, "snapshot", lambda: {
        "down_human": "1.0 Mb/s", "up_human": "0 b/s",
        "ping_ms": 4, "gateway": "192.168.1.1"})
    login(client, "viewer")
    resp = client.get("/api/netstats")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["down_human"] == "1.0 Mb/s"
    assert body["ping_ms"] == 4
