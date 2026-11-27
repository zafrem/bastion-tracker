#!/usr/bin/env python3
"""Checks a running monitoring stack (docker compose --profile monitoring up -d).

Passes when Prometheus scrapes Tracker and loads every alert rule without errors, alerts reach Alertmanager,
every dashboard query is accepted, and Grafana has the dashboard. Uses only the standard library.
"""
import base64
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PROMETHEUS = os.environ.get("PROMETHEUS_URL", "http://localhost:9092")
ALERTMANAGER = os.environ.get("ALERTMANAGER_URL", "http://localhost:9093")
GRAFANA = os.environ.get("GRAFANA_URL", "http://localhost:3001")
TIMEOUT = float(os.environ.get("CHECK_TIMEOUT_SECONDS", "180"))


def get(url, headers=None):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=10) as response:
        return json.load(response)


def eventually(what, check):
    """Retries check until it returns without raising, or the timeout passes."""
    deadline = time.monotonic() + TIMEOUT
    while True:
        try:
            check()
            print("ok:", what)
            return
        except Exception as error:  # the stack may still be starting
            if time.monotonic() > deadline:
                sys.exit(f"FAILED: {what}: {error}")
            time.sleep(3)


def scraped():
    targets = get(PROMETHEUS + "/api/v1/targets")["data"]["activeTargets"]
    health = {t["labels"]["job"]: (t["health"], t.get("lastError", "")) for t in targets}
    for job in ("tracker", "prometheus", "alertmanager"):
        assert health.get(job, ("missing", ""))[0] == "up", f"{job}: {health.get(job)}"


def rules_evaluate():
    with open(os.path.join(HERE, "prometheus/rules/tracker.yml")) as f:
        wanted = set(re.findall(r"- alert: (\w+)", f.read()))
    groups = get(PROMETHEUS + "/api/v1/rules")["data"]["groups"]
    loaded = {r["name"]: r for g in groups for r in g["rules"]}
    assert wanted <= set(loaded), f"not loaded: {sorted(wanted - set(loaded))}"
    bad = {n: (r["health"], r.get("lastError", "")) for n, r in loaded.items() if r["health"] != "ok"}
    assert not bad, f"rules not evaluating: {bad}"


def alerts_delivered():
    names = {a["labels"]["alertname"] for a in get(ALERTMANAGER + "/api/v2/alerts")}
    assert "Watchdog" in names, f"Alertmanager has {sorted(names)}"


def dashboard_queries():
    with open(os.path.join(HERE, "grafana/dashboards/tracker.json")) as f:
        panels = json.load(f)["panels"]
    for panel in panels:
        for target in panel.get("targets", []):
            query = target["expr"].replace("$__rate_interval", "5m").replace("$instance", ".*")
            result = get(PROMETHEUS + "/api/v1/query?" + urllib.parse.urlencode({"query": query}))
            assert result["status"] == "success", f"{panel['title']}: {result}"


def grafana():
    password = os.environ.get("GRAFANA_ADMIN_PASSWORD") or "admin"
    auth = {"Authorization": "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()}
    dashboard = get(GRAFANA + "/api/dashboards/uid/bastion-tracker", auth)
    assert dashboard["dashboard"]["title"] == "Bastion Tracker"
    health = get(GRAFANA + "/api/datasources/uid/prometheus/health", auth)
    assert health["status"] == "OK", health


eventually("Prometheus scrapes Tracker, itself and Alertmanager", scraped)
eventually("every alert rule is loaded and evaluates", rules_evaluate)
eventually("alerts reach Alertmanager", alerts_delivered)
eventually("Prometheus accepts every dashboard query", dashboard_queries)
eventually("Grafana serves the dashboard and reaches Prometheus", grafana)
