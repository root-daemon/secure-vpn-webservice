"""In-VPC synthetic check for the internal web service.

Calls the /health endpoint over HTTPS, verifying the server certificate
against the project's private CA (bundled as ca.crt), and publishes
Availability (1/0) and LatencyMs metrics to CloudWatch.
"""

import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TARGET_URL = os.environ.get("TARGET_URL", "https://app.securevpn.internal/health")
NAMESPACE = os.environ.get("METRIC_NAMESPACE", "securevpn/Synthetics")
TIMEOUT_SECONDS = float(os.environ.get("TIMEOUT_SECONDS", "8"))
CA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ca.crt")

cloudwatch = boto3.client("cloudwatch")


def build_ssl_context(ca_file: str = CA_FILE) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def probe(url: str, context: ssl.SSLContext, timeout: float) -> dict:
    """Return {'ok': bool, 'latency_ms': float, 'status': int|None, 'error': str|None}."""
    started = time.monotonic()
    status = None
    error = None
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "securevpn-synthetic/1.0"})
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            status = response.status
            body = json.loads(response.read().decode("utf-8"))
            if status != 200 or body.get("status") != "ok":
                error = f"unhealthy response: status={status} body={body}"
    except urllib.error.HTTPError as exc:
        status = exc.code
        error = f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001 - any failure means "down"
        error = f"{type(exc).__name__}: {exc}"
    latency_ms = (time.monotonic() - started) * 1000
    return {"ok": error is None, "latency_ms": round(latency_ms, 1), "status": status, "error": error}


def handler(event, context):
    result = probe(TARGET_URL, build_ssl_context(), TIMEOUT_SECONDS)
    endpoint = urllib.parse.urlparse(TARGET_URL).hostname
    dimensions = [{"Name": "Endpoint", "Value": endpoint}]

    cloudwatch.put_metric_data(
        Namespace=NAMESPACE,
        MetricData=[
            {"MetricName": "Availability", "Dimensions": dimensions, "Value": 1 if result["ok"] else 0, "Unit": "Count"},
            {"MetricName": "LatencyMs", "Dimensions": dimensions, "Value": result["latency_ms"], "Unit": "Milliseconds"},
        ],
    )

    log = logger.info if result["ok"] else logger.error
    log(json.dumps({"target": TARGET_URL, **result}))
    return result
