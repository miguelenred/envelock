#!/usr/bin/env python3
"""A/B the framework smoke harness on a disposable local HTTP endpoint.

The baseline checks only status/body; the current harness additionally handles cookies and checks
headers and redirects. These arms do NOT provide equivalent coverage. This measures the test
harness, not the protected application's runtime. No external server or framework is touched.
"""
from __future__ import annotations

import argparse
import http.server
import importlib.util
import random
import statistics
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib dispatch name
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Set-Cookie", "probe=123; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(b'{"pong":true}')

    def log_message(self, *_args):
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=int, default=40)
    parser.add_argument("--requests", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.pairs <= 500 or not 1 <= args.requests <= 200:
        parser.error("pairs must be 1..500 and requests must be 1..200")
    spec = importlib.util.spec_from_file_location("framework_smoke_bench", ROOT / "scripts/framework-smoke.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = http.server.HTTPServer(("127.0.0.1", 0), FixtureHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    port = server.server_port
    module.ROUTES["bench"] = [("GET", "/probe", None)] * args.requests
    url = f"http://127.0.0.1:{port}/probe"

    def baseline():
        for _ in range(args.requests):
            request = urllib.request.Request(url, headers={"Content-Type": "application/json",
                                                           "Accept": "application/json"})
            with urllib.request.urlopen(request, timeout=3) as response:  # nosec B310 - local disposable server
                if response.status != 200 or response.read() != b'{"pong":true}':
                    raise RuntimeError("unexpected baseline response")

    def extended():
        responses = module.probe(port, "bench", [])
        if len(responses) != args.requests or not all(item[0] == 200 and item[1] == b'{"pong":true}'
                                                      for item in responses.values()):
            raise RuntimeError("unexpected extended response")

    values = {"baseline": [], "extended": []}
    rng = random.Random(73)  # nosec B311 - randomized measurement order, not cryptography
    try:
        baseline()
        extended()
        for _ in range(args.pairs):
            pair = [(baseline, values["baseline"]), (extended, values["extended"])]
            rng.shuffle(pair)
            for run, measurements in pair:
                start = time.perf_counter_ns()
                run()
                measurements.append((time.perf_counter_ns() - start) / 1_000_000)
        a, b = statistics.median(values["baseline"]), statistics.median(values["extended"])
        print(f"pairs={args.pairs} requests={args.requests} baseline_ms={a:.3f} extended_ms={b:.3f} ratio={b/a:.3f}")
        print("Different verification coverage; measures test harness overhead, not application runtime.")
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
