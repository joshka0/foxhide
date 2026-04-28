#!/usr/bin/env python3

import argparse
import json
import statistics
import time
import urllib.error
import urllib.request


def parse_args():
    parser = argparse.ArgumentParser(
        description="Benchmark /detect latency for one or more privacy-filter HTTP endpoints."
    )
    parser.add_argument(
        "--target",
        action="append",
        required=True,
        help="Target in name=url form, for example node=http://127.0.0.1:8090",
    )
    parser.add_argument(
        "--input",
        default="Email me at josh@example.com or call +1 415 555 0199.",
    )
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    return parser.parse_args()


def main():
    args = parse_args()
    results = []
    for target in args.target:
        name, base_url = parse_target(target)
        detections = None

        for _ in range(args.warmup):
            detections = post_detect(base_url, args.input, args.timeout_seconds)

        timings = []
        for _ in range(args.runs):
            start = time.perf_counter()
            detections = post_detect(base_url, args.input, args.timeout_seconds)
            timings.append((time.perf_counter() - start) * 1000.0)

        sorted_timings = sorted(timings)
        results.append(
            {
                "name": name,
                "url": base_url,
                "warmup": args.warmup,
                "runs": args.runs,
                "meanMs": round(statistics.fmean(timings), 2),
                "minMs": round(sorted_timings[0], 2),
                "maxMs": round(sorted_timings[-1], 2),
                "p50Ms": round(percentile(sorted_timings, 0.5), 2),
                "p95Ms": round(percentile(sorted_timings, 0.95), 2),
                "resultCount": len(detections),
                "resultPreview": detections,
            }
        )

    print(json.dumps(results, indent=2))


def parse_target(value: str):
    if "=" not in value:
        raise ValueError("--target must be in name=url form")
    name, url = value.split("=", 1)
    return name, url.rstrip("/")


def post_detect(base_url: str, text: str, timeout_seconds: float):
    request = urllib.request.Request(
        f"{base_url}/detect",
        data=json.dumps({"text": text}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload["detections"]


def percentile(sorted_values, ratio):
    if len(sorted_values) == 1:
        return sorted_values[0]
    index = min(len(sorted_values) - 1, max(0, int(len(sorted_values) * ratio + 0.9999) - 1))
    return sorted_values[index]


if __name__ == "__main__":
    main()
