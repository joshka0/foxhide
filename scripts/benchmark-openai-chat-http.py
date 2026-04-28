#!/usr/bin/env python3

import argparse
import json
import statistics
import time
import urllib.request


def parse_args():
    parser = argparse.ArgumentParser(
        description="Benchmark an OpenAI-compatible /v1/chat/completions endpoint."
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:1234/v1")
    parser.add_argument("--model", required=True)
    parser.add_argument(
        "--prompt",
        default="Respond with exactly two short sentences on why local inference latency matters. Do not show reasoning.",
    )
    parser.add_argument("--max-tokens", type=int, default=80)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--warmup", type=int, default=0)
    parser.add_argument("--runs", type=int, default=1)
    return parser.parse_args()


def main():
    args = parse_args()
    payload = {
        "model": args.model,
        "messages": [{"role": "user", "content": args.prompt}],
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
        "stream": False,
    }

    for _ in range(args.warmup):
        run_once(args.base_url, payload)

    runs = [run_once(args.base_url, payload) for _ in range(args.runs)]
    last_run = runs[-1]

    output_tokens = [run["completion_tokens"] for run in runs if run["completion_tokens"] is not None]
    tps_values = [
        (run["completion_tokens"] / (run["total_ms"] / 1000.0))
        for run in runs
        if run["completion_tokens"] is not None and run["total_ms"] > 0
    ]

    result = {
        "runtime": "openai-http",
        "baseUrl": args.base_url,
        "model": args.model,
        "promptChars": len(args.prompt),
        "warmup": args.warmup,
        "runs": args.runs,
        "totalMs": round(last_run["total_ms"], 2),
        "meanTotalMs": round(statistics.fmean(run["total_ms"] for run in runs), 2),
        "completionTokens": last_run["completion_tokens"],
        "promptTokens": last_run["prompt_tokens"],
        "meanCompletionTps": round(statistics.fmean(tps_values), 2) if tps_values else None,
        "outputPreview": last_run["output"][:800],
    }
    print(json.dumps(result, indent=2))


def run_once(base_url: str, payload: dict):
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    start = time.perf_counter()
    with urllib.request.urlopen(request, timeout=600) as response:
        data = json.loads(response.read().decode("utf-8"))
    total_ms = (time.perf_counter() - start) * 1000.0

    choice = (data.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    usage = data.get("usage") or {}
    return {
        "total_ms": total_ms,
        "output": message.get("content", ""),
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
    }


if __name__ == "__main__":
    main()
