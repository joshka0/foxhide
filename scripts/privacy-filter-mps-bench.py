#!/usr/bin/env python3

import argparse
import json
import statistics
import time

import torch
from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline


def parse_args():
    parser = argparse.ArgumentParser(
        description="Benchmark openai/privacy-filter with Hugging Face Transformers on MPS or CPU."
    )
    parser.add_argument("--model", default="openai/privacy-filter")
    parser.add_argument(
        "--input",
        default="Email me at josh@example.com or call +1 415 555 0199.",
    )
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--cache-dir", default=".hf-cache")
    return parser.parse_args()


def sync(device_name):
    if device_name == "mps":
        torch.mps.synchronize()


def pick_device():
    return "mps" if torch.backends.mps.is_available() else "cpu"


def main():
    args = parse_args()
    device_name = pick_device()
    dtype = torch.float16 if device_name == "mps" else torch.float32

    load_start = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(args.model, cache_dir=args.cache_dir)
    model = AutoModelForTokenClassification.from_pretrained(
        args.model,
        cache_dir=args.cache_dir,
        dtype=dtype,
    )
    model.to(torch.device(device_name))
    classifier = pipeline(
        task="token-classification",
        model=model,
        tokenizer=tokenizer,
        aggregation_strategy="simple",
        device=torch.device(device_name),
    )
    sync(device_name)
    load_ms = (time.perf_counter() - load_start) * 1000.0

    for _ in range(args.warmup):
        classifier(args.input)
        sync(device_name)

    timings = []
    result = None

    for _ in range(args.runs):
        start = time.perf_counter()
        result = classifier(args.input)
        sync(device_name)
        timings.append((time.perf_counter() - start) * 1000.0)

    sorted_timings = sorted(timings)
    payload = {
        "runtime": f"transformers-pytorch-{device_name}",
        "model": args.model,
        "cacheDir": args.cache_dir,
        "device": device_name,
        "dtype": str(dtype).replace("torch.", ""),
        "inputChars": len(args.input),
        "warmup": args.warmup,
        "runs": args.runs,
        "loadMs": round(load_ms, 2),
        "meanMs": round(statistics.fmean(timings), 2),
        "minMs": round(sorted_timings[0], 2),
        "maxMs": round(sorted_timings[-1], 2),
        "p50Ms": round(percentile(sorted_timings, 0.5), 2),
        "p95Ms": round(percentile(sorted_timings, 0.95), 2),
        "resultCount": len(result) if isinstance(result, list) else None,
    }
    print(json.dumps(payload, indent=2))


def percentile(sorted_values, ratio):
    if len(sorted_values) == 1:
        return sorted_values[0]
    index = min(len(sorted_values) - 1, max(0, int(len(sorted_values) * ratio + 0.9999) - 1))
    return sorted_values[index]


if __name__ == "__main__":
    main()
