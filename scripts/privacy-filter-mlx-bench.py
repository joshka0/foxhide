#!/usr/bin/env python3

import argparse
import json
import statistics
import time
from itertools import groupby

import importlib.metadata as md
import mlx.core as mx
from mlx_embeddings.utils import load


def parse_args():
    parser = argparse.ArgumentParser(
        description="Benchmark MLX privacy-filter inference on Apple Silicon."
    )
    parser.add_argument(
        "--model",
        default="mlx-community/openai-privacy-filter-8bit",
    )
    parser.add_argument(
        "--input",
        default="Email me at josh@example.com or call +1 415 555 0199.",
    )
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--runs", type=int, default=5)
    return parser.parse_args()


def main():
    args = parse_args()

    load_start = time.perf_counter()
    model, tokenizer = load(args.model)
    load_ms = (time.perf_counter() - load_start) * 1000.0

    for _ in range(args.warmup):
        infer(model, tokenizer, args.input)

    timings = []
    last_pairs = []

    for _ in range(args.runs):
        start = time.perf_counter()
        last_pairs = infer(model, tokenizer, args.input)
        timings.append((time.perf_counter() - start) * 1000.0)

    sorted_timings = sorted(timings)
    payload = {
        "runtime": "mlx-embeddings",
        "mlxEmbeddingsVersion": md.version("mlx-embeddings"),
        "model": args.model,
        "inputChars": len(args.input),
        "warmup": args.warmup,
        "runs": args.runs,
        "loadMs": round(load_ms, 2),
        "meanMs": round(statistics.fmean(timings), 2),
        "minMs": round(sorted_timings[0], 2),
        "maxMs": round(sorted_timings[-1], 2),
        "p50Ms": round(percentile(sorted_timings, 0.5), 2),
        "p95Ms": round(percentile(sorted_timings, 0.95), 2),
        "resultCount": len(last_pairs),
        "resultPreview": last_pairs,
    }
    print(json.dumps(payload, indent=2))


def infer(model, tokenizer, text):
    inputs = tokenizer(text, return_tensors="mlx")
    outputs = model(inputs["input_ids"], attention_mask=inputs["attention_mask"])
    preds = mx.argmax(outputs.logits, axis=-1)
    mx.eval(outputs.logits, preds)

    pred_ids = preds[0].tolist()
    token_ids = inputs["input_ids"][0].tolist()
    id2label = model.config.id2label

    def entity(pred):
        label = id2label[str(pred)]
        return None if label == "O" else label.split("-", 1)[-1]

    pairs = []
    for ent, group in groupby(zip(token_ids, pred_ids), key=lambda item: entity(item[1])):
        if ent:
            grouped_ids = [token_id for token_id, _ in group]
            pairs.append([ent, tokenizer.decode(grouped_ids).strip()])

    return pairs


def percentile(sorted_values, ratio):
    if len(sorted_values) == 1:
        return sorted_values[0]
    index = min(len(sorted_values) - 1, max(0, int(len(sorted_values) * ratio + 0.9999) - 1))
    return sorted_values[index]


if __name__ == "__main__":
    main()
