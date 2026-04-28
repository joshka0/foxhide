#!/usr/bin/env python3

import argparse
import json
import statistics
import time

from mlx_lm import stream_generate
from mlx_lm.utils import load


def parse_args():
    parser = argparse.ArgumentParser(
        description="Benchmark a local MLX chat model directory."
    )
    parser.add_argument("--model", required=True, help="Path to local MLX model directory")
    parser.add_argument(
        "--prompt",
        default="Respond with exactly two short sentences on why local inference latency matters. Do not show reasoning.",
    )
    parser.add_argument("--max-tokens", type=int, default=96)
    parser.add_argument("--warmup", type=int, default=0)
    parser.add_argument("--runs", type=int, default=1)
    return parser.parse_args()


def main():
    args = parse_args()

    load_start = time.perf_counter()
    model, tokenizer = load(args.model)
    load_ms = (time.perf_counter() - load_start) * 1000.0

    prompt = build_prompt(tokenizer, args.prompt)

    for _ in range(args.warmup):
        run_once(model, tokenizer, prompt, args.max_tokens)

    runs = [run_once(model, tokenizer, prompt, args.max_tokens) for _ in range(args.runs)]
    last_run = runs[-1]

    payload = {
        "runtime": "mlx-lm-direct",
        "model": args.model,
        "promptChars": len(args.prompt),
        "loadMs": round(load_ms, 2),
        "warmup": args.warmup,
        "runs": args.runs,
        "ttftMs": round(last_run["ttft_ms"], 2),
        "totalMs": round(last_run["total_ms"], 2),
        "meanTtftMs": round(statistics.fmean(run["ttft_ms"] for run in runs), 2),
        "meanTotalMs": round(statistics.fmean(run["total_ms"] for run in runs), 2),
        "promptTokens": last_run["prompt_tokens"],
        "promptTps": round_or_none(last_run["prompt_tps"]),
        "generationTokens": last_run["generation_tokens"],
        "generationTps": round_or_none(last_run["generation_tps"]),
        "meanGenerationTps": round_or_none(
            statistics.fmean(run["generation_tps"] for run in runs if run["generation_tps"] is not None)
        ),
        "peakMemoryGb": round_or_none(last_run["peak_memory"]),
        "finishReason": last_run["finish_reason"],
        "outputPreview": last_run["output"][:800],
    }
    print(json.dumps(payload, indent=2))


def build_prompt(tokenizer, user_prompt: str) -> str:
    messages = [{"role": "user", "content": user_prompt}]
    apply_chat_template = getattr(tokenizer, "apply_chat_template", None)
    if callable(apply_chat_template):
        try:
            return apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )
        except TypeError:
            return apply_chat_template(messages, tokenize=False)
    return user_prompt


def run_once(model, tokenizer, prompt: str, max_tokens: int):
    start = time.perf_counter()
    first_token_ms = None
    text_parts = []
    last_response = None

    for response in stream_generate(
        model,
        tokenizer,
        prompt,
        max_tokens=max_tokens,
    ):
        if first_token_ms is None and response.text:
            first_token_ms = (time.perf_counter() - start) * 1000.0
        if response.text:
            text_parts.append(response.text)
        last_response = response

    total_ms = (time.perf_counter() - start) * 1000.0
    return {
        "ttft_ms": first_token_ms or total_ms,
        "total_ms": total_ms,
        "prompt_tokens": getattr(last_response, "prompt_tokens", None),
        "prompt_tps": getattr(last_response, "prompt_tps", None),
        "generation_tokens": getattr(last_response, "generation_tokens", None),
        "generation_tps": getattr(last_response, "generation_tps", None),
        "peak_memory": getattr(last_response, "peak_memory", None),
        "finish_reason": getattr(last_response, "finish_reason", None),
        "output": "".join(text_parts).strip(),
    }


def round_or_none(value):
    if value is None:
        return None
    return round(float(value), 2)


if __name__ == "__main__":
    main()
