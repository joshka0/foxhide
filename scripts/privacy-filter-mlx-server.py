#!/usr/bin/env python3

import json
import os
import re
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from itertools import groupby
from typing import Optional

import importlib.metadata as md
import mlx.core as mx
from mlx_embeddings.utils import load


HOST = os.environ.get("PRIVACY_FILTER_HOST", "127.0.0.1")
PORT = int(os.environ.get("PRIVACY_FILTER_PORT", "8092"))
MODEL_ID = os.environ.get(
    "PRIVACY_FILTER_MLX_MODEL",
    "mlx-community/openai-privacy-filter-8bit",
)


@dataclass
class Detection:
    entity: str
    score: float
    start: int
    end: int
    text: str


print(
    f"loading {MODEL_ID} with mlx-embeddings {md.version('mlx-embeddings')}",
    flush=True,
)
MODEL, TOKENIZER = load(MODEL_ID)
ID2LABEL = MODEL.config.id2label


class Handler(BaseHTTPRequestHandler):
    server_version = "privacy-filter-mlx/0.1"

    def do_GET(self):
        if self.path == "/healthz":
            self.write_json(200, {"ok": True, "runtime": "mlx-embeddings"})
            return
        self.write_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/detect", "/redact"):
            self.write_json(404, {"error": "not found"})
            return

        try:
            body = self.read_json()
            text = body.get("text") if isinstance(body.get("text"), str) else ""
            min_score = body.get("min_score", 0.85)
            if not isinstance(min_score, (int, float)):
                min_score = 0.85
            replacement = (
                body.get("replacement")
                if isinstance(body.get("replacement"), str)
                else "[REDACTED:{entity}]"
            )

            if not text:
                if self.path == "/detect":
                    self.write_json(200, {"detections": []})
                else:
                    self.write_json(200, {"redacted": "", "detections": []})
                return

            detections = detect_text(text, float(min_score))
            if self.path == "/detect":
                self.write_json(
                    200,
                    {"detections": [detection.__dict__ for detection in detections]},
                )
            else:
                self.write_json(
                    200,
                    {
                        "redacted": replace_spans(text, detections, replacement),
                        "detections": [detection.__dict__ for detection in detections],
                    },
                )
        except Exception as error:
            self.write_json(500, {"error": str(error)})

    def log_message(self, format, *args):
        return

    def read_json(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > 2 * 1024 * 1024:
            raise ValueError("request too large")
        raw = self.rfile.read(content_length) if content_length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def write_json(self, status, value):
        payload = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def detect_text(text: str, min_score: float) -> list[Detection]:
    inputs = TOKENIZER(text, return_tensors="mlx", return_offsets_mapping=True)
    outputs = MODEL(inputs["input_ids"], attention_mask=inputs["attention_mask"])
    probs = mx.softmax(outputs.logits, axis=-1)
    pred_ids = mx.argmax(probs, axis=-1)
    pred_scores = mx.max(probs, axis=-1)
    mx.eval(outputs.logits, probs, pred_ids, pred_scores)

    groups = group_tokens(
        pred_ids[0].tolist(),
        pred_scores[0].tolist(),
        inputs["offset_mapping"][0].tolist(),
        min_score,
    )
    detections = []
    for group in groups:
        start = group[0]["start"]
        end = group[-1]["end"]
        entity = group[0]["entity"]
        score = sum(token["score"] for token in group) / len(group)
        span = normalize_detection_span(text, entity, start, end)
        if span is None:
            continue
        detections.append(
            Detection(
                entity=entity,
                score=round(score, 6),
                start=span["start"],
                end=span["end"],
                text=text[span["start"] : span["end"]],
            )
        )
    return merge_overlapping(detections)


def group_tokens(pred_ids, pred_scores, offset_mapping, min_score):
    groups = []
    current = None

    for pred_id, score, offsets in zip(pred_ids, pred_scores, offset_mapping):
        start, end = offsets
        if start == end:
            current = None
            continue

        label = ID2LABEL[str(pred_id)]
        prefix, entity = parse_entity(label)
        if entity is None or score < min_score:
            current = None
            continue

        starts_new = (
            current is None
            or prefix == "B"
            or prefix == "S"
            or entity != current["entity"]
            or start > current["last_end"]
        )

        if starts_new:
            current = {"entity": entity, "tokens": [], "last_end": end}
            groups.append(current["tokens"])

        current["tokens"].append(
            {
                "entity": entity,
                "score": float(score),
                "start": int(start),
                "end": int(end),
            }
        )
        current["last_end"] = end

        if prefix in ("E", "S"):
            current = None

    return groups


def parse_entity(label: str) -> tuple[Optional[str], Optional[str]]:
    if label == "O":
        return None, None
    match = re.match(r"^([BIES])-?(.*)$", label)
    if match:
        return match.group(1), match.group(2)
    return None, label


def normalize_detection_span(text: str, entity: str, start: int, end: int):
    while start < end and text[start].isspace():
        start += 1
    while start < end and text[end - 1].isspace():
        end -= 1

    if entity in ("private_email", "email"):
        return find_overlapping_match(
            text,
            start,
            end,
            re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE),
        )

    if entity in ("private_phone", "phone"):
        span_text = text[start:end]
        if sum(character.isdigit() for character in span_text) < 7:
            return None

    return {"start": start, "end": end}


def find_overlapping_match(text: str, start: int, end: int, pattern):
    for match in pattern.finditer(text):
        match_start = match.start()
        match_end = match.end()
        if start < match_end and match_start < end:
            return {"start": match_start, "end": match_end}
    return None


def merge_overlapping(detections: list[Detection]) -> list[Detection]:
    if not detections:
        return []
    detections = sorted(detections, key=lambda item: (item.start, item.end))
    merged = [detections[0]]
    for detection in detections[1:]:
        previous = merged[-1]
        if detection.start > previous.end:
            merged.append(detection)
            continue
        previous_end = previous.end
        previous.end = max(previous.end, detection.end)
        previous.text = previous.text + detection.text[max(0, previous_end - detection.start) :]
        previous.score = max(previous.score, detection.score)
        if detection.entity not in previous.entity.split("+"):
            previous.entity = f"{previous.entity}+{detection.entity}"
    return merged


def replace_spans(text: str, detections: list[Detection], replacement: str) -> str:
    output = []
    cursor = 0
    for detection in detections:
        output.append(text[cursor : detection.start])
        output.append(
            replacement.replace("{entity}", detection.entity)
            .replace("{text}", detection.text)
            .replace("{score}", f"{detection.score:.4f}")
        )
        cursor = detection.end
    output.append(text[cursor:])
    return "".join(output)


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), Handler)
    print(f"privacy-filter-mlx listening on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()
