import http from "node:http";
import { pipeline } from "@huggingface/transformers";
import { redactText } from "./redact.mjs";
import {
  configureTransformers,
  defaultCacheDir,
  progressLogger,
} from "./transformers-env.mjs";

const host = process.env.PRIVACY_FILTER_HOST ?? "127.0.0.1";
const port = Number(process.env.PRIVACY_FILTER_PORT ?? "8090");
const cacheDir = process.env.PRIVACY_FILTER_CACHE_DIR ?? defaultCacheDir;
const quiet = isTruthy(process.env.PRIVACY_FILTER_QUIET ?? "true");

await configureTransformers({ cacheDir, localOnly: true });

const pipePromise = pipeline("token-classification", "openai/privacy-filter", {
  dtype: process.env.PRIVACY_FILTER_DTYPE ?? "q4",
  local_files_only: true,
  progress_callback: quiet ? undefined : progressLogger(),
});

const server = http.createServer(async (request, response) => {
  try {
    if (request.method === "GET" && request.url === "/healthz") {
      writeJson(response, 200, { ok: true });
      return;
    }

    if (request.method !== "POST" || !["/detect", "/redact"].includes(request.url)) {
      writeJson(response, 404, { error: "not found" });
      return;
    }

    const body = await readJson(request);
    const text = typeof body.text === "string" ? body.text : "";
    const minScore = Number.isFinite(body.min_score) ? body.min_score : 0.85;
    const replacement =
      typeof body.replacement === "string"
        ? body.replacement
        : "[REDACTED:{entity}]";

    if (!text) {
      writeJson(response, 200, request.url === "/detect" ? { detections: [] } : {
        redacted: "",
        detections: [],
      });
      return;
    }

    const pipe = await pipePromise;
    const tokens = await pipe(text, { aggregation_strategy: "none" });
    const redaction = redactText(text, tokens, { minScore, replacement });

    if (request.url === "/detect") {
      writeJson(response, 200, { detections: redaction.detections });
    } else {
      writeJson(response, 200, redaction);
    }
  } catch (error) {
    writeJson(response, 500, { error: error.message });
  }
});

server.listen(port, host, () => {
  console.error(`privacy-filter listening on http://${host}:${port}`);
});

function writeJson(response, status, value) {
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json");
  response.end(JSON.stringify(value));
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 2 * 1024 * 1024) {
      throw new Error("request too large");
    }
    chunks.push(chunk);
  }

  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function isTruthy(value) {
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}
