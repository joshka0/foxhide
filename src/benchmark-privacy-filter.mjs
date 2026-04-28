import { performance } from "node:perf_hooks";
import { pipeline } from "@huggingface/transformers";
import {
  hasFlag,
  parseJsonFlag,
  printJson,
  readFlag,
  readInput,
} from "./format.mjs";
import {
  configureTransformers,
  defaultCacheDir,
  progressLogger,
} from "./transformers-env.mjs";

const args = process.argv.slice(2);
const model = readFlag(args, "--model", "openai/privacy-filter");
const input = readInput(
  args,
  "Email me at josh@example.com or call +1 415 555 0199.",
);
const cacheDir = readFlag(args, "--cache-dir", defaultCacheDir);
const localOnly = hasFlag(args, "--local");
const quiet = hasFlag(args, "--quiet");
const warmup = Number.parseInt(readFlag(args, "--warmup", "1"), 10);
const runs = Number.parseInt(readFlag(args, "--runs", "5"), 10);
const pipelineOptions = parseJsonFlag(args, "--options", '{"dtype":"q4"}');
const runOptions = parseJsonFlag(
  args,
  "--args",
  '{"aggregation_strategy":"simple"}',
);

if (!Number.isFinite(warmup) || warmup < 0) {
  throw new Error("--warmup must be a non-negative integer");
}

if (!Number.isFinite(runs) || runs <= 0) {
  throw new Error("--runs must be a positive integer");
}

const resolvedCacheDir = await configureTransformers({ cacheDir, localOnly });

const loadStart = performance.now();
const pipe = await pipeline("token-classification", model, {
  ...pipelineOptions,
  local_files_only: localOnly,
  progress_callback: quiet ? undefined : progressLogger(),
});
const loadMs = performance.now() - loadStart;

for (let index = 0; index < warmup; index += 1) {
  await pipe(input, runOptions);
}

const timingsMs = [];
let lastResult = null;

for (let index = 0; index < runs; index += 1) {
  const start = performance.now();
  lastResult = await pipe(input, runOptions);
  timingsMs.push(performance.now() - start);
}

const sorted = [...timingsMs].sort((left, right) => left - right);

printJson({
  runtime: "transformers.js-onnx",
  model,
  cacheDir: resolvedCacheDir,
  localOnly,
  inputChars: input.length,
  warmup,
  runs,
  loadMs: round(loadMs),
  meanMs: round(average(timingsMs)),
  minMs: round(sorted[0]),
  maxMs: round(sorted[sorted.length - 1]),
  p50Ms: round(percentile(sorted, 0.5)),
  p95Ms: round(percentile(sorted, 0.95)),
  resultCount: Array.isArray(lastResult) ? lastResult.length : null,
  pipelineOptions,
  runOptions,
});

function average(values) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function percentile(sortedValues, ratio) {
  if (sortedValues.length === 1) return sortedValues[0];
  const index = Math.min(
    sortedValues.length - 1,
    Math.max(0, Math.ceil(sortedValues.length * ratio) - 1),
  );
  return sortedValues[index];
}

function round(value) {
  return Math.round(value * 100) / 100;
}
