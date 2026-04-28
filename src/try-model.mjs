import { pipeline } from "@huggingface/transformers";
import {
  hasFlag,
  parseJsonFlag,
  printJson,
  readFlag,
  readInput,
  usage,
} from "./format.mjs";
import {
  configureTransformers,
  defaultCacheDir,
  progressLogger,
} from "./transformers-env.mjs";

const examples = [
  {
    task: "token-classification",
    model: "openai/privacy-filter",
    input: "Email me at josh@example.com or call +1 415 555 0199.",
  },
  {
    task: "sentiment-analysis",
    model: "Xenova/distilbert-base-uncased-finetuned-sst-2-english",
    input: "This is surprisingly good.",
  },
  {
    task: "text-classification",
    model: "Xenova/toxic-bert",
    input: "You are wonderful.",
  },
];

const args = process.argv.slice(2);
const defaults = examples[0];

if (hasFlag(args, "--examples")) {
  printJson(examples);
  process.exit(0);
}

if (hasFlag(args, "--help")) {
  console.log(usage({ command: "pnpm try --", ...defaults }));
  process.exit(0);
}

const task = readFlag(args, "--task", defaults.task);
const model = readFlag(args, "--model", defaults.model);
const input = readInput(args, defaults.input);
const cacheDir = readFlag(args, "--cache-dir", defaultCacheDir);
const localOnly = hasFlag(args, "--local");
const pipelineOptions = parseJsonFlag(args, "--options");
const runOptions = parseJsonFlag(args, "--args");
const resolvedCacheDir = await configureTransformers({ cacheDir, localOnly });

console.error(`Loading ${task} pipeline: ${model}`);
console.error(`Cache directory: ${resolvedCacheDir}`);
console.error(`Remote model loading: ${localOnly ? "disabled" : "enabled"}`);

const pipe = await pipeline(task, model, {
  ...pipelineOptions,
  local_files_only: localOnly,
  progress_callback: progressLogger(),
});

console.error("Running inference...");
const result = await pipe(input, runOptions);

printJson({
  task,
  model,
  cacheDir: resolvedCacheDir,
  localOnly,
  input,
  result,
});
