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

const args = process.argv.slice(2);
const defaults = {
  task: "token-classification",
  model: "openai/privacy-filter",
  input: "My name is Harry Potter and my email is harry.potter@hogwarts.edu.",
};

if (hasFlag(args, "--help")) {
  console.log(usage({ command: "pnpm download --", ...defaults }));
  process.exit(0);
}

const task = readFlag(args, "--task", defaults.task);
const model = readFlag(args, "--model", defaults.model);
const input = readInput(args, defaults.input);
const cacheDir = readFlag(args, "--cache-dir", defaultCacheDir);
const pipelineOptions = parseJsonFlag(args, "--options", '{"dtype":"q4"}');
const runOptions = parseJsonFlag(args, "--args", "{}");
const skipRun = hasFlag(args, "--skip-run");
const resolvedCacheDir = await configureTransformers({ cacheDir });

console.error(`Downloading ${task} pipeline: ${model}`);
console.error(`Cache directory: ${resolvedCacheDir}`);

const pipe = await pipeline(task, model, {
  ...pipelineOptions,
  progress_callback: progressLogger(),
});

if (skipRun) {
  printJson({
    task,
    model,
    cacheDir: resolvedCacheDir,
    downloaded: true,
  });
  process.exit(0);
}

console.error("Running a warmup inference to verify the cached files...");
const result = await pipe(input, runOptions);

printJson({
  task,
  model,
  cacheDir: resolvedCacheDir,
  input,
  result,
});
