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
import { redactText } from "./redact.mjs";

const args = process.argv.slice(2);
const defaults = {
  task: "token-classification",
  model: "openai/privacy-filter",
  input: "Email me at josh@example.com or call +1 415 555 0199.",
};

if (hasFlag(args, "--help")) {
  console.log(usage({ command: "pnpm privacy --", ...defaults }));
  process.exit(0);
}

const input = readInput(
  args,
  defaults.input,
);
const cacheDir = readFlag(args, "--cache-dir", defaultCacheDir);
const localOnly = hasFlag(args, "--local");
const shouldRedact = hasFlag(args, "--redact");
const textOnly = hasFlag(args, "--text");
const quiet = hasFlag(args, "--quiet");
const replacement = readFlag(args, "--replacement", "[REDACTED:{entity}]");
const minScore = Number(readFlag(args, "--min-score", "0.85"));
const pipelineOptions = parseJsonFlag(args, "--options", '{"dtype":"q4"}');
const runOptions = parseJsonFlag(
  args,
  "--args",
  shouldRedact
    ? '{"aggregation_strategy":"none"}'
    : '{"aggregation_strategy":"simple"}',
);
const resolvedCacheDir = await configureTransformers({ cacheDir, localOnly });

if (!Number.isFinite(minScore) || minScore < 0 || minScore > 1) {
  throw new Error("--min-score must be a number between 0 and 1");
}

if (!quiet) {
  console.error(`Cache directory: ${resolvedCacheDir}`);
  console.error(`Remote model loading: ${localOnly ? "disabled" : "enabled"}`);
}

const pipe = await pipeline("token-classification", "openai/privacy-filter", {
  ...pipelineOptions,
  local_files_only: localOnly,
  progress_callback: quiet ? undefined : progressLogger(),
});
const result = await pipe(input, runOptions);

if (!shouldRedact) {
  printJson(result);
} else {
  const redaction = redactText(input, result, { minScore, replacement });
  if (textOnly) {
    console.log(redaction.redacted);
  } else {
    printJson({
      input,
      ...redaction,
    });
  }
}
