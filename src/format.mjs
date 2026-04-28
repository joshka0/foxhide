export function printJson(value) {
  console.log(JSON.stringify(value, null, 2));
}

export function readFlag(args, name, fallback = undefined) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`Missing value for ${name}`);
  }
  return value;
}

export function hasFlag(args, name) {
  return args.includes(name);
}

export function readInput(args, fallback = "") {
  const cleanArgs = args.filter((arg) => arg !== "--");
  const flagInput = readFlag(cleanArgs, "--input", undefined);
  if (flagInput !== undefined) return flagInput;

  const positional = cleanArgs.filter((arg, index) => {
    const previous = cleanArgs[index - 1];
    return !arg.startsWith("--") && !previous?.startsWith("--");
  });

  return positional.length > 0 ? positional.join(" ") : fallback;
}

export function usage({ command, task, model, input }) {
  return [
    `Usage: ${command} --task ${task} --model ${model} --input "${input}"`,
    "",
    "Flags:",
    "  --task <task>        Transformers.js pipeline task",
    "  --model <model>      Hugging Face model id",
    "  --input <text>       Text to pass into the pipeline",
    "  --options <json>     JSON options passed to pipeline(...)",
    "  --args <json>        JSON options passed to pipe(input, ...)",
    "  --cache-dir <path>   Model cache directory, default .models-cache",
    "  --local              Use cached/local model files only",
    "  --redact             Replace detected private text in the input",
    "  --replacement <text> Replacement template, default [REDACTED:{entity}]",
    "  --min-score <num>    Minimum token confidence for redaction, default 0.85",
    "  --text               Print only redacted text when used with --redact",
    "  --quiet              Suppress progress logs",
    "  --examples           Print model examples",
    "  --help               Print this help",
  ].join("\n");
}

export function parseJsonFlag(args, name, fallback = "{}") {
  const value = readFlag(args, name, fallback);
  try {
    return JSON.parse(value);
  } catch (error) {
    throw new Error(`${name} must be valid JSON: ${error.message}`);
  }
}
