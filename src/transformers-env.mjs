import path from "node:path";
import { mkdir } from "node:fs/promises";
import { env } from "@huggingface/transformers";

export const defaultCacheDir = ".models-cache";

export async function configureTransformers({
  cacheDir = defaultCacheDir,
  localOnly = false,
} = {}) {
  const resolvedCacheDir = path.resolve(cacheDir);
  await mkdir(resolvedCacheDir, { recursive: true });

  env.cacheDir = resolvedCacheDir;
  env.allowLocalModels = true;
  env.allowRemoteModels = !localOnly;

  return resolvedCacheDir;
}

export function progressLogger() {
  const lastLineByFile = new Map();

  return (event) => {
    if (!event?.status) return;

    if (event.status === "progress" || event.status === "progress_total") {
      const loaded = formatBytes(event.loaded);
      const total = formatBytes(event.total);
      const progress =
        typeof event.progress === "number"
          ? `${event.progress.toFixed(1)}%`
          : "unknown";
      const file = event.file ?? event.name ?? "model";
      const line = `${file}: ${progress} (${loaded}/${total})`;

      if (lastLineByFile.get(file) !== line) {
        console.error(line);
        lastLineByFile.set(file, line);
      }
      return;
    }

    if (["initiate", "download", "done", "ready"].includes(event.status)) {
      const file = event.file ? ` ${event.file}` : "";
      console.error(`${event.status}${file}`);
    }
  };
}

function formatBytes(value) {
  if (!Number.isFinite(value) || value <= 0) return "?";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;

  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }

  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}
