export function redactText(input, tokens, {
  minScore = 0.85,
  replacement = "[REDACTED:{entity}]",
} = {}) {
  const detections = buildDetections(input, tokens, minScore);
  const redacted = replaceSpans(input, detections, replacement);

  return {
    redacted,
    detections,
  };
}

function buildDetections(input, tokens, minScore) {
  const groups = groupTokens(tokens, minScore);
  const detections = [];
  let cursor = 0;

  for (const group of groups) {
    const rawText = group.tokens.map((token) => token.word ?? "").join("");
    const leadingWhitespace = rawText.length - rawText.trimStart().length;
    const trailingWhitespace = rawText.length - rawText.trimEnd().length;
    const text = rawText.trim();

    if (!text) continue;

    let rawStart = input.indexOf(rawText, cursor);
    let start;
    let end;

    if (rawStart !== -1) {
      start = rawStart + leadingWhitespace;
      end = rawStart + rawText.length - trailingWhitespace;
    } else {
      start = input.indexOf(text, cursor);
      if (start === -1) continue;
      end = start + text.length;
    }

    const span = normalizeDetectionSpan(input, group.entity, start, end);
    if (!span) continue;

    detections.push({
      entity: group.entity,
      score: average(group.tokens.map((token) => token.score)),
      start: span.start,
      end: span.end,
      text: input.slice(span.start, span.end),
    });

    cursor = span.end;
  }

  return mergeOverlapping(detections);
}

function normalizeDetectionSpan(input, entity, start, end) {
  if (entity === "private_email" || entity === "email") {
    return findOverlappingMatch(input, start, end, /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi);
  }

  if (entity === "private_phone" || entity === "phone") {
    const text = input.slice(start, end);
    if ((text.match(/\d/g) ?? []).length < 7) return null;
  }

  return { start, end };
}

function findOverlappingMatch(input, start, end, pattern) {
  for (const match of input.matchAll(pattern)) {
    const matchStart = match.index;
    const matchEnd = matchStart + match[0].length;
    if (start < matchEnd && matchStart < end) {
      return { start: matchStart, end: matchEnd };
    }
  }

  return null;
}

function groupTokens(tokens, minScore) {
  const groups = [];
  let current = null;

  for (const token of tokens) {
    if (!Number.isFinite(token.score) || token.score < minScore) {
      current = null;
      continue;
    }

    const parsed = parseEntity(token.entity);
    if (!parsed.entity) {
      current = null;
      continue;
    }

    const startsNew =
      !current ||
      parsed.prefix === "B" ||
      parsed.entity !== current.entity;

    if (startsNew) {
      current = { entity: parsed.entity, tokens: [] };
      groups.push(current);
    }

    current.tokens.push(token);

    if (parsed.prefix === "E" || parsed.prefix === "S") {
      current = null;
    }
  }

  return groups;
}

function parseEntity(value = "") {
  const match = value.match(/^(?<prefix>[BIES])-?(?<entity>.+)$/);
  if (!match?.groups) return { prefix: null, entity: value };

  return {
    prefix: match.groups.prefix,
    entity: match.groups.entity,
  };
}

function mergeOverlapping(detections) {
  const sorted = detections.toSorted((a, b) => a.start - b.start || a.end - b.end);
  const merged = [];

  for (const detection of sorted) {
    const previous = merged.at(-1);
    if (!previous || detection.start > previous.end) {
      merged.push({ ...detection });
      continue;
    }

    const previousEnd = previous.end;
    previous.end = Math.max(previous.end, detection.end);
    previous.text = previous.text + inputSliceOverlap(previous.text, detection.text, previousEnd - detection.start);
    previous.score = Math.max(previous.score, detection.score);
    if (!previous.entity.includes(detection.entity)) {
      previous.entity = `${previous.entity}+${detection.entity}`;
    }
  }

  return merged;
}

function inputSliceOverlap(previousText, nextText, overlap) {
  return previousText + nextText.slice(Math.max(0, overlap));
}

function replaceSpans(input, detections, replacement) {
  let output = "";
  let cursor = 0;

  for (const detection of detections) {
    output += input.slice(cursor, detection.start);
    output += formatReplacement(replacement, detection);
    cursor = detection.end;
  }

  return output + input.slice(cursor);
}

function formatReplacement(template, detection) {
  return template
    .replaceAll("{entity}", detection.entity)
    .replaceAll("{text}", detection.text)
    .replaceAll("{score}", detection.score.toFixed(4));
}

function average(values) {
  const finite = values.filter(Number.isFinite);
  if (finite.length === 0) return 0;
  return finite.reduce((sum, value) => sum + value, 0) / finite.length;
}
