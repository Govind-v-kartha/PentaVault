class ApiError extends Error {
  constructor(message, status = 500, detail = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

const JSON_HEADERS = { "Content-Type": "application/json" };

async function parseResponse(response) {
  if (response.ok) {
    const text = await response.text();
    return text ? JSON.parse(text) : {};
  }

  let detail = null;
  try {
    const payload = await response.json();
    detail = payload?.detail ?? payload;
  } catch {
    detail = null;
  }

  const message =
    (typeof detail === "string" && detail) ||
    (detail?.message && String(detail.message)) ||
    `Request failed (${response.status})`;

  throw new ApiError(message, response.status, detail);
}

export async function getFrontendMode() {
  const resp = await fetch("/api/frontend/mode");
  return parseResponse(resp);
}

export async function startScan(payload) {
  const resp = await fetch("/api/scan", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
  return parseResponse(resp);
}

export async function getScan(scanId) {
  const resp = await fetch(`/api/scan/${encodeURIComponent(scanId)}`);
  return parseResponse(resp);
}

export async function updateScan(scanId, body) {
  const resp = await fetch(`/api/scan/${encodeURIComponent(scanId)}`, {
    method: "PATCH",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
  return parseResponse(resp);
}

export async function cancelScan(scanId) {
  const resp = await fetch(`/api/scan/${encodeURIComponent(scanId)}/cancel`, {
    method: "POST",
  });
  return parseResponse(resp);
}

export async function listScans() {
  const resp = await fetch("/api/scans");
  return parseResponse(resp);
}

export async function deleteScan(scanId) {
  const resp = await fetch(`/api/scan/${encodeURIComponent(scanId)}`, {
    method: "DELETE",
  });
  return parseResponse(resp);
}

export async function fetchOwaspReference() {
  const resp = await fetch("/api/owasp");
  return parseResponse(resp);
}

export async function fetchMitreReference() {
  const resp = await fetch("/api/mitre");
  return parseResponse(resp);
}

export async function fetchMitreTactics() {
  const resp = await fetch("/api/mitre/tactics");
  return parseResponse(resp);
}

export async function fetchMitreBreakdown(scanId) {
  const resp = await fetch(`/api/scan/${encodeURIComponent(scanId)}/mitre`);
  return parseResponse(resp);
}

export async function aiAnalyze(scanId) {
  const resp = await fetch("/api/ai/analyze", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ scan_id: scanId }),
  });
  return parseResponse(resp);
}

export async function aiExecutiveSummary(scanId) {
  const resp = await fetch("/api/ai/executive-summary", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ scan_id: scanId }),
  });
  return parseResponse(resp);
}

export async function aiRemediate(scanId, findingIndex) {
  const resp = await fetch("/api/ai/remediate", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({ scan_id: scanId, finding_index: findingIndex }),
  });
  return parseResponse(resp);
}

export async function aiMitreExplain({ scanId, techniqueId, techniqueName = "", tactic = "", question = "" }) {
  const resp = await fetch("/api/ai/mitre-explain", {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify({
      scan_id: scanId,
      technique_id: techniqueId,
      technique_name: techniqueName,
      tactic,
      question,
    }),
  });
  return parseResponse(resp);
}

function parseSseBlock(raw) {
  const lines = raw.split("\n").map((line) => line.trim()).filter(Boolean);
  if (!lines.length) {
    return null;
  }

  let event = "message";
  const dataLines = [];
  for (const line of lines) {
    if (line.startsWith("event:")) {
      event = line.slice(6).trim();
      continue;
    }
    if (line.startsWith("data:")) {
      dataLines.push(line.slice(5).trim());
    }
  }

  const dataText = dataLines.join("\n");
  let data = dataText;
  if (dataText) {
    try {
      data = JSON.parse(dataText);
    } catch {
      data = dataText;
    }
  }

  return { event, data };
}

export async function consumeAiStream(endpoint, body, handlers = {}) {
  const resp = await fetch(endpoint, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });

  if (!resp.ok || !resp.body) {
    await parseResponse(resp);
    return;
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  const onEvent = handlers.onEvent ?? (() => {});
  const onError = handlers.onError ?? (() => {});
  const onDone = handlers.onDone ?? (() => {});

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }

    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split("\n\n");
    buffer = chunks.pop() ?? "";

    for (const chunk of chunks) {
      const evt = parseSseBlock(chunk);
      if (!evt) {
        continue;
      }
      onEvent(evt);
      if (evt.event === "error") {
        onError(evt.data);
      }
      if (evt.event === "done") {
        onDone(evt.data);
      }
    }
  }

  if (buffer.trim()) {
    const evt = parseSseBlock(buffer);
    if (evt) {
      onEvent(evt);
      if (evt.event === "error") {
        onError(evt.data);
      }
      if (evt.event === "done") {
        onDone(evt.data);
      }
    }
  }
}

export { ApiError };
