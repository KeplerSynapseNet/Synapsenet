const vscode = require("vscode");
const http = require("http");
const fs = require("fs");
const path = require("path");

function getConfig() {
  const cfg = vscode.workspace.getConfiguration("synapsenet");
  return {
    host: cfg.get("rpcHost", "127.0.0.1"),
    port: cfg.get("rpcPort", 8332),
    maxTokens: cfg.get("aiMaxTokens", 256),
    temperature: cfg.get("aiTemperature", 0.2),
    inlineEnabled: cfg.get("inlineEnabled", true),
    inlineMaxTokens: cfg.get("inlineMaxTokens", 96),
    inlineDebounceMs: cfg.get("inlineDebounceMs", 250),
    inlineTemperature: cfg.get("inlineTemperature", cfg.get("aiTemperature", 0.2)),
    patchMaxTokens: cfg.get("patchMaxTokens", 1024),
    patchTemperature: cfg.get("patchTemperature", 0.2)
  };
}

function rpcCall(method, params) {
  const cfg = getConfig();
  const payload = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  const options = {
    hostname: cfg.host,
    port: cfg.port,
    path: "/",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  };

  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed && parsed.error) {
            const msg = parsed.error && parsed.error.message ? parsed.error.message : "RPC error";
            reject(new Error(msg));
            return;
          }
          resolve(parsed.result);
        } catch (e) {
          reject(e);
        }
      });
    });
    const timeoutMs = method === "ai.complete" ? 300000 : 15000;
    req.setTimeout(timeoutMs, () => req.destroy(new Error("RPC timeout")));
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function sleepMs(ms, token) {
  return new Promise((resolve) => {
    if (!ms || ms <= 0) return resolve();
    const t = setTimeout(resolve, ms);
    if (token) {
      token.onCancellationRequested(() => {
        clearTimeout(t);
        resolve();
      });
    }
  });
}

function normalizeCitations(input) {
  if (!input) return [];
  const raw = input.replace(/;/g, ",");
  const parts = raw.split(",").map((s) => s.trim()).filter(Boolean);
  return parts;
}

function cleanModelText(text) {
  if (!text) return "";
  let t = String(text);
  t = t.replace(/^\s*```[a-zA-Z0-9_-]*\s*/m, "");
  t = t.replace(/```+\s*$/m, "");
  return t;
}

function stripLeadingRole(text) {
  if (!text) return "";
  let t = String(text);
  t = t.replace(/^\s*(assistant|ai|synapsenet)\s*:\s*/i, "");
  return t;
}

function buildCompletionPrompt(document, position) {
  const cfg = getConfig();
  const full = document.getText();
  const offset = document.offsetAt(position);
  const prefixMax = 12000;
  const suffixMax = 2000;
  const prefixStart = Math.max(0, offset - prefixMax);
  const suffixEnd = Math.min(full.length, offset + suffixMax);
  const prefix = full.slice(prefixStart, offset);
  const suffix = full.slice(offset, suffixEnd);
  const lang = document.languageId || "text";

  return {
    prompt:
      "You are a local code completion engine. Return only the code continuation (no markdown).\n" +
      "Language: " + lang + "\n" +
      "-----\n" +
      prefix +
      "\n<cursor>\n" +
      suffix +
      "\n-----\n" +
      "Continue after <cursor>.",
    maxTokens: cfg.maxTokens,
    temperature: cfg.temperature
  };
}

function buildInlineCompletionParams(document, position) {
  const cfg = getConfig();
  const full = document.getText();
  const offset = document.offsetAt(position);
  const prefixMax = 8000;
  const suffixMax = 800;
  const prefixStart = Math.max(0, offset - prefixMax);
  const suffixEnd = Math.min(full.length, offset + suffixMax);
  const prefix = full.slice(prefixStart, offset);
  const suffix = full.slice(offset, suffixEnd);
  const lang = document.languageId || "text";

  return {
    prompt:
      "You are a local code completion engine. Return ONLY the code to insert at <cursor> (no markdown, no explanations).\n" +
      "Language: " + lang + "\n" +
      "-----\n" +
      prefix +
      "\n<cursor>\n" +
      suffix +
      "\n-----\n" +
      "Continue after <cursor>.",
    maxTokens: cfg.inlineMaxTokens,
    temperature: cfg.inlineTemperature,
    topP: 0.9,
    topK: 40,
    stopSequences: ["\n```", "```", "\n\n\n"]
  };
}

function getWorkspaceRoot() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) return null;
  return folders[0].uri.fsPath;
}

function getWorkspaceRelPath(uri) {
  const root = getWorkspaceRoot();
  if (!root) return null;
  const abs = uri.fsPath;
  const rel = path.relative(root, abs);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) return null;
  return rel.replace(/\\/g, "/");
}

function splitLinesPreserve(text) {
  if (!text) return [];
  const t = String(text).replace(/\r\n/g, "\n");
  return t.split("\n");
}

function parseUnifiedDiff(diffText) {
  const lines = splitLinesPreserve(diffText);
  const fileDiffs = [];

  const reDiff = /^diff --git a\/(.+?) b\/(.+)$/;
  const reOld = /^--- (?:a\/(.+)|\/dev\/null)$/;
  const reNew = /^\+\+\+ (?:b\/(.+)|\/dev\/null)$/;
  const reHunk = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

  let i = 0;
  while (i < lines.length) {
    const m = reDiff.exec(lines[i]);
    if (!m) {
      i++;
      continue;
    }

    const file = {
      aPath: m[1],
      bPath: m[2],
      oldPath: null,
      newPath: null,
      hunks: []
    };
    i++;

    while (i < lines.length) {
      if (reDiff.test(lines[i])) break;

      const oldM = reOld.exec(lines[i]);
      if (oldM) {
        file.oldPath = oldM[1] || null;
        i++;
        continue;
      }
      const newM = reNew.exec(lines[i]);
      if (newM) {
        file.newPath = newM[1] || null;
        i++;
        continue;
      }

      const h = reHunk.exec(lines[i]);
      if (h) {
        const hunk = {
          oldStart: parseInt(h[1], 10),
          oldCount: h[2] ? parseInt(h[2], 10) : 1,
          newStart: parseInt(h[3], 10),
          newCount: h[4] ? parseInt(h[4], 10) : 1,
          lines: []
        };
        i++;
        while (i < lines.length) {
          if (reDiff.test(lines[i]) || reHunk.test(lines[i])) break;
          const ln = lines[i];
          if (!ln) {
            hunk.lines.push({ type: " ", content: "" });
            i++;
            continue;
          }
          const ch = ln[0];
          if (ch === " " || ch === "+" || ch === "-") {
            hunk.lines.push({ type: ch, content: ln.slice(1) });
            i++;
            continue;
          }
          if (ch === "\\") {
            i++;
            continue;
          }
          i++;
        }
        file.hunks.push(hunk);
        continue;
      }

      i++;
    }

    if (!file.oldPath && !file.newPath) {
      throw new Error("Bad diff: missing ---/+++ headers");
    }
    fileDiffs.push(file);
  }

  if (fileDiffs.length === 0) throw new Error("No diff found");
  return fileDiffs;
}

function applyHunksToText(originalText, hunks) {
  const originalLines = splitLinesPreserve(originalText);
  let idx = 0;
  const out = [];

  for (const hunk of hunks) {
    const target = Math.max(0, (hunk.oldStart || 1) - 1);
    while (idx < target && idx < originalLines.length) out.push(originalLines[idx++]);

    for (const ln of hunk.lines) {
      if (ln.type === " ") {
        const cur = idx < originalLines.length ? originalLines[idx] : undefined;
        if (cur !== ln.content) throw new Error("Hunk context mismatch");
        out.push(cur);
        idx++;
        continue;
      }
      if (ln.type === "-") {
        const cur = idx < originalLines.length ? originalLines[idx] : undefined;
        if (cur !== ln.content) throw new Error("Hunk delete mismatch");
        idx++;
        continue;
      }
      if (ln.type === "+") {
        out.push(ln.content);
        continue;
      }
    }
  }

  while (idx < originalLines.length) out.push(originalLines[idx++]);
  return out.join("\n");
}

async function computePatchEdits(diffText) {
  const root = getWorkspaceRoot();
  if (!root) throw new Error("No workspace folder");

  const fileDiffs = parseUnifiedDiff(diffText);
  const edits = [];

  for (const fd of fileDiffs) {
    const rel = fd.newPath || fd.oldPath;
    if (!rel) throw new Error("Diff missing file path");
    if (rel.startsWith("/") || rel.includes("..")) throw new Error("Unsafe path in diff: " + rel);

    if (fd.newPath === null) {
      throw new Error("Delete file diffs are not supported yet");
    }

    const absPath = path.join(root, rel);
    const uri = vscode.Uri.file(absPath);

    let originalText = "";
    let exists = true;
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      originalText = doc.getText();
    } catch (_) {
      exists = false;
      originalText = "";
    }

    const newText = applyHunksToText(originalText, fd.hunks);
    edits.push({ relPath: rel, uri, exists, originalText, newText });
  }

  return edits;
}

async function cmdModelStatus(output) {
  const res = await rpcCall("model.status", {});
  output.appendLine(JSON.stringify(res, null, 2));
  vscode.window.showInformationMessage("SynapseNet model: " + (res && res.state ? res.state : "unknown"));
}

async function cmdModelList(output) {
  const res = await rpcCall("model.list", {});
  output.appendLine(JSON.stringify(res, null, 2));

  const items = Array.isArray(res) ? res : [];
  if (items.length === 0) {
    vscode.window.showInformationMessage("No models found (try adding .gguf under ~/.synapsenet/models)");
    return;
  }

  const pick = await vscode.window.showQuickPick(
    items.map((m) => ({
      label: m.name || path.basename(m.path || ""),
      description: m.path || "",
      detail: m.sizeBytes ? String(m.sizeBytes) + " bytes" : "",
      _path: m.path
    })),
    { placeHolder: "Select a model to load" }
  );
  if (!pick || !pick._path) return;

  const loaded = await rpcCall("model.load", { path: pick._path });
  output.appendLine(JSON.stringify(loaded, null, 2));
  if (loaded && loaded.ok) {
    vscode.window.showInformationMessage("Model loaded: " + (loaded.name || pick.label));
  } else {
    vscode.window.showErrorMessage("Model load failed: " + (loaded && loaded.error ? loaded.error : "unknown"));
  }
}

async function cmdModelLoad(output) {
  const home = process.env.HOME || process.env.USERPROFILE || "";
  const defaultDir = home ? path.join(home, ".synapsenet", "models") : "";
  const defaultUri = defaultDir ? vscode.Uri.file(defaultDir) : undefined;

  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    canSelectFiles: true,
    canSelectFolders: false,
    defaultUri,
    filters: { Models: ["gguf"] },
    openLabel: "Load GGUF Model"
  });
  if (!picked || picked.length === 0) return;
  const modelPath = picked[0].fsPath;

  const res = await rpcCall("model.load", { path: modelPath });
  output.appendLine(JSON.stringify(res, null, 2));
  if (res && res.ok) {
    vscode.window.showInformationMessage("Model loaded: " + (res.name || path.basename(modelPath)));
  } else {
    vscode.window.showErrorMessage("Model load failed: " + (res && res.error ? res.error : "unknown"));
  }
}

async function cmdModelUnload(output) {
  const res = await rpcCall("model.unload", {});
  output.appendLine(JSON.stringify(res, null, 2));
  vscode.window.showInformationMessage("Model unloaded");
}

async function cmdAiStop(output) {
  const res = await rpcCall("ai.stop", {});
  output.appendLine(JSON.stringify(res, null, 2));
  vscode.window.showInformationMessage("AI stop requested");
}

async function cmdAiComplete(output) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage("No active editor");
    return;
  }

  const doc = editor.document;
  const pos = editor.selection.active;
  const selection = editor.selection && !editor.selection.isEmpty ? doc.getText(editor.selection) : "";

  let params;
  if (selection) {
    const cfg = getConfig();
    params = {
      prompt:
        "You are a local coding assistant. Return only code (no markdown).\n" +
        "Language: " + (doc.languageId || "text") + "\n" +
        "-----\n" +
        selection +
        "\n-----\n" +
        "Improve/continue this code.",
      maxTokens: cfg.maxTokens,
      temperature: cfg.temperature
    };
  } else {
    params = buildCompletionPrompt(doc, pos);
  }

  const res = await rpcCall("ai.complete", params);
  output.appendLine(JSON.stringify({ request: params, response: res }, null, 2));

  const text = cleanModelText(res && res.text ? String(res.text) : "");
  if (!text) {
    vscode.window.showErrorMessage("Empty completion");
    return;
  }

  await editor.edit((edit) => {
    edit.insert(pos, text);
  });
}

async function cmdPoeSubmitCode(output) {
  const title = await vscode.window.showInputBox({ prompt: "Code contribution title" });
  if (!title) return;

  const patchPick = await vscode.window.showOpenDialog({
    canSelectMany: false,
    canSelectFiles: true,
    canSelectFolders: false,
    openLabel: "Select patch/diff file"
  });
  if (!patchPick || patchPick.length === 0) return;
  const patchPath = patchPick[0].fsPath;

  const citationsRaw = await vscode.window.showInputBox({ prompt: "Citations (optional, comma-separated submitId/contentId hex)" });
  const citations = normalizeCitations(citationsRaw);

  const patch = fs.readFileSync(patchPath, "utf8");
  if (!patch || patch.length === 0) {
    vscode.window.showErrorMessage("Patch file is empty");
    return;
  }

  const params = { title, patch, auto_finalize: true };
  if (citations.length > 0) params.citations = citations;

  const res = await rpcCall("poe.submit_code", params);
  output.appendLine(JSON.stringify(res, null, 2));
  vscode.window.showInformationMessage("Submitted: " + (res.submitId || ""));
}

async function cmdSuggestPatch(output, previewState) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage("No active editor");
    return;
  }

  const relPath = getWorkspaceRelPath(editor.document.uri);
  if (!relPath) {
    vscode.window.showErrorMessage("File must be inside the workspace");
    return;
  }

  const instruction = await vscode.window.showInputBox({ prompt: "Describe the change (returns unified diff patch)" });
  if (!instruction) return;

  const cfg = getConfig();
  const fileText = editor.document.getText();
  if (fileText.length > 200000) {
    vscode.window.showErrorMessage("File too large for patch mode (select a smaller file)");
    return;
  }

  const params = {
    prompt:
      "You are a code editing engine.\n" +
      "Output a unified diff patch that applies cleanly.\n" +
      "No markdown. Only the diff.\n" +
      "Target file: " + relPath + "\n" +
      "Instruction: " + instruction + "\n" +
      "-----\n" +
      fileText +
      "\n-----\n" +
      "Return: diff --git a/" + relPath + " b/" + relPath + " ...",
    maxTokens: cfg.patchMaxTokens,
    temperature: cfg.patchTemperature
  };

  let res;
  try {
    res = await rpcCall("ai.complete", params);
  } catch (e) {
    vscode.window.showErrorMessage("ai.complete failed: " + String(e));
    return;
  }

  const raw = cleanModelText(res && res.text ? String(res.text) : "");
  if (!raw) {
    vscode.window.showErrorMessage("Empty patch");
    return;
  }

  let edits;
  try {
    edits = await computePatchEdits(raw);
  } catch (e) {
    output.appendLine(raw);
    vscode.window.showErrorMessage("Patch parse/apply failed: " + String(e));
    return;
  }

  previewState.lastPatchText = raw;
  previewState.lastEdits = edits;

  if (edits.length === 0) {
    vscode.window.showInformationMessage("No edits in patch");
    return;
  }

  const pick = await vscode.window.showQuickPick(
    edits.map((e) => ({ label: e.relPath })),
    { placeHolder: "Preview which file?" }
  );
  if (!pick) return;
  const chosen = edits.find((e) => e.relPath === pick.label);
  if (!chosen) return;

  const baseUri = vscode.Uri.from({ scheme: "synapsenet-preview", path: "/orig/" + chosen.relPath });
  const newUri = vscode.Uri.from({ scheme: "synapsenet-preview", path: "/new/" + chosen.relPath });
  previewState.previewContent.set(baseUri.toString(), chosen.originalText);
  previewState.previewContent.set(newUri.toString(), chosen.newText);

  await vscode.commands.executeCommand("vscode.diff", baseUri, newUri, "SynapseNet Patch: " + chosen.relPath);

  const choice = await vscode.window.showInformationMessage("Apply patch to workspace?", "Apply", "Cancel");
  if (choice !== "Apply") return;

  const we = new vscode.WorkspaceEdit();
  for (const e of edits) {
    if (!e.exists) {
      we.createFile(e.uri, { overwrite: false, ignoreIfExists: true });
      we.insert(e.uri, new vscode.Position(0, 0), e.newText);
      continue;
    }
    const doc = await vscode.workspace.openTextDocument(e.uri);
    const end = doc.lineCount > 0 ? doc.lineAt(doc.lineCount - 1).range.end : new vscode.Position(0, 0);
    we.replace(e.uri, new vscode.Range(new vscode.Position(0, 0), end), e.newText);
  }
  const ok = await vscode.workspace.applyEdit(we);
  if (!ok) {
    vscode.window.showErrorMessage("Failed to apply workspace edit");
    return;
  }
  await vscode.workspace.saveAll(false);

  const submitChoice = await vscode.window.showInformationMessage("Submit this patch as PoE code contribution?", "Submit", "Skip");
  if (submitChoice !== "Submit") return;

  const title = await vscode.window.showInputBox({ prompt: "Code contribution title", value: instruction.slice(0, 120) });
  if (!title) return;
  const citationsRaw = await vscode.window.showInputBox({ prompt: "Citations (optional, comma-separated submitId/contentId hex)" });
  const citations = normalizeCitations(citationsRaw);

  const submitParams = { title, patch: raw, auto_finalize: true };
  if (citations.length > 0) submitParams.citations = citations;
  const submitRes = await rpcCall("poe.submit_code", submitParams);
  output.appendLine(JSON.stringify(submitRes, null, 2));
  vscode.window.showInformationMessage("Submitted: " + (submitRes.submitId || ""));
}

async function cmdToggleInline() {
  const cfg = vscode.workspace.getConfiguration("synapsenet");
  const cur = cfg.get("inlineEnabled", true);
  await cfg.update("inlineEnabled", !cur, vscode.ConfigurationTarget.Global);
  vscode.window.showInformationMessage("SynapseNet inline completions: " + (!cur ? "ON" : "OFF"));
}

function buildChatPrompt(messages) {
  const maxMsgs = 16;
  const slice = messages.length > maxMsgs ? messages.slice(messages.length - maxMsgs) : messages;
  let p =
    "You are a local AI agent running inside SynapseNet.\n" +
    "Return only the assistant answer (no markdown unless the user asks).\n" +
    "If the user asks for code, output code only.\n" +
    "Conversation:\n";
  for (const m of slice) {
    const role = m.role === "user" ? "User" : "Assistant";
    p += role + ": " + String(m.content || "") + "\n";
  }
  p += "Assistant:";
  return p;
}

function chatHtml(initialState) {
  const s = JSON.stringify(initialState || {});
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SynapseNet Chat</title>
  <style>
    :root { color-scheme: dark; }
    html, body { height: 100%; margin: 0; padding: 0; background: #0b0d10; color: #e7e7e7; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .wrap { display: flex; flex-direction: column; height: 100%; }
    .top { display: flex; gap: 12px; align-items: center; padding: 10px 12px; border-bottom: 1px solid #1b222d; background: #0b0d10; }
    .top .pill { padding: 4px 8px; border: 1px solid #1b222d; border-radius: 999px; font-size: 12px; color: #9fb3c8; }
    .top label { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: #cbd5e1; }
    .top input[type="checkbox"] { transform: translateY(1px); }
    .top input[type="number"] { width: 84px; background: #0f141a; border: 1px solid #1b222d; color: #e7e7e7; border-radius: 8px; padding: 4px 8px; }
    .msgs { flex: 1; overflow: auto; padding: 14px 12px; }
    .msg { max-width: 960px; margin: 0 auto 12px auto; padding: 10px 12px; border: 1px solid #1b222d; border-radius: 12px; background: #0f141a; }
    .msg.user { border-color: #1f7a8c55; }
    .msg.assistant { border-color: #7f5af055; }
    .meta { display: flex; gap: 10px; font-size: 11px; color: #94a3b8; margin-bottom: 8px; }
    .content { white-space: pre-wrap; word-break: break-word; line-height: 1.35; }
    .bottom { padding: 10px 12px; border-top: 1px solid #1b222d; background: #0b0d10; }
    .row { max-width: 960px; margin: 0 auto; display: flex; gap: 8px; align-items: center; }
    textarea { flex: 1; resize: none; height: 60px; background: #0f141a; border: 1px solid #1b222d; color: #e7e7e7; border-radius: 12px; padding: 10px 12px; font-family: inherit; }
    button { background: #151b22; border: 1px solid #1b222d; color: #e7e7e7; border-radius: 12px; padding: 10px 12px; cursor: pointer; }
    button:hover { border-color: #2a3546; }
    button.primary { background: #1f7a8c; border-color: #1f7a8c; }
    button.primary:hover { background: #236c7a; border-color: #236c7a; }
    button.danger { background: #5b1f1f; border-color: #5b1f1f; }
    button.danger:hover { background: #6a2424; border-color: #6a2424; }
    .status { max-width: 960px; margin: 10px auto 0 auto; font-size: 12px; color: #9fb3c8; }
    .hint { color: #64748b; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <span class="pill" id="modelPill">model: -</span>
      <span class="pill" id="webPill">web: off</span>
      <label><input type="checkbox" id="webInject" /> Web inject</label>
      <label><input type="checkbox" id="webOnion" /> Onion</label>
      <label><input type="checkbox" id="webTor" /> Tor clearnet</label>
      <label>maxTokens <input type="number" id="maxTokens" min="1" max="8192" /></label>
      <label>temp <input type="number" id="temperature" min="0" max="2" step="0.05" /></label>
    </div>
    <div class="msgs" id="msgs"></div>
    <div class="bottom">
      <div class="row">
        <textarea id="input" placeholder="Ask the local agent…" spellcheck="false"></textarea>
        <button class="primary" id="sendBtn">Send</button>
        <button class="danger" id="stopBtn">Stop</button>
        <button id="clearBtn">Clear</button>
      </div>
      <div class="status" id="statusLine"><span class="hint">Enter to send • Shift+Enter newline</span></div>
    </div>
  </div>

  <script>
    const vscode = acquireVsCodeApi();
    let state = ${s};

    const elMsgs = document.getElementById("msgs");
    const elInput = document.getElementById("input");
    const elSend = document.getElementById("sendBtn");
    const elStop = document.getElementById("stopBtn");
    const elClear = document.getElementById("clearBtn");
    const elModel = document.getElementById("modelPill");
    const elWeb = document.getElementById("webPill");
    const elWebInject = document.getElementById("webInject");
    const elWebOnion = document.getElementById("webOnion");
    const elWebTor = document.getElementById("webTor");
    const elMaxTokens = document.getElementById("maxTokens");
    const elTemp = document.getElementById("temperature");
    const elStatus = document.getElementById("statusLine");

    function safeBool(v) { return !!v; }
    function safeNum(v, def) { const n = Number(v); return Number.isFinite(n) ? n : def; }

    function setState(next) {
      state = next || {};
      render();
    }

    function render() {
      const msgs = Array.isArray(state.messages) ? state.messages : [];
      elMsgs.innerHTML = "";
      for (const m of msgs) {
        const wrap = document.createElement("div");
        wrap.className = "msg " + (m.role === "user" ? "user" : "assistant");
        const meta = document.createElement("div");
        meta.className = "meta";
        const who = document.createElement("span");
        who.textContent = m.role === "user" ? "You" : "AI";
        meta.appendChild(who);
        if (m.model) {
          const model = document.createElement("span");
          model.textContent = "model: " + m.model;
          meta.appendChild(model);
        }
        if (m.web && typeof m.web.lastResults === "number") {
          const w = document.createElement("span");
          w.textContent = "web: " + m.web.lastResults + " (clearnet " + (m.web.lastClearnetResults || 0) + ", onion " + (m.web.lastDarknetResults || 0) + ")";
          meta.appendChild(w);
        }
        wrap.appendChild(meta);
        const content = document.createElement("div");
        content.className = "content";
        content.textContent = String(m.content || "");
        wrap.appendChild(content);
        elMsgs.appendChild(wrap);
      }

      const opts = state.options || {};
      elWebInject.checked = safeBool(opts.webInject);
      elWebOnion.checked = safeBool(opts.webOnion);
      elWebTor.checked = safeBool(opts.webTor);
      elMaxTokens.value = String(safeNum(opts.maxTokens, 256));
      elTemp.value = String(safeNum(opts.temperature, 0.2));

      const st = state.status || {};
      elModel.textContent = "model: " + (st.model || "-");
      elWeb.textContent = "web: " + (opts.webInject ? (opts.webOnion ? "clearnet+onion" : "clearnet") : "off");

      if (st.generating) {
        elStatus.textContent = "Generating…";
      } else if (st.error) {
        elStatus.textContent = "Error: " + st.error;
      } else {
        elStatus.innerHTML = '<span class="hint">Enter to send • Shift+Enter newline</span>';
      }

      if (st.autoScroll !== false) {
        elMsgs.scrollTop = elMsgs.scrollHeight;
      }
    }

    function collectOptions() {
      return {
        webInject: elWebInject.checked,
        webOnion: elWebOnion.checked,
        webTor: elWebTor.checked,
        maxTokens: safeNum(elMaxTokens.value, 256),
        temperature: safeNum(elTemp.value, 0.2)
      };
    }

    function send() {
      const text = String(elInput.value || "");
      const trimmed = text.trim();
      if (!trimmed) return;
      const options = collectOptions();
      elInput.value = "";
      vscode.postMessage({ type: "send", text: trimmed, options });
    }

    elSend.addEventListener("click", send);
    elStop.addEventListener("click", () => vscode.postMessage({ type: "stop" }));
    elClear.addEventListener("click", () => vscode.postMessage({ type: "clear" }));

    elInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        send();
      }
    });

    window.addEventListener("message", (event) => {
      const msg = event.data;
      if (!msg || !msg.type) return;
      if (msg.type === "state") setState(msg.state);
    });

    vscode.postMessage({ type: "ready" });
    render();
  </script>
</body>
</html>`;
}

async function cmdOpenChat(context, output, chatState) {
  if (chatState.panel) {
    chatState.panel.reveal(vscode.ViewColumn.Beside);
    return;
  }

  const cfg = getConfig();
  chatState.options = chatState.options || {
    webInject: false,
    webOnion: false,
    webTor: false,
    maxTokens: cfg.maxTokens,
    temperature: cfg.temperature
  };

  const panel = vscode.window.createWebviewPanel(
    "synapsenetChat",
    "SynapseNet Chat",
    vscode.ViewColumn.Beside,
    { enableScripts: true, retainContextWhenHidden: true }
  );
  chatState.panel = panel;

  const state = {
    messages: chatState.messages || [],
    options: chatState.options,
    status: { model: "", generating: false, error: "" }
  };
  panel.webview.html = chatHtml(state);

  const postState = (s) => {
    try {
      panel.webview.postMessage({ type: "state", state: s });
    } catch (_) {}
  };

  const updateStatus = async (s, opts) => {
    let modelName = "";
    try {
      const st = await rpcCall("model.status", {});
      if (st && st.name) modelName = String(st.name);
    } catch (_) {}
    const next = { ...s, options: opts, status: { ...(s.status || {}), model: modelName } };
    postState(next);
    return next;
  };

  let current = await updateStatus(state, chatState.options);

  panel.onDidDispose(() => {
    chatState.panel = null;
  }, null, context.subscriptions);

  panel.webview.onDidReceiveMessage(async (msg) => {
    if (!msg || !msg.type) return;

    if (msg.type === "ready") {
      postState(current);
      return;
    }

    if (msg.type === "clear") {
      chatState.messages = [];
      current = { ...current, messages: [], status: { ...(current.status || {}), generating: false, error: "" } };
      postState(current);
      return;
    }

    if (msg.type === "stop") {
      try {
        await rpcCall("ai.stop", {});
      } catch (_) {}
      return;
    }

    if (msg.type !== "send") return;
    const text = String(msg.text || "").trim();
    if (!text) return;

    const opts = msg.options || {};
    chatState.options = {
      webInject: !!opts.webInject,
      webOnion: !!opts.webOnion,
      webTor: !!opts.webTor,
      maxTokens: Math.max(1, Math.min(8192, Number(opts.maxTokens) || cfg.maxTokens)),
      temperature: Math.max(0, Math.min(2, Number(opts.temperature) || cfg.temperature))
    };

    chatState.messages = chatState.messages || [];
    chatState.messages.push({ role: "user", content: text });

    current = { ...current, messages: chatState.messages, options: chatState.options, status: { ...(current.status || {}), generating: true, error: "" } };
    current = await updateStatus(current, chatState.options);

    const prompt = buildChatPrompt(chatState.messages);
    const params = {
      prompt,
      maxTokens: chatState.options.maxTokens,
      temperature: chatState.options.temperature,
      topP: 0.9,
      topK: 40,
      stopSequences: ["\nUser:", "\nAssistant:", "\nYou:"]
    };
    if (chatState.options.webInject) {
      params.webInject = true;
      params.webOnion = chatState.options.webOnion;
      params.webTor = chatState.options.webTor;
      params.webQuery = text;
    }

    try {
      const res = await rpcCall("ai.complete", params);
      const raw = res && res.text ? String(res.text) : "";
      const out = stripLeadingRole(raw).trim();
      chatState.messages.push({
        role: "assistant",
        content: out || "[empty response]",
        model: res && res.model ? String(res.model) : "",
        web: res && res.web ? res.web : null
      });
      current = { ...current, messages: chatState.messages, status: { ...(current.status || {}), generating: false, error: "" } };
      current = await updateStatus(current, chatState.options);
    } catch (e) {
      current = { ...current, status: { ...(current.status || {}), generating: false, error: String(e) } };
      current = await updateStatus(current, chatState.options);
    }
  }, null, context.subscriptions);
}

function activate(context) {
  const output = vscode.window.createOutputChannel("SynapseNet");
  output.appendLine("SynapseNet extension activated");

  const previewState = {
    previewContent: new Map(),
    lastPatchText: "",
    lastEdits: []
  };

  const chatState = {
    panel: null,
    messages: [],
    options: null
  };

  const inlineCache = new Map();
  let inlineInFlight = false;

  const previewProvider = {
    provideTextDocumentContent: (uri) => {
      return previewState.previewContent.get(uri.toString()) || "";
    }
  };

  function cachePut(key, value) {
    inlineCache.set(key, { value, ts: Date.now() });
    if (inlineCache.size <= 64) return;
    let oldestKey = null;
    let oldestTs = Infinity;
    for (const [k, v] of inlineCache.entries()) {
      if (v.ts < oldestTs) {
        oldestTs = v.ts;
        oldestKey = k;
      }
    }
    if (oldestKey) inlineCache.delete(oldestKey);
  }

  const inlineProvider = {
    provideInlineCompletionItems: async (document, position, _context, token) => {
      const cfg = getConfig();
      if (!cfg.inlineEnabled) return [];
      if (token && token.isCancellationRequested) return [];
      if (inlineInFlight) return [];

      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.uri.toString() !== document.uri.toString()) return [];
      if (editor.selection && !editor.selection.isEmpty) return [];

      await sleepMs(cfg.inlineDebounceMs, token);
      if (token && token.isCancellationRequested) return [];

      const key = document.uri.toString() + "@" + document.version + ":" + document.offsetAt(position);
      const cached = inlineCache.get(key);
      if (cached && cached.value) {
        return [new vscode.InlineCompletionItem(cached.value, new vscode.Range(position, position))];
      }

      const params = buildInlineCompletionParams(document, position);

      inlineInFlight = true;
      try {
        const res = await rpcCall("ai.complete", params);
        const text = cleanModelText(res && res.text ? res.text : "");
        if (!text) return [];

        const clipped = text.length > 4000 ? text.slice(0, 4000) : text;
        cachePut(key, clipped);
        return [new vscode.InlineCompletionItem(clipped, new vscode.Range(position, position))];
      } catch (_) {
        return [];
      } finally {
        inlineInFlight = false;
      }
    }
  };

  context.subscriptions.push(
    output,
    vscode.commands.registerCommand("synapsenet.modelStatus", () => cmdModelStatus(output).catch((e) => vscode.window.showErrorMessage(String(e)))),
    vscode.commands.registerCommand("synapsenet.modelList", () => cmdModelList(output).catch((e) => vscode.window.showErrorMessage(String(e)))),
    vscode.commands.registerCommand("synapsenet.modelLoad", () => cmdModelLoad(output).catch((e) => vscode.window.showErrorMessage(String(e)))),
    vscode.commands.registerCommand("synapsenet.modelUnload", () => cmdModelUnload(output).catch((e) => vscode.window.showErrorMessage(String(e)))),
    vscode.commands.registerCommand("synapsenet.aiComplete", () => cmdAiComplete(output).catch((e) => vscode.window.showErrorMessage(String(e)))),
    vscode.commands.registerCommand("synapsenet.aiStop", () => cmdAiStop(output).catch((e) => vscode.window.showErrorMessage(String(e)))),
    vscode.commands.registerCommand("synapsenet.openChat", () => cmdOpenChat(context, output, chatState).catch((e) => vscode.window.showErrorMessage(String(e)))),
    vscode.commands.registerCommand("synapsenet.toggleInline", () => cmdToggleInline().catch((e) => vscode.window.showErrorMessage(String(e)))),
    vscode.commands.registerCommand("synapsenet.suggestPatch", () => cmdSuggestPatch(output, previewState).catch((e) => vscode.window.showErrorMessage(String(e)))),
    vscode.workspace.registerTextDocumentContentProvider("synapsenet-preview", previewProvider),
    vscode.languages.registerInlineCompletionItemProvider({ pattern: "**" }, inlineProvider),
    vscode.commands.registerCommand("synapsenet.poeSubmitCode", () => cmdPoeSubmitCode(output).catch((e) => vscode.window.showErrorMessage(String(e))))
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
