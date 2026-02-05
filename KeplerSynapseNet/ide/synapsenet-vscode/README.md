# SynapseNet VS Code Extension (prototype)

This is a minimal first step towards **Synapse IDE (AI CODING + NGT)**.

It talks to a running `synapsed` via local JSON-RPC:
- `model.*` (load/status)
- `ai.complete` (completion)
- IDE chat panel (Copilot-like) via `ai.complete` (optional Web4 injection)
- inline (ghost text) completions via `ai.complete`
- patch suggestions (preview/apply) via `ai.complete` (unified diff)
- `poe.submit_code` (submit a patch/diff as a CODE contribution)

## Run synapsed

Start the node (TUI or daemon). RPC must be enabled (default `8332`).

Example:

```bash
TERM=xterm-256color ./KeplerSynapseNet/build/synapsed
```

## Use in VS Code

1. Open this folder in VS Code.
2. Open `ide/synapsenet-vscode/`.
3. Run the Extension Host (F5 in the VS Code extension dev workflow).
4. In the Extension Host window:
   - `SynapseNet: Model Status`
   - `SynapseNet: Model List (Quick Pick)`
   - `SynapseNet: Load Model`
   - `SynapseNet: Unload Model`
   - `SynapseNet: AI Complete (Insert)`
   - `SynapseNet: AI Stop`
   - `SynapseNet: Open Chat (Web4 optional)`
   - `SynapseNet: Toggle Inline Completions`
   - `SynapseNet: Suggest Patch (Preview/Apply)`
   - `SynapseNet: Submit Code Patch (PoE)`

Settings:
- `synapsenet.rpcHost` (default `127.0.0.1`)
- `synapsenet.rpcPort` (default `8332`)
- `synapsenet.inlineEnabled` (default `true`)
- `synapsenet.inlineDebounceMs` (default `250`)
- `synapsenet.inlineMaxTokens` (default `96`)
- `synapsenet.patchMaxTokens` (default `1024`)
