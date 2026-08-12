# PentaVault Live Scanning on Vercel via Local Agent (Option 3)

Date: 2026-04-21  
Status: Proposed design approved in conversation (4 sections validated)

## Context and Problem

PentaVault currently blocks active scan execution when running on Vercel (`scanner/web/app.py`), returning a 503 with: "Live scanning is unavailable on the Vercel deployment. Run PentaVault locally for active scanning." This protects the deployment from unsupported execution patterns for long-running, privileged, network-active security scans.

The goal is to keep the deployed Vercel UI/API experience while restoring live scanning by executing scans on a trusted local runtime.

## Alternatives Considered

1. **Private scanner VM (always-on worker)**
   - Pros: stable runtime, central worker, predictable operations
   - Cons: persistent infra cost/ops burden
2. **Managed container workers (Railway/Render/Fly/K8s)**
   - Pros: cleaner scaling and managed infra
   - Cons: orchestration and networking complexity
3. **Hybrid local agent (chosen)**
   - Pros: lowest migration risk, reuses existing scanner runtime/tooling, aligns with current local-first scan engine
   - Cons: requires agent availability on trusted machines

**Recommendation and selection:** Option 3 (Hybrid local agent) was selected.

---

## 1) Architecture

Use Vercel as a **control plane** and a local `pentavault-agent` as the **execution plane**.

- Vercel-hosted application continues to provide:
  - Dashboard/UI
  - Scan queue orchestration
  - Scan history and report retrieval
  - API auth and policy checks
- Local `pentavault-agent` process provides:
  - Claiming scan jobs from the server
  - Running the existing scan pipeline locally
  - Streaming progress/finding counters
  - Uploading final findings/summary/artifact metadata

### Boundary decision

- **No active scanning runs in Vercel runtime.**
- Active scan logic remains local and reuses existing scanner modules.
- Cloud responsibilities remain coordination/state/security.

---

## 2) Components and Data Flow

### Core components

- **Job Queue Store (server-side):** tracks job lifecycle and assignment
- **Agent Runtime (local):** polling/claim loop + scan executor
- **Status API (server-side):** progress, heartbeat, result ingestion
- **Dashboard Adapter:** renders queue/claim/running/completed states from job events

### Job states

`queued -> claimed -> running -> completed | failed | cancelled`

Each job includes:
- `job_id`
- target + scan options (`mode`, `threads`, `timeout`, `use_browser`, etc.)
- creator metadata
- timestamps (`created_at`, `claimed_at`, `started_at`, `completed_at`)
- heartbeat timestamp
- status payload (`stage`, `progress`, `findings_count`, `error`)

### Data flow

1. User submits scan request in deployed UI.
2. Server enqueues job in `queued` state.
3. Local agent calls claim endpoint; server atomically assigns one queued job.
4. Agent transitions job to `running`, executes existing pipeline locally.
5. Agent sends periodic progress and heartbeat updates.
6. Agent submits final result payload (or fail payload).
7. Server marks final state and exposes results through existing dashboard/history APIs.

### UX behavior

- If no agent is online, UI shows queued state: "waiting for local agent."
- Once claimed, UI transitions to live stage/progress visualization.
- Existing scan history continues to function with execution mode metadata.

---

## 3) Security, Error Handling, and Testing

### Security model

- **Per-agent API token**, revocable and scoped for agent endpoints.
- Tokens stored **hashed** server-side; plaintext shown only at issuance.
- Request signing with timestamp/nonce (or equivalent anti-replay mechanism).
- Optional target guardrails (allowlist/policy) to constrain misuse.

### Reliability and failure handling

- Heartbeat timeout automatically requeues stale `claimed/running` jobs.
- Result/fail endpoints are idempotent to support retries.
- Partial artifacts/progress can be stored on failure for diagnostics.
- Cancellation is cooperative: server marks cancelled; agent checks cancel state between phases/modules.

### Testing plan

- **Unit tests:**
  - job state transition rules
  - token authentication and revocation
  - heartbeat timeout and requeue logic
- **Integration tests:**
  - end-to-end claim -> running -> complete/fail lifecycle
  - retry and idempotency behavior for progress/result endpoints
- **Regression tests:**
  - preserve current local-direct scanning behavior
  - ensure Vercel path still avoids direct in-runtime scan execution
- **E2E validation:**
  - submit from deployed UI, execute through local agent, verify live progress + final report availability

---

## 4) API Contract and Rollout Plan

### New coordination endpoints

- `POST /api/scans/jobs` — enqueue scan job
- `POST /api/agent/claim` — claim next eligible queued job
- `POST /api/agent/{job_id}/progress` — stage/progress/findings updates
- `POST /api/agent/{job_id}/heartbeat` — liveness signal
- `POST /api/agent/{job_id}/result` — final success payload
- `POST /api/agent/{job_id}/fail` — structured failure payload

### Compatibility strategy

- Keep current scan API path for local-direct mode where applicable.
- Introduce `execution_mode` metadata (`local_direct` | `agent_queue`).
- Preserve existing scan status schema where feasible to minimize frontend rewrites.

### Rollout sequence

1. Add job model and agent endpoints behind feature/config flag.
2. Implement local `pentavault-agent` executable/service wrapper.
3. Connect dashboard submission/polling to queue-driven lifecycle.
4. Enable queue mode by default for Vercel deployments.
5. Keep local-direct mode for offline development and fallback operations.

### Non-goals (phase 1)

- Multi-agent scheduling optimizations
- Horizontal autoscaling orchestration
- Tenant-level RBAC expansion beyond required agent auth

---

## Success Criteria

- Deployed Vercel UI can start a scan and receive live progress when a local agent is online.
- No active scanning executes inside Vercel runtime.
- Job lifecycle remains consistent and recoverable across agent disconnects.
- Final findings/reports are persisted and visible in dashboard/history.
