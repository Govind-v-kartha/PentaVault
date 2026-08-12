# Live Scanning via Local Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable live scanning from the deployed Vercel UI by queueing scan jobs in the API and executing them on a trusted local `pentavault-agent` worker.

**Architecture:** The FastAPI server becomes a control plane for queued scan jobs (`queued/claimed/running/completed/failed/cancelled`) while scan execution remains local. A local agent claims jobs over authenticated endpoints, runs the existing scan pipeline, and pushes progress/results back. React UI treats `queued`/`claimed` as active pre-execution states and preserves current local-direct behavior for non-Vercel execution.

**Tech Stack:** Python 3.13, FastAPI, unittest, requests/httpx, React 18 + Vite + Vitest, Vercel deployment.

---

## File Structure (decomposition before implementation)

### Create
- `scanner/agent/__init__.py` — agent package marker.
- `scanner/agent/auth.py` — token hashing, issue/revoke/verify, JSON token registry I/O.
- `scanner/agent/worker.py` — polling worker loop, claim/progress/heartbeat/result/fail transport.
- `scanner/agent/__main__.py` — CLI entrypoint (`run`, `issue-token`, `revoke-token`).
- `scanner/tests/test_agent_auth.py` — auth/token registry regression tests.
- `scanner/tests/test_agent_queue_api.py` — queue lifecycle and agent endpoint tests.
- `scanner/tests/test_agent_worker.py` — worker claim/execute/report tests with mocked transport.
- `scanner/web/frontend/src/pages/LiveScanPage.test.jsx` — queued/claimed live UI behavior tests.
- `.env.example` — placeholder env vars including agent settings.

### Modify
- `scanner/web/app.py` — queue state helpers, Vercel queue branch in `/api/scan`, new agent endpoints, heartbeat requeue handling, queue-aware cancel behavior.
- `scanner/web/frontend/src/pages/LiveScanPage.jsx` — queued/claimed status UX and terminal-state handling.
- `scanner/web/frontend/src/api/client.js` — optional typed helpers for queue metadata fields from existing APIs.
- `README.md` — local agent setup/operation docs for Vercel live scanning.
- `context.md` — architecture and API endpoint updates for agent queue model.

### Test Targets
- `python -m unittest scanner.tests.test_agent_auth -v`
- `python -m unittest scanner.tests.test_agent_queue_api -v`
- `python -m unittest scanner.tests.test_agent_worker -v`
- `python -m unittest scanner.tests.test_scan_runtime_metadata -v`
- `python -m unittest discover -s scanner/tests -p "test_*.py"`
- `npm --prefix scanner/web/frontend run test -- src/pages/LiveScanPage.test.jsx`
- `npm --prefix scanner/web/frontend run test`

---

### Task 1: Agent token registry and verification primitives

**Files:**
- Create: `scanner/agent/auth.py`
- Create: `scanner/tests/test_agent_auth.py`

- [ ] **Step 1: Write failing auth tests**

```python
# scanner/tests/test_agent_auth.py
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scanner.agent.auth import issue_agent_token, revoke_agent_token, verify_agent_token


class TestAgentAuth(unittest.TestCase):
    def test_issue_and_verify_roundtrip(self):
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            token_id, plaintext = issue_agent_token(data_dir, label="dev-laptop")

            record = verify_agent_token(data_dir, plaintext)
            self.assertIsNotNone(record)
            self.assertEqual(record["id"], token_id)
            self.assertEqual(record["label"], "dev-laptop")

    def test_revoked_token_is_rejected(self):
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            token_id, plaintext = issue_agent_token(data_dir, label="revocation-test")
            self.assertTrue(revoke_agent_token(data_dir, token_id))

            record = verify_agent_token(data_dir, plaintext)
            self.assertIsNone(record)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest scanner.tests.test_agent_auth -v`  
Expected: FAIL with `ModuleNotFoundError: No module named 'scanner.agent.auth'`

- [ ] **Step 3: Write minimal token registry implementation**

```python
# scanner/agent/auth.py
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _registry_path(data_dir: Path) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "agent_tokens.json"


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _load_registry(data_dir: Path) -> dict[str, Any]:
    path = _registry_path(data_dir)
    if not path.exists():
        return {"version": 1, "tokens": []}
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
        return {"version": 1, "tokens": []}
    return data


def _save_registry(data_dir: Path, registry: dict[str, Any]) -> None:
    path = _registry_path(data_dir)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)
    tmp.replace(path)


def issue_agent_token(data_dir: Path, label: str) -> tuple[str, str]:
    plaintext = f"pvagt_{secrets.token_urlsafe(32)}"
    token_id = f"agt_{secrets.token_hex(6)}"
    now = _utc_now()

    registry = _load_registry(data_dir)
    registry["tokens"].append(
        {
            "id": token_id,
            "label": label,
            "hash": _hash_token(plaintext),
            "created_at": now,
            "revoked_at": None,
        }
    )
    _save_registry(data_dir, registry)
    return token_id, plaintext


def revoke_agent_token(data_dir: Path, token_id: str) -> bool:
    registry = _load_registry(data_dir)
    changed = False
    now = _utc_now()
    for rec in registry["tokens"]:
        if rec.get("id") == token_id and rec.get("revoked_at") is None:
            rec["revoked_at"] = now
            changed = True
    if changed:
        _save_registry(data_dir, registry)
    return changed


def verify_agent_token(data_dir: Path, plaintext: str) -> dict[str, Any] | None:
    candidate = _hash_token(plaintext)
    registry = _load_registry(data_dir)
    for rec in registry["tokens"]:
        if rec.get("revoked_at") is not None:
            continue
        token_hash = rec.get("hash", "")
        if hmac.compare_digest(token_hash, candidate):
            return rec
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m unittest scanner.tests.test_agent_auth -v`  
Expected: PASS (`ok` for 2 tests)

- [ ] **Step 5: Commit**

```bash
git add scanner/agent/auth.py scanner/tests/test_agent_auth.py
git commit -m "feat(agent-auth): add token issue verify and revoke primitives"
```

---

### Task 2: Queue state helpers and stale-job recovery in backend

**Files:**
- Modify: `scanner/web/app.py`
- Test: `scanner/tests/test_agent_queue_api.py`

- [ ] **Step 1: Write failing queue helper tests**

```python
# scanner/tests/test_agent_queue_api.py
import unittest
from datetime import datetime, timedelta

from scanner.web import app as web_app


class TestAgentQueueHelpers(unittest.TestCase):
    def test_build_agent_queue_scan_defaults(self):
        req = web_app.ScanRequest(target="https://example.com", mode="quick")
        scan = web_app._build_agent_queue_scan("job-1", req)

        self.assertEqual(scan["scan_id"], "job-1")
        self.assertEqual(scan["status"], "queued")
        self.assertEqual(scan["execution_mode"], "agent_queue")
        self.assertEqual(scan["progress"], 0)
        self.assertEqual(scan["current_stage"], "Queued for local agent")

    def test_requeue_stale_claimed_job(self):
        sid = "job-stale"
        web_app.scans[sid] = {
            "scan_id": sid,
            "status": "claimed",
            "execution_mode": "agent_queue",
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "agent_heartbeat_at": (datetime.utcnow() - timedelta(minutes=10)).replace(microsecond=0).isoformat() + "Z",
            "current_stage": "Claimed by agent",
            "progress": 0,
            "findings": [],
            "stages": [],
            "summary": {},
            "findings_count": 0,
        }

        try:
            web_app._requeue_stale_agent_jobs(timeout_seconds=30)
            self.assertEqual(web_app.scans[sid]["status"], "queued")
            self.assertEqual(web_app.scans[sid]["current_stage"], "Queued for local agent")
        finally:
            web_app.scans.pop(sid, None)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest scanner.tests.test_agent_queue_api.TestAgentQueueHelpers -v`  
Expected: FAIL with `AttributeError` for missing `_build_agent_queue_scan` and `_requeue_stale_agent_jobs`

- [ ] **Step 3: Implement queue helper functions in `scanner/web/app.py`**

```python
# add near other helpers in scanner/web/app.py
from datetime import datetime, timezone

_AGENT_ACTIVE_STATES = {"queued", "claimed", "running"}
_TERMINAL_STATES = {"completed", "failed", "cancelled"}


def _utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _build_agent_queue_scan(scan_id: str, req: ScanRequest) -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "status": "queued",
        "execution_mode": "agent_queue",
        "target": req.target,
        "url": "",
        "mode": req.mode,
        "threads": req.threads,
        "timeout": req.timeout,
        "request_delay": req.request_delay,
        "cookie": req.cookie,
        "use_browser": req.use_browser,
        "crawl_mode": req.crawl_mode,
        "progress": 0,
        "current_stage": "Queued for local agent",
        "stages": [],
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "completed_at": None,
        "elapsed": 0,
        "findings": [],
        "findings_count": 0,
        "summary": {},
        "module_results": {},
        "recon_data": None,
        "fingerprint_data": None,
        "crawl_summary": None,
        "report_path": None,
        "error": None,
        "agent_id": None,
        "agent_claimed_at": None,
        "agent_heartbeat_at": None,
        "runtime_config": {
            "mode": req.mode,
            "threads": req.threads,
            "timeout_seconds": req.timeout,
            "request_delay_seconds": req.request_delay,
            "use_browser": req.use_browser,
            "crawl_mode": req.crawl_mode,
        },
        "execution_metadata": {
            "http_parallelization": "threadpool",
            "http_module_workers": req.threads,
            "resolved_crawl_mode": req.crawl_mode,
            "browser_module_execution": "disabled",
            "browser_module_timeout_seconds": 0,
            "http_module_count": 0,
            "browser_module_count": 0,
        },
    }


def _requeue_stale_agent_jobs(timeout_seconds: int) -> None:
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    for scan in scans.values():
        if scan.get("execution_mode") != "agent_queue":
            continue
        if scan.get("status") not in {"claimed", "running"}:
            continue
        hb_raw = scan.get("agent_heartbeat_at")
        if not isinstance(hb_raw, str) or not hb_raw:
            continue
        try:
            hb = datetime.fromisoformat(hb_raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        age = (now - hb).total_seconds()
        if age > timeout_seconds:
            scan["status"] = "queued"
            scan["current_stage"] = "Queued for local agent"
            scan["agent_id"] = None
            scan["agent_claimed_at"] = None
            scan["agent_heartbeat_at"] = None
```

- [ ] **Step 4: Run helper tests again**

Run: `python -m unittest scanner.tests.test_agent_queue_api.TestAgentQueueHelpers -v`  
Expected: PASS (`ok`)

- [ ] **Step 5: Commit**

```bash
git add scanner/web/app.py scanner/tests/test_agent_queue_api.py
git commit -m "feat(agent-queue): add queued scan state and stale-job requeue helpers"
```

---

### Task 3: Agent API endpoints and Vercel queue flow

**Files:**
- Modify: `scanner/web/app.py`
- Modify/Test: `scanner/tests/test_agent_queue_api.py`

- [ ] **Step 1: Add failing endpoint lifecycle tests**

```python
# append to scanner/tests/test_agent_queue_api.py
from unittest.mock import patch


class TestAgentQueueLifecycle(unittest.IsolatedAsyncioTestCase):
    async def test_vercel_start_scan_enqueues_instead_of_503(self):
        req = web_app.ScanRequest(target="https://example.com", mode="quick")

        with patch("scanner.web.app._IS_VERCEL", True):
            payload = await web_app.start_scan(req)

        scan_id = payload["scan_id"]
        try:
            self.assertEqual(payload["status"], "queued")
            self.assertEqual(web_app.scans[scan_id]["status"], "queued")
            self.assertEqual(web_app.scans[scan_id]["execution_mode"], "agent_queue")
        finally:
            web_app.scans.pop(scan_id, None)

    async def test_claim_progress_result_flow(self):
        req = web_app.ScanRequest(target="https://example.com", mode="quick")
        with patch("scanner.web.app._IS_VERCEL", True):
            queued = await web_app.start_scan(req)

        scan_id = queued["scan_id"]
        token_id, token = web_app.issue_agent_token(web_app.DATA_DIR, label="test-agent")

        try:
            claim = await web_app.agent_claim(
                web_app.AgentClaimRequest(agent_id="agent-1"),
                authorization=f"Bearer {token}",
            )
            self.assertEqual(claim["job"]["job_id"], scan_id)

            progress_resp = await web_app.agent_progress(
                scan_id,
                web_app.AgentProgressRequest(stage="Web Crawling", progress=30, findings_count=2, module_results={"Headers": 1}),
                authorization=f"Bearer {token}",
            )
            self.assertTrue(progress_resp["updated"])

            result_resp = await web_app.agent_result(
                scan_id,
                web_app.AgentResultRequest(
                    findings=[{"severity": "Low", "detail": "test"}],
                    summary={"total": 1},
                    stages=[{"name": "Vulnerability Testing", "time": 1.2}],
                    elapsed=2.5,
                ),
                authorization=f"Bearer {token}",
            )
            self.assertTrue(result_resp["accepted"])
            self.assertEqual(web_app.scans[scan_id]["status"], "completed")
        finally:
            web_app.revoke_agent_token(web_app.DATA_DIR, token_id)
            web_app.scans.pop(scan_id, None)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest scanner.tests.test_agent_queue_api.TestAgentQueueLifecycle -v`  
Expected: FAIL (missing models/endpoints, and `start_scan` still raises 503 on Vercel)

- [ ] **Step 3: Implement queue-aware API behavior and agent endpoints**

```python
# key additions in scanner/web/app.py
from fastapi import FastAPI, Header, HTTPException
from scanner.agent.auth import issue_agent_token, revoke_agent_token, verify_agent_token

_AGENT_HEARTBEAT_TIMEOUT_SECONDS = int(os.environ.get("PENTAVAULT_AGENT_HEARTBEAT_TIMEOUT_SECONDS", "30"))


class AgentClaimRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=80)


class AgentProgressRequest(BaseModel):
    stage: str = Field(min_length=1)
    progress: int = Field(ge=0, le=100)
    findings_count: int = Field(default=0, ge=0)
    module_results: dict[str, int] = Field(default_factory=dict)


class AgentResultRequest(BaseModel):
    findings: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    stages: list[dict[str, Any]] = Field(default_factory=list)
    elapsed: float = Field(default=0, ge=0)
    report_path: str | None = None
    runtime_config: dict[str, Any] = Field(default_factory=dict)
    execution_metadata: dict[str, Any] = Field(default_factory=dict)


class AgentFailRequest(BaseModel):
    error: str = Field(min_length=1)


def _require_agent_auth(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"code": "AGENT_AUTH_REQUIRED", "message": "Missing bearer token"})
    token = authorization.split(" ", 1)[1].strip()
    rec = verify_agent_token(DATA_DIR, token)
    if rec is None:
        raise HTTPException(status_code=403, detail={"code": "AGENT_AUTH_INVALID", "message": "Invalid agent token"})
    return rec


def _next_queued_agent_scan() -> dict[str, Any] | None:
    queued = [s for s in scans.values() if s.get("execution_mode") == "agent_queue" and s.get("status") == "queued"]
    queued.sort(key=lambda s: s.get("started_at", ""))
    return queued[0] if queued else None


@app.post("/api/scans/jobs", response_model=dict)
async def enqueue_scan_job(req: ScanRequest):
    scan_id = str(uuid.uuid4())
    scans[scan_id] = _build_agent_queue_scan(scan_id, req)
    _save_history()
    return {"scan_id": scan_id, "status": "queued", "execution_mode": "agent_queue"}


@app.post("/api/agent/claim")
async def agent_claim(req: AgentClaimRequest, authorization: str | None = Header(default=None)):
    _require_agent_auth(authorization)
    _requeue_stale_agent_jobs(_AGENT_HEARTBEAT_TIMEOUT_SECONDS)
    scan = _next_queued_agent_scan()
    if scan is None:
        return {"job": None}

    scan["status"] = "claimed"
    scan["current_stage"] = "Claimed by agent"
    scan["agent_id"] = req.agent_id
    scan["agent_claimed_at"] = _utc_now_iso()
    scan["agent_heartbeat_at"] = _utc_now_iso()
    _save_history()

    return {
        "job": {
            "job_id": scan["scan_id"],
            "scan_request": {
                "target": scan["target"],
                "mode": scan["mode"],
                "threads": scan["threads"],
                "timeout": scan["timeout"],
                "request_delay": scan.get("request_delay", 0.0),
                "cookie": scan.get("cookie"),
                "use_browser": scan.get("use_browser", False),
                "crawl_mode": scan.get("crawl_mode", "auto"),
            },
        }
    }


@app.post("/api/agent/{job_id}/progress")
async def agent_progress(job_id: str, req: AgentProgressRequest, authorization: str | None = Header(default=None)):
    _require_agent_auth(authorization)
    scan = scans.get(job_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") in _TERMINAL_STATES:
        return {"updated": False, "cancelled": scan.get("status") == "cancelled"}

    scan["status"] = "running"
    scan["current_stage"] = req.stage
    scan["progress"] = req.progress
    scan["findings_count"] = req.findings_count
    scan["module_results"] = req.module_results
    scan["agent_heartbeat_at"] = _utc_now_iso()
    return {"updated": True, "cancelled": False}


@app.post("/api/agent/{job_id}/heartbeat")
async def agent_heartbeat(job_id: str, authorization: str | None = Header(default=None)):
    _require_agent_auth(authorization)
    scan = scans.get(job_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") in _TERMINAL_STATES:
        return {"updated": False}
    scan["agent_heartbeat_at"] = _utc_now_iso()
    return {"updated": True}


@app.post("/api/agent/{job_id}/result")
async def agent_result(job_id: str, req: AgentResultRequest, authorization: str | None = Header(default=None)):
    _require_agent_auth(authorization)
    scan = scans.get(job_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan["findings"] = req.findings
    scan["summary"] = req.summary or _build_summary(req.findings)
    scan["stages"] = req.stages
    scan["elapsed"] = req.elapsed
    scan["report_path"] = req.report_path
    scan["findings_count"] = len(req.findings)
    if req.runtime_config:
        scan["runtime_config"] = req.runtime_config
    if req.execution_metadata:
        scan["execution_metadata"] = req.execution_metadata

    _finalize_scan(scan, "completed", "Complete")
    return {"accepted": True}


@app.post("/api/agent/{job_id}/fail")
async def agent_fail(job_id: str, req: AgentFailRequest, authorization: str | None = Header(default=None)):
    _require_agent_auth(authorization)
    scan = scans.get(job_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    _finalize_scan(scan, "failed", f"Error: {req.error}", error=req.error)
    return {"accepted": True}
```

```python
# replace Vercel branch in start_scan() in scanner/web/app.py
if _IS_VERCEL:
    scan_id = str(uuid.uuid4())
    scans[scan_id] = _build_agent_queue_scan(scan_id, req)
    _save_history()
    return {"scan_id": scan_id, "status": "queued", "execution_mode": "agent_queue"}
```

```python
# extend cancel endpoint in scanner/web/app.py
if scan.get("execution_mode") == "agent_queue" and scan.get("status") in _AGENT_ACTIVE_STATES:
    _finalize_scan(scan, "cancelled", "Cancelled by user")
    return {"cancelled": True}
```

- [ ] **Step 4: Run lifecycle tests**

Run: `python -m unittest scanner.tests.test_agent_queue_api.TestAgentQueueLifecycle -v`  
Expected: PASS (`ok`)

- [ ] **Step 5: Run queue test module to verify all cases**

Run: `python -m unittest scanner.tests.test_agent_queue_api -v`  
Expected: PASS (helper + lifecycle tests)

- [ ] **Step 6: Commit**

```bash
git add scanner/web/app.py scanner/tests/test_agent_queue_api.py
git commit -m "feat(agent-api): add queue claim progress and result endpoints"
```

---

### Task 4: Local `pentavault-agent` worker and CLI entrypoint

**Files:**
- Create: `scanner/agent/worker.py`
- Create: `scanner/agent/__main__.py`
- Create/Test: `scanner/tests/test_agent_worker.py`

- [ ] **Step 1: Write failing worker flow test**

```python
# scanner/tests/test_agent_worker.py
import unittest
from unittest.mock import patch

from scanner.agent.worker import WorkerConfig, run_once


class _FakeSession:
    def __init__(self):
        self.calls = []

    def post(self, url, json=None, headers=None, timeout=10):
        self.calls.append((url, json))
        class Resp:
            def raise_for_status(self):
                return None
            def json(self_inner):
                if url.endswith("/api/agent/claim"):
                    return {
                        "job": {
                            "job_id": "job-1",
                            "scan_request": {
                                "target": "https://example.com",
                                "mode": "quick",
                                "threads": 1,
                                "timeout": 5,
                                "request_delay": 0.0,
                                "cookie": None,
                                "use_browser": False,
                                "crawl_mode": "auto",
                            },
                        }
                    }
                return {"accepted": True, "updated": True, "cancelled": False}
        return Resp()


class TestAgentWorker(unittest.TestCase):
    def test_run_once_claims_and_reports_result(self):
        cfg = WorkerConfig(server_url="https://example.vercel.app", agent_id="agent-1", token="tkn")
        sess = _FakeSession()

        with patch("scanner.agent.worker.execute_claimed_job", return_value=True):
            processed = run_once(cfg, sess)

        self.assertTrue(processed)
        self.assertTrue(any(call[0].endswith("/api/agent/claim") for call in sess.calls))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest scanner.tests.test_agent_worker -v`  
Expected: FAIL with `ModuleNotFoundError` for `scanner.agent.worker`

- [ ] **Step 3: Implement worker transport and execution loop**

```python
# scanner/agent/worker.py
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

import requests

from scanner.web import app as web_app


@dataclass
class WorkerConfig:
    server_url: str
    agent_id: str
    token: str
    poll_interval_seconds: float = 2.0
    heartbeat_interval_seconds: float = 5.0


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def run_once(config: WorkerConfig, session: requests.Session) -> bool:
    claim_resp = session.post(
        f"{config.server_url}/api/agent/claim",
        json={"agent_id": config.agent_id},
        headers=_headers(config.token),
        timeout=20,
    )
    claim_resp.raise_for_status()
    payload = claim_resp.json()
    job = payload.get("job")
    if not job:
        return False

    execute_claimed_job(config, session, job)
    return True


def execute_claimed_job(config: WorkerConfig, session: requests.Session, job: dict[str, Any]) -> bool:
    job_id = job["job_id"]
    req = web_app.ScanRequest(**job["scan_request"])

    web_app.scans[job_id] = web_app._build_agent_queue_scan(job_id, req)
    web_app.scans[job_id]["status"] = "running"

    t = threading.Thread(target=web_app._run_scan, args=(job_id, req), daemon=True)
    t.start()

    last_heartbeat = 0.0
    while t.is_alive():
        scan = web_app.scans[job_id]
        progress_resp = session.post(
            f"{config.server_url}/api/agent/{job_id}/progress",
            json={
                "stage": scan.get("current_stage", "Running"),
                "progress": int(scan.get("progress", 0)),
                "findings_count": int(scan.get("findings_count", 0)),
                "module_results": scan.get("module_results", {}),
            },
            headers=_headers(config.token),
            timeout=20,
        )
        progress_resp.raise_for_status()
        p = progress_resp.json()
        if p.get("cancelled"):
            scan["_cancel"] = True

        now = time.monotonic()
        if now - last_heartbeat >= config.heartbeat_interval_seconds:
            hb = session.post(
                f"{config.server_url}/api/agent/{job_id}/heartbeat",
                headers=_headers(config.token),
                timeout=20,
            )
            hb.raise_for_status()
            last_heartbeat = now

        time.sleep(1.0)

    final_scan = web_app.scans[job_id]
    if final_scan.get("status") == "completed":
        result = session.post(
            f"{config.server_url}/api/agent/{job_id}/result",
            json={
                "findings": final_scan.get("findings", []),
                "summary": final_scan.get("summary", {}),
                "stages": final_scan.get("stages", []),
                "elapsed": final_scan.get("elapsed", 0),
                "report_path": final_scan.get("report_path"),
                "runtime_config": final_scan.get("runtime_config", {}),
                "execution_metadata": final_scan.get("execution_metadata", {}),
            },
            headers=_headers(config.token),
            timeout=60,
        )
        result.raise_for_status()
        return True

    fail = session.post(
        f"{config.server_url}/api/agent/{job_id}/fail",
        json={"error": final_scan.get("error") or "scan execution failed"},
        headers=_headers(config.token),
        timeout=20,
    )
    fail.raise_for_status()
    return False


def run_forever(config: WorkerConfig) -> None:
    session = requests.Session()
    while True:
        try:
            processed = run_once(config, session)
            if not processed:
                time.sleep(config.poll_interval_seconds)
        except Exception:
            time.sleep(config.poll_interval_seconds)
```

```python
# scanner/agent/__main__.py
from __future__ import annotations

import argparse
import os
from pathlib import Path

from scanner.agent.auth import issue_agent_token, revoke_agent_token
from scanner.agent.worker import WorkerConfig, run_forever


def main() -> None:
    parser = argparse.ArgumentParser(description="PentaVault local agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_cmd = sub.add_parser("run")
    run_cmd.add_argument("--server-url", required=True)
    run_cmd.add_argument("--agent-id", required=True)
    run_cmd.add_argument("--token", default=os.environ.get("PENTAVAULT_AGENT_TOKEN"))
    run_cmd.add_argument("--poll-interval", type=float, default=2.0)
    run_cmd.add_argument("--heartbeat-interval", type=float, default=5.0)

    issue_cmd = sub.add_parser("issue-token")
    issue_cmd.add_argument("--label", required=True)
    issue_cmd.add_argument("--data-dir", default=os.environ.get("PENTAVAULT_DATA_DIR", "scanner/data"))

    revoke_cmd = sub.add_parser("revoke-token")
    revoke_cmd.add_argument("--token-id", required=True)
    revoke_cmd.add_argument("--data-dir", default=os.environ.get("PENTAVAULT_DATA_DIR", "scanner/data"))

    args = parser.parse_args()

    if args.cmd == "issue-token":
        token_id, plaintext = issue_agent_token(Path(args.data_dir), args.label)
        print(f"token_id={token_id}")
        print(f"token={plaintext}")
        return

    if args.cmd == "revoke-token":
        ok = revoke_agent_token(Path(args.data_dir), args.token_id)
        print("revoked" if ok else "not-found")
        return

    if not args.token:
        raise SystemExit("--token or PENTAVAULT_AGENT_TOKEN is required")

    cfg = WorkerConfig(
        server_url=args.server_url.rstrip("/"),
        agent_id=args.agent_id,
        token=args.token,
        poll_interval_seconds=args.poll_interval,
        heartbeat_interval_seconds=args.heartbeat_interval,
    )
    run_forever(cfg)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run worker unit tests**

Run: `python -m unittest scanner.tests.test_agent_worker -v`  
Expected: PASS (`ok`)

- [ ] **Step 5: Commit**

```bash
git add scanner/agent/__init__.py scanner/agent/worker.py scanner/agent/__main__.py scanner/tests/test_agent_worker.py
git commit -m "feat(agent-worker): add local polling worker and cli commands"
```

---

### Task 5: React live-scan UX for queued and claimed states

**Files:**
- Modify: `scanner/web/frontend/src/pages/LiveScanPage.jsx`
- Modify (optional helper fields): `scanner/web/frontend/src/api/client.js`
- Test: `scanner/web/frontend/src/pages/LiveScanPage.test.jsx`

- [ ] **Step 1: Write failing React test for queued state behavior**

```jsx
// scanner/web/frontend/src/pages/LiveScanPage.test.jsx
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import LiveScanPage from './LiveScanPage';

vi.mock('../api/client', () => ({
  getScan: vi.fn()
}));

import { getScan } from '../api/client';

describe('LiveScanPage queued status', () => {
  it('shows waiting message and does not render completion banner for queued job', async () => {
    getScan.mockResolvedValue({
      scan_id: 'job-1',
      target: 'https://example.com',
      status: 'queued',
      progress: 0,
      current_stage: 'Queued for local agent',
      findings_count: 0,
      findings: [],
      stages: [],
      module_results: {},
      mode: 'quick',
    });

    render(
      <MemoryRouter initialEntries={["/scan/job-1/live"]}>
        <Routes>
          <Route path="/scan/:id/live" element={<LiveScanPage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/Queued for local agent/i)).toBeInTheDocument();
    });

    expect(screen.getByText(/Waiting for local agent/i)).toBeInTheDocument();
    expect(screen.queryByText(/Mission Complete/i)).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm --prefix scanner/web/frontend run test -- src/pages/LiveScanPage.test.jsx`  
Expected: FAIL because waiting banner/terminal handling does not yet support queued state

- [ ] **Step 3: Implement queued/claimed status UX in `LiveScanPage.jsx`**

```jsx
// key additions in LiveScanPage.jsx
const ACTIVE_STATUSES = new Set(['queued', 'claimed', 'running']);
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled']);

// replace existing isDone and status handling
const status = scan?.status || 'queued';
const isDone = TERMINAL_STATUSES.has(status);

// keep polling stop condition strictly terminal
if (TERMINAL_STATUSES.has(data.status)) {
  clearInterval(pollRef.current);
  clearInterval(timerRef.current);
  if (data.status === 'completed') {
    setTimeout(() => navigate(`/scan/${id}/results`, { replace: true }), 1500);
  }
}

// add queue banner in render (above stage pipeline)
{(status === 'queued' || status === 'claimed') && (
  <div className="glass-card" role="status" aria-live="polite">
    <strong>{status === 'queued' ? 'Waiting for local agent' : 'Agent claimed job'}</strong>
    <p className="text-fog text-sm">
      {status === 'queued'
        ? 'Your scan request is queued and will start when a local pentavault-agent is online.'
        : 'A local pentavault-agent has claimed this job and is preparing execution.'}
    </p>
  </div>
)}
```

- [ ] **Step 4: Re-run frontend test**

Run: `npm --prefix scanner/web/frontend run test -- src/pages/LiveScanPage.test.jsx`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/web/frontend/src/pages/LiveScanPage.jsx scanner/web/frontend/src/pages/LiveScanPage.test.jsx scanner/web/frontend/src/api/client.js
git commit -m "feat(frontend): support queued and claimed agent scan states"
```

---

### Task 6: Documentation, env contract, and context updates

**Files:**
- Create: `.env.example`
- Modify: `README.md`
- Modify: `context.md`

- [ ] **Step 1: Create `.env.example` with new agent configuration variables**

```env
# scanner/web runtime
PENTAVAULT_FRONTEND_MODE=react
PENTAVAULT_HOST=127.0.0.1
PENTAVAULT_PORT=8000

# AI placeholders (do not commit real keys)
PENTAVAULT_GEMINI_API_KEYS=your_key_1,your_key_2
PENTAVAULT_GEMINI_MODELS=gemini-2.0-flash,gemini-2.0-flash-lite

# agent queue auth and liveness
PENTAVAULT_AGENT_HEARTBEAT_TIMEOUT_SECONDS=30

# local worker runtime
PENTAVAULT_AGENT_TOKEN=replace_with_issued_token
```

- [ ] **Step 2: Add README section with exact local agent commands**

```markdown
## Live scanning on Vercel (Local Agent Mode)

When running on Vercel, scan requests are queued and executed by a trusted local worker.

1. Issue an agent token on the API host:
   ```bash
   python -m scanner.agent issue-token --label dev-laptop
   ```
2. Start the local agent:
   ```bash
   python -m scanner.agent run \
     --server-url https://pentavault.vercel.app \
     --agent-id dev-laptop \
     --token <PASTE_ISSUED_TOKEN>
   ```
3. Launch a scan from the web UI. Status transitions: `queued -> claimed -> running -> completed`.
```

- [ ] **Step 3: Update `context.md` architecture and API endpoint sections**

```markdown
### Additions to Architecture Overview
- Vercel deployment now uses a queue/control-plane model for active scans.
- Local `pentavault-agent` workers execute scan jobs and push progress/results over authenticated agent APIs.

### Additions to REST API Endpoint Reference
- `POST /api/scans/jobs`
- `POST /api/agent/claim`
- `POST /api/agent/{job_id}/progress`
- `POST /api/agent/{job_id}/heartbeat`
- `POST /api/agent/{job_id}/result`
- `POST /api/agent/{job_id}/fail`
```

- [ ] **Step 4: Run focused regression tests after doc/env contract updates**

Run: `python -m unittest scanner.tests.test_scan_runtime_metadata scanner.tests.test_agent_queue_api -v`  
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add .env.example README.md context.md
git commit -m "docs(agent-queue): document local worker flow and env contract"
```

---

### Task 7: Full verification, security checks, and release handoff

**Files:**
- Modify if needed: `tasks/todo.md` (record verification commands/results)

- [ ] **Step 1: Run full backend test suite**

Run: `python -m unittest discover -s scanner/tests -p "test_*.py"`  
Expected: PASS (all tests green)

- [ ] **Step 2: Run full frontend test suite**

Run: `npm --prefix scanner/web/frontend run test`  
Expected: PASS

- [ ] **Step 3: Run dependency audits required by project rules**

Run:
```bash
python -m pip install pip-audit
python -m pip_audit -r scanner/requirements.txt
npm --prefix scanner/web/frontend audit --json
```
Expected:
- `pip_audit`: no critical unresolved vulnerabilities (or documented exceptions)
- `npm audit`: output captured; any high/critical must be addressed or explicitly documented

- [ ] **Step 4: Perform queue-mode smoke test (manual)**

Run in two shells:
```bash
# Shell A (API)
python -m scanner.web.app

# Shell B (worker)
python -m scanner.agent issue-token --label smoke-test
python -m scanner.agent run --server-url http://127.0.0.1:8000 --agent-id smoke-test --token <issued_token>
```
Then launch a scan via UI and confirm status path: `queued -> claimed -> running -> completed`.

Expected: Live progress updates appear in `/scan/:id/live`, and final report endpoints remain downloadable.

- [ ] **Step 5: Final commit for verification notes**

```bash
git add tasks/todo.md
git commit -m "chore(verification): record full test audit and smoke results"
```

---

## Spec Coverage Check (self-review)

- **Architecture split (control plane vs local execution):** Covered by Tasks 2–4.
- **Job states and queue lifecycle:** Covered by Tasks 2–3 tests and endpoint implementation.
- **Security model (revocable token auth):** Covered by Task 1 auth primitives and Task 3 endpoint enforcement.
- **Failure/requeue handling:** Covered by stale heartbeat requeue helper in Task 2 and fail endpoint in Task 3.
- **Testing requirements (unit/integration/regression/E2E):** Covered by Tasks 1–7.
- **Rollout + docs + env updates:** Covered by Task 6.

No unresolved placeholders remain in this plan.
