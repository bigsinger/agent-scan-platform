from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

from ..security import SensitiveDataGuard
from ..store import AssessmentStore, new_id, utc_now
from .scanner import LocalScanEngine, ScanCancelled


TERMINAL_STATES = {"COMPLETED", "PARTIAL_COMPLETED", "FAILED", "CANCELLED"}
RUNNING_STATES = {"QUEUED", "RUNNING_DISCOVERY", "RUNNING_STATIC", "RUNNING_REPORT"}
_MAX_WORKERS = max(1, min(int(os.environ.get("ASSESSMENT_SCAN_WORKERS", "2")), 4))
_executor = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="assessment-scan")
_lock = threading.RLock()
_futures: dict[str, Future[Any]] = {}
_cancel_flags: dict[str, threading.Event] = {}


def background_jobs_enabled() -> bool:
    return os.environ.get("ASSESSMENT_DISABLE_BACKGROUND_JOBS", "").strip().lower() not in {"1", "true", "yes", "on"}


def _request_fingerprint(payload: dict[str, Any]) -> str:
    selected = {
        key: payload.get(key)
        for key in (
            "mode",
            "target_path",
            "path",
            "target",
            "adapter",
            "max_files",
            "max_file_bytes",
            "max_depth",
            "include_skills",
            "include_mcp",
            "run_local_analyzers",
            "execution_mode",
        )
    }
    raw = json.dumps(selected, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _display_status(state_code: str) -> str:
    return {
        "QUEUED": "排队中",
        "RUNNING_DISCOVERY": "运行中",
        "RUNNING_STATIC": "运行中",
        "RUNNING_REPORT": "运行中",
        "WAITING_CONSENT": "等待审批",
        "COMPLETED": "已完成",
        "PARTIAL_COMPLETED": "部分完成",
        "FAILED": "失败",
        "CANCELLED": "已取消",
    }.get(state_code, state_code)


def _merge_state_task(store: AssessmentStore, task: dict[str, Any]) -> None:
    state = store.get_state()
    rows = [row for row in state.get("tasks", []) if row.get("id") != task.get("id")]
    rows.insert(0, task)
    state["tasks"] = rows[:500]
    state["selectedTask"] = task
    store.save_state(state)


def _record_event(
    store: AssessmentStore,
    task_id: str,
    event_type: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> None:
    payload = SensitiveDataGuard.sanitize_for_persist({"message": message, **(details or {})})
    job_id = f"job_{task_id}"
    store.scan_event(task_id, event_type, payload, job_id=job_id)
    store.upsert_record(
        "task_event",
        {
            "id": new_id("tev"),
            "task_id": task_id,
            "job_id": job_id,
            "type": event_type,
            "message": payload.get("message", ""),
            "details": payload,
            "created_at": utc_now(),
        },
        status="RECORDED",
    )


def _update_runtime(
    store: AssessmentStore,
    task_id: str,
    state_code: str,
    progress: int,
    *,
    details: dict[str, Any] | None = None,
    event_type: str | None = None,
    message: str = "",
) -> dict[str, Any]:
    details = SensitiveDataGuard.sanitize_for_persist(details or {})
    task = store.get_record("task", task_id) or store.get_record("assessment", task_id) or {"id": task_id}
    task.update(details)
    task.update(
        {
            "id": task_id,
            "state_code": state_code,
            "stage": state_code,
            "status": _display_status(state_code),
            "progress": 100 if state_code == "COMPLETED" else max(0, min(int(progress), 99)),
            "updated_at": utc_now(),
            "mutates_installed_agents": False,
            "stdio_mcp_started": False,
            "agent_runtime_started": False,
        }
    )
    if state_code in TERMINAL_STATES:
        task.setdefault("finished_at", utc_now())
    store.upsert_record("task", task, status=state_code)
    store.upsert_record("assessment", task, status=state_code)

    job = store.get_record("scan_job", f"job_{task_id}") or {"id": f"job_{task_id}", "task_id": task_id}
    job.update(
        {
            "status": state_code,
            "state_code": state_code,
            "progress": task["progress"],
            "updated_at": task["updated_at"],
            "result_assessment_id": task_id if state_code in {"COMPLETED", "PARTIAL_COMPLETED"} else None,
        }
    )
    store.upsert_record("scan_job", job, status=state_code)

    execution = store.get_record("process_execution", f"exec_{task_id}") or {
        "id": f"exec_{task_id}",
        "task_id": task_id,
        "job_id": job["id"],
        "executor": "in-process-bounded-worker",
        "created_at": task.get("created_at") or utc_now(),
    }
    execution.update(
        {
            "status": state_code,
            "state_code": state_code,
            "progress": task["progress"],
            "updated_at": task["updated_at"],
            "external_process_started": False,
            "mutates_installed_agents": False,
        }
    )
    store.upsert_record("process_execution", execution, status=state_code)
    _merge_state_task(store, task)
    if event_type:
        _record_event(store, task_id, event_type, message or event_type, {"state_code": state_code, "progress": task["progress"], **details})
    return task


def queue_scan(
    store: AssessmentStore,
    payload: dict[str, Any],
    *,
    auto_start: bool | None = None,
    source_task_id: str | None = None,
) -> dict[str, Any]:
    request = SensitiveDataGuard.sanitize_for_persist(dict(payload))
    fingerprint = _request_fingerprint(request)
    for existing in store.list_records("task", limit=5000):
        if existing.get("request_fingerprint") == fingerprint and existing.get("state_code") in RUNNING_STATES:
            return {
                "task": existing,
                "job": store.get_record("scan_job", f"job_{existing['id']}") or {"id": f"job_{existing['id']}", "task_id": existing["id"], "status": existing.get("state_code")},
                "deduplicated": True,
            }

    task_id = new_id("asm")
    now = utc_now()
    task = {
        "id": task_id,
        "name": "异步快速扫描",
        "status": "排队中",
        "stage": "QUEUED",
        "state_code": "QUEUED",
        "progress": 0,
        "scan_request": request,
        "request_fingerprint": fingerprint,
        "source_task_id": source_task_id,
        "safe_mode": "local-readonly",
        "mutates_installed_agents": False,
        "stdio_mcp_started": False,
        "agent_runtime_started": False,
        "created_at": now,
        "updated_at": now,
    }
    store.upsert_record("task", task, status="QUEUED")
    store.upsert_record("assessment", task, status="QUEUED")
    job = {"id": f"job_{task_id}", "task_id": task_id, "status": "QUEUED", "state_code": "QUEUED", "progress": 0, "created_at": now, "updated_at": now}
    store.upsert_record("scan_job", job, status="QUEUED")
    store.upsert_record(
        "process_execution",
        {
            "id": f"exec_{task_id}",
            "task_id": task_id,
            "job_id": job["id"],
            "executor": "in-process-bounded-worker",
            "status": "QUEUED",
            "state_code": "QUEUED",
            "progress": 0,
            "external_process_started": False,
            "created_at": now,
            "updated_at": now,
        },
        status="QUEUED",
    )
    _merge_state_task(store, task)
    _record_event(store, task_id, "task.queued", "异步扫描已进入受控队列", {"state_code": "QUEUED", "request_fingerprint": fingerprint})
    if auto_start if auto_start is not None else background_jobs_enabled():
        submit_scan(store, task_id)
    return {"task": task, "job": job, "deduplicated": False}


def submit_scan(store: AssessmentStore, task_id: str) -> Future[Any]:
    with _lock:
        existing = _futures.get(task_id)
        if existing and not existing.done():
            return existing
        flag = _cancel_flags.setdefault(task_id, threading.Event())
        flag.clear()
        future = _executor.submit(run_scan_task, store, task_id)
        _futures[task_id] = future
        return future


def run_scan_task(store: AssessmentStore, task_id: str) -> dict[str, Any]:
    task = store.get_record("task", task_id) or store.get_record("assessment", task_id)
    if not task:
        raise ValueError("queued scan task not found")
    if task.get("state_code") == "CANCELLED":
        return task
    request = dict(task.get("scan_request") or {})
    request["_assessment_id"] = task_id
    deadline = time.monotonic() + max(5, min(int(request.get("timeout_seconds") or 600), 3600))
    cancel_flag = _cancel_flags.setdefault(task_id, threading.Event())

    def cancelled() -> bool:
        if cancel_flag.is_set():
            return True
        current = store.get_record("task", task_id) or {}
        return current.get("state_code") == "CANCELLED"

    def progress(stage: str, percent: int, details: dict[str, Any]) -> None:
        if time.monotonic() > deadline:
            cancel_flag.set()
            raise ScanCancelled("scan time limit reached")
        _update_runtime(
            store,
            task_id,
            stage,
            percent,
            details={"progress_details": details},
            event_type="task.progress",
            message=f"扫描阶段更新：{stage}",
        )

    try:
        _update_runtime(store, task_id, "RUNNING_DISCOVERY", 2, event_type="task.started", message="受控 worker 已开始执行扫描")
        result = LocalScanEngine(store, progress_callback=progress, cancel_check=cancelled).run_quick_scan(request)
        waiting = bool(result.discovery.consents)
        state_code = "WAITING_CONSENT" if waiting else "COMPLETED"
        final_details = {
            "report_id": result.report.get("id"),
            "finding_count": len(result.findings),
            "evidence_count": len(result.evidence),
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "pending_consents": len(result.discovery.consents),
            "scan_request": task.get("scan_request") or {},
            "request_fingerprint": task.get("request_fingerprint"),
        }
        final = _update_runtime(
            store,
            task_id,
            state_code,
            95 if waiting else 100,
            details=final_details,
            event_type="task.waiting_consent" if waiting else "task.completed",
            message="扫描等待 MCP 审批" if waiting else "扫描、证据和报告已完成",
        )
        return final
    except ScanCancelled:
        return _update_runtime(store, task_id, "CANCELLED", 0, event_type="task.cancelled", message="扫描已在文件读取检查点停止")
    except Exception as exc:
        return _update_runtime(
            store,
            task_id,
            "FAILED",
            0,
            details={"error_code": type(exc).__name__, "retryable": True},
            event_type="task.failed",
            message="扫描执行失败；未修改已安装 Agent",
        )
    finally:
        with _lock:
            _futures.pop(task_id, None)


def cancel_scan(store: AssessmentStore, task_id: str, reason: str = "local-user requested") -> dict[str, Any]:
    task = store.get_record("task", task_id) or store.get_record("assessment", task_id) or {"id": task_id}
    if task.get("state_code") in TERMINAL_STATES:
        return task
    _cancel_flags.setdefault(task_id, threading.Event()).set()
    return _update_runtime(
        store,
        task_id,
        "CANCELLED",
        int(task.get("progress") or 0),
        details={"cancel_reason": SensitiveDataGuard.redact_text(reason)},
        event_type="task.cancel_requested",
        message="已记录取消请求，worker 将在下一个读取检查点停止",
    )


def retry_scan(store: AssessmentStore, task_id: str, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    source = store.get_record("task", task_id) or store.get_record("assessment", task_id)
    if not source:
        raise ValueError("source scan task not found")
    payload = dict(source.get("scan_request") or {})
    payload.update(overrides or {})
    return queue_scan(store, payload, source_task_id=task_id)


def recover_interrupted_scans(store: AssessmentStore) -> int:
    recovered = 0
    for task in store.list_records("task", limit=5000):
        state = str(task.get("state_code") or "")
        if state in {"RUNNING_DISCOVERY", "RUNNING_STATIC", "RUNNING_REPORT"}:
            _update_runtime(
                store,
                str(task["id"]),
                "FAILED",
                int(task.get("progress") or 0),
                details={"error_code": "WORKER_RESTARTED", "retryable": True},
                event_type="task.recovered_after_restart",
                message="服务重启后检测到未完成任务，已标记可重试失败",
            )
            recovered += 1
    return recovered
