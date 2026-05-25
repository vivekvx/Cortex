from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from cortex_shield.guard import CortexGuard
from cortex_shield.models import ToolCall
from cortex_shield.policy import PolicyEngine
from cortex_shield.policy_config import load_policy_config
from cortex_shield.risk import RiskEngine
from cortex_shield.trace_store import TraceStore


class CreateRunRequest(BaseModel):
    name: str


class ToolCallRequest(BaseModel):
    run_id: str
    tool: str
    action: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class ToolResultRequest(BaseModel):
    output: Any = None
    error: Optional[str] = None


class ApprovalRequest(BaseModel):
    approved: bool


def create_app(store: TraceStore | None = None, api_token: Optional[str] = None) -> FastAPI:
    app = FastAPI(title="Cortex Shield Runtime", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    trace_store = store or TraceStore(os.environ.get("CORTEX_TRACE_DB", "cortex_traces.sqlite3"))
    resolved_api_token = api_token if api_token is not None else os.environ.get("CORTEX_API_TOKEN")
    policy_config = load_policy_config(os.environ.get("CORTEX_POLICY_PATH"))
    guard = CortexGuard(
        store=trace_store,
        risk_engine=RiskEngine(),
        policy_engine=PolicyEngine(config=policy_config),
    )

    def require_auth(authorization: Optional[str] = Header(default=None)) -> None:
        if not resolved_api_token:
            return
        expected = f"Bearer {resolved_api_token}"
        if authorization != expected:
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.post("/runs")
    def create_run(request: CreateRunRequest, _auth: None = Depends(require_auth)) -> Dict[str, Any]:
        return trace_store.create_run(request.name).to_dict()

    @app.get("/runs")
    def list_runs(_auth: None = Depends(require_auth)) -> Dict[str, Any]:
        return {"runs": [run.to_dict() for run in trace_store.list_runs()]}

    @app.get("/runs/{run_id}/events")
    def list_events(run_id: str, _auth: None = Depends(require_auth)) -> Dict[str, Any]:
        if trace_store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        return {"events": [event.to_dict() for event in trace_store.list_events(run_id)]}

    @app.post("/guard/execute")
    def guard_execute(request: ToolCallRequest, _auth: None = Depends(require_auth)) -> Dict[str, Any]:
        if trace_store.get_run(request.run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        tool_call = ToolCall.from_dict(request.model_dump(exclude={"run_id"}))
        result = guard.execute(
            run_id=request.run_id,
            tool_call=tool_call,
            executor=lambda call: {"status": "simulated", "tool": call.tool.value, "action": call.action},
        )
        return result.to_dict()

    @app.post("/guard/check")
    def guard_check(request: ToolCallRequest, _auth: None = Depends(require_auth)) -> Dict[str, Any]:
        if trace_store.get_run(request.run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        tool_call = ToolCall.from_dict(request.model_dump(exclude={"run_id"}))
        return guard.check(run_id=request.run_id, tool_call=tool_call).to_dict()

    @app.get("/events/{event_id}")
    def get_event(event_id: str, _auth: None = Depends(require_auth)) -> Dict[str, Any]:
        event = trace_store.get_event(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="event not found")
        return event.to_dict()

    @app.post("/events/{event_id}/result")
    def record_result(
        event_id: str,
        request: ToolResultRequest,
        _auth: None = Depends(require_auth),
    ) -> Dict[str, Any]:
        event = trace_store.record_result(event_id, output=request.output, error=request.error)
        if event is None:
            raise HTTPException(status_code=404, detail="event not found")
        return event.to_dict()

    @app.get("/approvals")
    def pending_approvals(_auth: None = Depends(require_auth)) -> Dict[str, Any]:
        return {"approvals": [event.to_dict() for event in trace_store.pending_approvals()]}

    @app.post("/approvals/{event_id}")
    def resolve_approval(
        event_id: str,
        request: ApprovalRequest,
        _auth: None = Depends(require_auth),
    ) -> Dict[str, Any]:
        event = trace_store.resolve_approval(event_id, request.approved)
        if event is None:
            raise HTTPException(status_code=404, detail="event not found")
        return event.to_dict()

    return app


app = create_app()
