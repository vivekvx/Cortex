from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, List, Optional

from cortex_shield.models import (
    DecisionAction,
    PolicyDecision,
    RiskAssessment,
    RiskLevel,
    Run,
    ToolCall,
    TraceEvent,
)


class TraceStore:
    def __init__(self, path: str = "cortex_traces.sqlite3") -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True) if Path(path).parent != Path(".") else None
        self._init_schema()

    def create_run(self, name: str) -> Run:
        run = Run(name=name)
        with self._connect() as db:
            db.execute("insert into runs (id, name) values (?, ?)", (run.id, run.name))
        return self.get_run(run.id) or run

    def list_runs(self) -> List[Run]:
        with self._connect() as db:
            rows = db.execute("select id, name, created_at from runs order by created_at desc").fetchall()
        return [Run(id=row["id"], name=row["name"], created_at=row["created_at"]) for row in rows]

    def get_run(self, run_id: str) -> Optional[Run]:
        with self._connect() as db:
            row = db.execute("select id, name, created_at from runs where id = ?", (run_id,)).fetchone()
        if row is None:
            return None
        return Run(id=row["id"], name=row["name"], created_at=row["created_at"])

    def record_event(
        self,
        run_id: str,
        tool_call: ToolCall,
        assessment: RiskAssessment,
        decision: PolicyDecision,
        output: Optional[Any] = None,
        error: Optional[str] = None,
    ) -> TraceEvent:
        event = TraceEvent(
            run_id=run_id,
            tool_call=tool_call,
            assessment=assessment,
            decision=decision,
            approval_status="pending" if decision.action == DecisionAction.REQUIRE_APPROVAL else None,
            output=output,
            error=error,
        )
        with self._connect() as db:
            db.execute(
                """
                insert into events (
                    id, run_id, tool_call, assessment, decision, approval_status, output, error
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.run_id,
                    json.dumps(self._public_tool_call(tool_call)),
                    json.dumps(assessment.to_dict()),
                    json.dumps(decision.to_dict()),
                    event.approval_status,
                    json.dumps(output),
                    error,
                ),
            )
        return self.get_event(event.id) or event

    def list_events(self, run_id: str) -> List[TraceEvent]:
        with self._connect() as db:
            rows = db.execute(
                "select * from events where run_id = ? order by created_at asc",
                (run_id,),
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def get_event(self, event_id: str) -> Optional[TraceEvent]:
        with self._connect() as db:
            row = db.execute("select * from events where id = ?", (event_id,)).fetchone()
        return self._event_from_row(row) if row else None

    def record_result(
        self,
        event_id: str,
        output: Optional[Any] = None,
        error: Optional[str] = None,
    ) -> Optional[TraceEvent]:
        event = self.get_event(event_id)
        taint = self._taint_for_result(event) if event and error is None else None
        with self._connect() as db:
            db.execute(
                "update events set output = ?, error = ?, taint_kind = ?, taint_source_event_id = ? where id = ?",
                (
                    json.dumps(output),
                    error,
                    taint["kind"] if taint else None,
                    taint["source_event_id"] if taint else None,
                    event_id,
                ),
            )
        return self.get_event(event_id)

    def is_tainted_event(self, event_id: str) -> bool:
        with self._connect() as db:
            row = db.execute(
                "select 1 from events where id = ? and taint_source_event_id is not null",
                (event_id,),
            ).fetchone()
        return row is not None

    def pending_approvals(self) -> List[TraceEvent]:
        with self._connect() as db:
            rows = db.execute(
                """
                select * from events
                where approval_status = 'pending'
                order by created_at asc
                """
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def resolve_approval(self, event_id: str, approved: bool) -> Optional[TraceEvent]:
        status = "approved" if approved else "rejected"
        with self._connect() as db:
            db.execute("update events set approval_status = ? where id = ?", (status, event_id))
        return self.get_event(event_id)

    def _init_schema(self) -> None:
        with self._connect() as db:
            db.execute(
                """
                create table if not exists runs (
                    id text primary key,
                    name text not null,
                    created_at text not null default current_timestamp
                )
                """
            )
            db.execute(
                """
                create table if not exists events (
                    id text primary key,
                    run_id text not null references runs(id),
                    tool_call text not null,
                    assessment text not null,
                    decision text not null,
                    approval_status text,
                    output text,
                    error text,
                    taint_kind text,
                    taint_source_event_id text,
                    created_at text not null default current_timestamp
                )
                """
            )
            self._ensure_column(db, "events", "taint_kind", "text")
            self._ensure_column(db, "events", "taint_source_event_id", "text")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def _event_from_row(self, row: sqlite3.Row) -> TraceEvent:
        tool_call = ToolCall.from_dict(json.loads(row["tool_call"]))
        assessment_raw = json.loads(row["assessment"])
        decision_raw = json.loads(row["decision"])
        return TraceEvent(
            id=row["id"],
            run_id=row["run_id"],
            tool_call=tool_call,
            assessment=RiskAssessment(
                level=RiskLevel(assessment_raw["level"]),
                score=assessment_raw["score"],
                reasons=assessment_raw["reasons"],
            ),
            decision=PolicyDecision(
                action=DecisionAction(decision_raw["action"]),
                reason=decision_raw["reason"],
            ),
            approval_status=row["approval_status"],
            output=json.loads(row["output"]) if row["output"] else None,
            error=row["error"],
            taint=self._taint_from_row(row),
            created_at=row["created_at"],
        )

    def _taint_for_result(self, event: Optional[TraceEvent]) -> Optional[dict[str, str]]:
        if event is None:
            return None
        if event.tool_call.tool.value == "browser":
            return {"kind": "browser_output", "source_event_id": event.id}
        if event.tool_call.tool.value == "filesystem" and event.tool_call.action.lower() == "read":
            return {"kind": "file_read_output", "source_event_id": event.id}
        return None

    def _public_tool_call(self, tool_call: ToolCall) -> dict[str, Any]:
        raw = tool_call.to_dict()
        raw["payload"] = {
            key: value for key, value in raw["payload"].items() if key != "_cortex_tainted_source"
        }
        return raw

    def _taint_from_row(self, row: sqlite3.Row) -> Optional[dict[str, str]]:
        if not row["taint_source_event_id"]:
            return None
        return {
            "kind": row["taint_kind"],
            "source_event_id": row["taint_source_event_id"],
        }

    def _ensure_column(self, db: sqlite3.Connection, table: str, column: str, column_type: str) -> None:
        columns = [row["name"] for row in db.execute(f"pragma table_info({table})").fetchall()]
        if column not in columns:
            db.execute(f"alter table {table} add column {column} {column_type}")
