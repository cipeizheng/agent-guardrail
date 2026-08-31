"""MCP 2026-07-28 request-scoped Tool enforcement."""

from __future__ import annotations

from typing import cast

from fastapi.responses import JSONResponse, Response
from pydantic import JsonValue
from starlette.requests import Request

from agent_guardrail.adapters.mcp import MCPAdapter, MCPAdapterError, ParsedMCPRequest
from agent_guardrail.adapters.mcp.adapter import (
    GUARDRAIL_BLOCKED,
    GUARDRAIL_UNAVAILABLE,
    INTERNAL_ERROR,
    INVALID_REQUEST,
    PARSE_ERROR,
)
from agent_guardrail.enforcement import (
    AuditSink,
    EnforcementCheckpoint,
    EnforcementSession,
    GuardrailUnavailable,
)
from agent_guardrail.gateway.auth import GatewayAuthenticationError, GatewayAuthenticator
from agent_guardrail.gateway.config import GatewaySettings
from agent_guardrail.gateway.http import RequestReadError, read_json_body
from agent_guardrail.gateway.mcp_upstream import (
    MCPUpstream,
    MCPUpstreamError,
    MCPUpstreamResponse,
)
from agent_guardrail.gateway.task_sessions import (
    TASK_SESSION_HEADER,
    TOOL_PROPOSAL_HEADER,
    TaskSession,
    TaskSessionError,
    TaskSessionStore,
)
from agent_guardrail.models import (
    CandidateEvent,
    CandidateRelation,
    Decision,
    EventKind,
    EventOrigin,
    RelationKind,
    SecurityDestination,
    ToolCall,
)
from agent_guardrail.runtime import PolicyAnalyzer


class MCPGateway:
    """Proxy a safe modern MCP subset and enforce actual tools/call side effects."""

    def __init__(
        self,
        *,
        settings: GatewaySettings,
        runtime: PolicyAnalyzer,
        upstream: MCPUpstream | None,
        audit: AuditSink,
        authenticator: GatewayAuthenticator,
        task_sessions: TaskSessionStore,
    ) -> None:
        self.settings = settings
        self.runtime = runtime
        self.upstream = upstream
        self.audit = audit
        self.authenticator = authenticator
        self.task_sessions = task_sessions
        self.adapter = MCPAdapter()

    async def handle(self, http_request: Request) -> Response:
        try:
            client_authorization = self.authenticator.authenticate(http_request)
        except GatewayAuthenticationError:
            return self._rpc_error(
                MCPAdapterError(
                    code="invalid_api_key",
                    message="A valid Gateway API key is required.",
                    rpc_code=INVALID_REQUEST,
                    status_code=401,
                )
            )

        origin = http_request.headers.get("origin")
        if origin is not None and origin.rstrip("/") not in self.settings.mcp_allowed_origins:
            return self._rpc_error(
                MCPAdapterError(
                    code="origin_not_allowed",
                    message="The request Origin is not allowed.",
                    rpc_code=INVALID_REQUEST,
                    status_code=403,
                )
            )
        if self.upstream is None:
            return self._rpc_error(
                MCPAdapterError(
                    code="mcp_not_configured",
                    message="The MCP Gateway is not configured.",
                    rpc_code=INTERNAL_ERROR,
                    status_code=503,
                )
            )

        try:
            payload = await read_json_body(http_request, self.settings.max_request_bytes)
            request = self.adapter.parse_request(payload)
            self.adapter.validate_headers(request, list(http_request.headers.raw))
        except RequestReadError as exc:
            rpc_code = PARSE_ERROR if exc.code == "invalid_json" else INVALID_REQUEST
            return self._rpc_error(
                MCPAdapterError(
                    code=exc.code,
                    message=str(exc),
                    rpc_code=rpc_code,
                    status_code=exc.status_code,
                )
            )
        except MCPAdapterError as exc:
            return self._rpc_error(exc)

        if request.envelope.method != "tools/call":
            return await self._forward_non_tool(
                request,
                http_request=http_request,
                client_authorization=client_authorization,
            )
        return await self._guard_tool_call(
            request,
            http_request=http_request,
            client_authorization=client_authorization,
        )

    async def _forward_non_tool(
        self,
        request: ParsedMCPRequest,
        *,
        http_request: Request,
        client_authorization: str | None,
    ) -> Response:
        try:
            upstream = await self._forward(request, http_request, client_authorization)
            parsed = self.adapter.parse_response(
                upstream.body,
                media_type=upstream.media_type,
                request_id=request.envelope.id,
            )
        except MCPUpstreamError as exc:
            return self._upstream_error(request, exc)
        except MCPAdapterError as exc:
            return self._rpc_error(exc)

        if request.envelope.method == "server/discover" and upstream.status_code == 200:
            return Response(
                content=self.adapter.rewrite_discover_response(parsed),
                status_code=200,
                media_type="application/json",
            )
        return Response(
            content=upstream.body,
            status_code=upstream.status_code,
            media_type=upstream.media_type,
        )

    async def _guard_tool_call(
        self,
        request: ParsedMCPRequest,
        *,
        http_request: Request,
        client_authorization: str | None,
    ) -> Response:
        try:
            task, persistent = await self._resolve_session(http_request)
        except TaskSessionError as exc:
            return self._rpc_error(
                MCPAdapterError(
                    code=exc.code,
                    message=str(exc),
                    rpc_code=INVALID_REQUEST,
                    status_code=400,
                    request_id=request.envelope.id,
                )
            )
        session = task.enforcement
        trace_id = session.trace.id
        async with task.operation_lock:
            try:
                proposal_id = self._proposal_id(http_request, persistent=persistent)
                tool_call = self.adapter.request_to_tool_call(request)
                proposal_event_id: str | None = None
                if proposal_id is not None:
                    proposal_event_id = self._validated_proposal_event_id(
                        session,
                        proposal_id=proposal_id,
                        tool_call=tool_call,
                    )
                    tool_call = tool_call.model_copy(update={"call_id": proposal_id})
            except TaskSessionError as exc:
                return self._rpc_error(
                    MCPAdapterError(
                        code=exc.code,
                        message=str(exc),
                        rpc_code=INVALID_REQUEST,
                        status_code=400,
                        request_id=request.envelope.id,
                    )
                )
            pre_candidate = CandidateEvent(
                key="mcp-tool-call",
                kind=EventKind.TOOL_CALL,
                payload=cast(dict[str, JsonValue], tool_call.model_dump(mode="json")),
                metadata={
                    "adapter": "mcp_gateway",
                    "protocol_version": request.protocol_version,
                },
                origin=EventOrigin.CLIENT_ASSERTED,
                relations=(
                    (
                        CandidateRelation(
                            source_event_id=proposal_event_id,
                            kind=RelationKind.INFLUENCED_BY,
                        ),
                    )
                    if proposal_event_id is not None
                    else ()
                ),
            )
            try:
                pre_decision = await session.submit_candidates(
                    (pre_candidate,),
                    primary_key=pre_candidate.key,
                    security_context=session.security_context.with_enforcement_destination(
                        SecurityDestination.EXTERNAL_TOOL
                    ),
                )
            except GuardrailUnavailable:
                return self._guardrail_unavailable(
                    request,
                    trace_id,
                    EnforcementCheckpoint.BEFORE_TOOL_CALL,
                )
            if pre_decision.blocked:
                return self._guardrail_blocked(
                    request,
                    pre_decision,
                    EnforcementCheckpoint.BEFORE_TOOL_CALL,
                )

        try:
            upstream = await self._forward(request, http_request, client_authorization)
            parsed = self.adapter.parse_response(
                upstream.body,
                media_type=upstream.media_type,
                request_id=request.envelope.id,
            )
            result = self.adapter.response_to_tool_result(parsed, request=request)
            if proposal_id is not None:
                result = result.model_copy(update={"call_id": proposal_id})
        except MCPUpstreamError as exc:
            return self._upstream_error(request, exc, trace_id=trace_id)
        except MCPAdapterError as exc:
            return self._rpc_error(exc, trace_id=trace_id)

        try:
            post_decision = await session.submit(
                kind=EventKind.TOOL_RESULT,
                payload=cast(dict[str, JsonValue], result.model_dump(mode="json")),
                metadata={"adapter": "mcp_gateway", "protocol_version": request.protocol_version},
                source_event_ids=(pre_decision.event_id,),
                origin=EventOrigin.OBSERVED,
                security_context=session.security_context.with_enforcement_destination(
                    SecurityDestination.CLIENT
                ),
            )
        except GuardrailUnavailable:
            return self._guardrail_unavailable(
                request,
                trace_id,
                EnforcementCheckpoint.BEFORE_TOOL_OUTPUT_RELEASE,
            )
        if post_decision.blocked:
            return self._guardrail_blocked(
                request,
                post_decision,
                EnforcementCheckpoint.BEFORE_TOOL_OUTPUT_RELEASE,
            )

        return Response(
            content=upstream.body,
            status_code=upstream.status_code,
            media_type=upstream.media_type,
            headers={"x-guardrail-trace-id": trace_id},
        )

    async def _resolve_session(
        self,
        request: Request,
    ) -> tuple[TaskSession, bool]:
        values = request.headers.getlist(TASK_SESSION_HEADER)
        if len(values) > 1:
            raise TaskSessionError(
                "task_session_invalid",
                "The Gateway task session header must occur at most once.",
            )
        if not values:
            if self.settings.task_sessions_required:
                raise TaskSessionError(
                    "task_session_required",
                    "A Gateway task session is required for this request.",
                )
            return (
                self.task_sessions.ephemeral(
                    max_trace_events=self.settings.max_trace_events,
                ),
                False,
            )
        return await self.task_sessions.get(values[0]), True

    @staticmethod
    def _proposal_id(request: Request, *, persistent: bool) -> str | None:
        values = request.headers.getlist(TOOL_PROPOSAL_HEADER)
        if len(values) > 1:
            raise TaskSessionError(
                "tool_proposal_invalid",
                "The tool proposal header must occur at most once.",
            )
        if not values:
            return None
        proposal_id = values[0]
        if (
            not persistent
            or not proposal_id
            or proposal_id != proposal_id.strip()
            or len(proposal_id) > 256
        ):
            raise TaskSessionError(
                "tool_proposal_invalid",
                "The tool proposal reference is invalid for this task session.",
            )
        return proposal_id

    @staticmethod
    def _validated_proposal_event_id(
        session: EnforcementSession,
        *,
        proposal_id: str,
        tool_call: ToolCall,
    ) -> str:
        matches = []
        for event in session.trace.events:
            if (
                event.kind is not EventKind.TOOL_CALL_PROPOSAL
                or event.origin is not EventOrigin.OBSERVED
            ):
                continue
            proposal = ToolCall.model_validate(event.payload)
            if proposal.call_id == proposal_id:
                matches.append((event, proposal))
        if len(matches) != 1:
            raise TaskSessionError(
                "tool_proposal_invalid",
                "The tool proposal reference is missing, ambiguous, or not committed.",
            )
        event, proposal = matches[0]
        if proposal.name != tool_call.name or proposal.arguments != tool_call.arguments:
            raise TaskSessionError(
                "tool_proposal_mismatch",
                "The MCP tool call does not match its observed model proposal.",
            )
        if any(
            candidate.kind is EventKind.TOOL_CALL
            and ToolCall.model_validate(candidate.payload).call_id == proposal_id
            for candidate in session.trace.events
        ):
            raise TaskSessionError(
                "tool_proposal_replayed",
                "The observed model proposal has already been executed.",
            )
        return event.id

    async def _forward(
        self,
        request: ParsedMCPRequest,
        http_request: Request,
        client_authorization: str | None,
    ) -> MCPUpstreamResponse:
        if self.upstream is None:
            raise MCPUpstreamError("mcp_not_configured")
        return await self.upstream.forward(
            request.envelope.model_dump(mode="json"),
            inbound_headers=http_request.headers,
            client_authorization=client_authorization,
        )

    def _guardrail_blocked(
        self,
        request: ParsedMCPRequest,
        decision: Decision,
        checkpoint: EnforcementCheckpoint,
    ) -> JSONResponse:
        error = MCPAdapterError(
            code="guardrail_blocked",
            message="Tool call blocked by guardrail policy.",
            rpc_code=GUARDRAIL_BLOCKED,
            status_code=200,
            request_id=request.envelope.id,
            data={
                "type": "guardrail_violation",
                "trace_id": decision.trace_id,
                "checkpoint": checkpoint.value,
                "violations": cast(
                    JsonValue,
                    [
                        {"rule_id": violation.rule_id, "code": violation.code}
                        for violation in decision.violations
                    ],
                ),
            },
        )
        return self._rpc_error(error, trace_id=decision.trace_id)

    def _guardrail_unavailable(
        self,
        request: ParsedMCPRequest,
        trace_id: str,
        checkpoint: EnforcementCheckpoint,
    ) -> JSONResponse:
        return self._rpc_error(
            MCPAdapterError(
                code="guardrail_unavailable",
                message="Guardrail evaluation is unavailable.",
                rpc_code=GUARDRAIL_UNAVAILABLE,
                status_code=503,
                request_id=request.envelope.id,
                data={"trace_id": trace_id, "checkpoint": checkpoint.value},
            ),
            trace_id=trace_id,
        )

    def _upstream_error(
        self,
        request: ParsedMCPRequest,
        error: MCPUpstreamError,
        *,
        trace_id: str | None = None,
    ) -> JSONResponse:
        return self._rpc_error(
            MCPAdapterError(
                code=error.code,
                message="The MCP upstream request failed.",
                rpc_code=INTERNAL_ERROR,
                status_code=504 if error.timed_out else 502,
                request_id=request.envelope.id,
            ),
            trace_id=trace_id,
        )

    def _rpc_error(
        self,
        error: MCPAdapterError,
        *,
        trace_id: str | None = None,
    ) -> JSONResponse:
        headers = {"x-guardrail-trace-id": trace_id} if trace_id is not None else None
        return JSONResponse(
            self.adapter.error_payload(error),
            status_code=error.status_code,
            headers=headers,
        )
