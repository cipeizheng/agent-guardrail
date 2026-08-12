"""Bounded JSON request handling for Core protocol routes."""

from __future__ import annotations

import json

from starlette.requests import Request


class CoreRequestReadError(ValueError):
    def __init__(self, code: str, message: str, *, status_code: int = 400) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(message)


async def read_core_json_body(request: Request, max_bytes: int) -> object:
    """Read one application/json body without exceeding the configured limit."""

    content_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if content_type.lower() != "application/json":
        raise CoreRequestReadError(
            "unsupported_content_type",
            "Content-Type must be application/json.",
            status_code=415,
        )
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            parsed_content_length = int(content_length)
        except ValueError as exc:
            raise CoreRequestReadError(
                "invalid_content_length",
                "Content-Length must be an integer.",
            ) from exc
        if parsed_content_length < 0:
            raise CoreRequestReadError(
                "invalid_content_length",
                "Content-Length cannot be negative.",
            )
        if parsed_content_length > max_bytes:
            raise CoreRequestReadError(
                "request_too_large",
                "The request body exceeds the configured limit.",
                status_code=413,
            )

    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            raise CoreRequestReadError(
                "request_too_large",
                "The request body exceeds the configured limit.",
                status_code=413,
            )
        chunks.append(chunk)
    try:
        return json.loads(b"".join(chunks))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CoreRequestReadError(
            "invalid_json",
            "The request body must contain valid JSON.",
        ) from exc
