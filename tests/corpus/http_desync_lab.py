from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class ParserBoundaryResult:
    content_length_boundary: int
    chunked_boundary: int
    disagreement: bool


def _split_headers(raw: bytes):
    marker = b"\r\n\r\n"
    index = raw.find(marker)
    if index < 0:
        raise ValueError("header terminator missing")
    header_end = index + len(marker)
    lines = raw[:index].decode("ascii", errors="strict").split("\r\n")
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return header_end, headers


def _content_length_boundary(raw: bytes) -> int:
    header_end, headers = _split_headers(raw)
    length = int(headers.get("content-length", "0"))
    return header_end + length


def _chunked_boundary(raw: bytes) -> int:
    header_end, headers = _split_headers(raw)
    if headers.get("transfer-encoding", "").lower() != "chunked":
        return header_end
    cursor = header_end
    while True:
        line_end = raw.find(b"\r\n", cursor)
        if line_end < 0:
            raise ValueError("chunk size terminator missing")
        size = int(raw[cursor:line_end].decode("ascii"), 16)
        cursor = line_end + 2
        if size == 0:
            if raw[cursor:cursor + 2] != b"\r\n":
                raise ValueError("final chunk terminator missing")
            return cursor + 2
        cursor += size
        if raw[cursor:cursor + 2] != b"\r\n":
            raise ValueError("chunk data terminator missing")
        cursor += 2


def evaluate_parser_boundary(raw: bytes) -> ParserBoundaryResult:
    """Compare two toy HTTP/1 framing policies on local synthetic bytes only."""
    cl = _content_length_boundary(raw)
    te = _chunked_boundary(raw)
    return ParserBoundaryResult(
        content_length_boundary=cl,
        chunked_boundary=te,
        disagreement=cl != te,
    )


def synthetic_ambiguous_request() -> bytes:
    """Benign ambiguity: trailing byte is an inert marker, not a second request."""
    return (
        b"POST /lab HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Length: 6\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n\r\nX"
    )


def synthetic_normalized_request() -> bytes:
    return (
        b"POST /lab HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Length: 5\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n\r\n"
    )
