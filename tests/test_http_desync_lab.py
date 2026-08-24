from tests.corpus.http_desync_lab import (
    evaluate_parser_boundary,
    synthetic_ambiguous_request,
    synthetic_normalized_request,
)


def test_local_http_desync_parser_disagreement_positive_and_negative():
    ambiguous = evaluate_parser_boundary(synthetic_ambiguous_request())
    normalized = evaluate_parser_boundary(synthetic_normalized_request())

    assert ambiguous.disagreement is True
    assert abs(ambiguous.content_length_boundary - ambiguous.chunked_boundary) == 1
    assert normalized.disagreement is False


def test_http_desync_lab_contains_no_followup_request_or_external_target():
    raw = synthetic_ambiguous_request()
    assert raw.count(b"HTTP/1.1") == 1
    assert b"Host: 127.0.0.1" in raw
    assert b"http://" not in raw.lower()
    assert b"https://" not in raw.lower()
