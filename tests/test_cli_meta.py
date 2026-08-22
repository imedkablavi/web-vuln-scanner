from __future__ import annotations

import pytest

from core import cli


def test_checks_command_lists_new_checks(capsys):
    assert cli._handle_meta_command(["web-vuln-scanner", "checks"]) is True
    output = capsys.readouterr().out
    assert "ssti" in output
    assert "crlf" in output
    assert "trace" in output
    assert "open_redirect" in output
    assert "xss_reflected" in output
    assert "WSTG-INPV-18" in output


def test_profiles_command_explains_safety_modes(capsys):
    assert cli._handle_meta_command(["web-vuln-scanner", "profiles"]) is True
    output = capsys.readouterr().out
    assert "passive" in output
    assert "safe-active" in output
    assert "full-authorized" in output
    assert "no payload injection" in output.lower()


def test_version_command_is_available(capsys):
    assert cli._handle_meta_command(["web-vuln-scanner", "version"]) is True
    assert capsys.readouterr().out.strip()


def test_doctor_returns_success_for_core_runtime(capsys):
    with pytest.raises(SystemExit) as exc:
        cli._handle_meta_command(["web-vuln-scanner", "doctor"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "Core runtime looks ready" in output
