"""The east-west wrapper preserves every non-mTLS SSLContext return path."""

from __future__ import annotations

import importlib.util
import ssl
from pathlib import Path
from unittest.mock import Mock, patch



module_path = Path(__file__).resolve().parents[4] / "tools/kubetee-litellm-overlay/sitecustomize.py"


def load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_public_ca_and_http_context_preserve_return_value():
    import certifi

    context = Mock(name="public-context")
    module = load_module("kubetee_sitecustomize_public")
    with patch.object(module, "_orig", return_value=context):
        for _ in range(3):
            assert module._create_default_context(cafile=certifi.where()) is context
            context.load_cert_chain.assert_not_called()


def test_missing_eastwest_files_leave_context_unchanged(tmp_path):
    module = load_module("kubetee_sitecustomize_missing")
    module._EW_DIR = str(tmp_path)
    module._CA = str(tmp_path / "ca.pem")
    module._CRT = str(tmp_path / "tls.crt")
    module._KEY = str(tmp_path / "tls.key")
    context = ssl.create_default_context()
    with patch.object(module, "_orig", return_value=context):
        assert module._create_default_context(capath=str(tmp_path)) is context


def test_missing_tls_files_cannot_create_partial_credentials(tmp_path):
    module = load_module("kubetee_sitecustomize_missing_crt")
    module._CA = str(tmp_path / "ca.pem")
    module._CRT = str(tmp_path / "tls.crt")
    module._KEY = str(tmp_path / "tls.key")
    (tmp_path / "ca.pem").write_bytes(b"")
    (tmp_path / "tls.crt").write_bytes(b"")
    context = Mock(name="public-context")
    with patch.object(module, "_orig", return_value=context):
        assert module._create_default_context(cafile=module._CA) is context
        context.load_cert_chain.assert_not_called()
