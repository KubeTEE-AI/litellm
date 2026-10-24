import os
import ssl

# East-west client-cert chain for httpx 0.28 (ssl_verify CA path +
# load_cert_chain into the shared SSLContext). Paths are env-driven since the
# strict-custody roll (2026-10-24): the material is fetched into the
# container's own scratch by kubetee_eastwest.py, not the host-shared /certs
# emptyDir (which the same roll retires).
_orig = ssl.create_default_context
_EW_DIR = os.environ.get("KUBETEE_EASTWEST_DIR", "/run/kubetee-eastwest")
_CA = os.path.join(_EW_DIR, "ca.pem")
_CRT = os.path.join(_EW_DIR, "tls.crt")
_KEY = os.path.join(_EW_DIR, "tls.key")


def _create_default_context(*args, **kwargs):
    ctx = _orig(*args, **kwargs)
    cafile = kwargs.get("cafile")
    if cafile == _CA and os.path.isfile(_CRT) and os.path.isfile(_KEY):
        ctx.load_cert_chain(_CRT, _KEY)
    return ctx


ssl.create_default_context = _create_default_context
