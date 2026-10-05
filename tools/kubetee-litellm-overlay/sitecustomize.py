import os
import ssl

_orig = ssl.create_default_context
_CA = "/certs/ca.pem"
_CRT = "/certs/tls.crt"
_KEY = "/certs/tls.key"


def _create_default_context(*args, **kwargs):
    ctx = _orig(*args, **kwargs)
    cafile = kwargs.get("cafile")
    if cafile == _CA and os.path.isfile(_CRT) and os.path.isfile(_KEY):
        ctx.load_cert_chain(_CRT, _KEY)
    return ctx


ssl.create_default_context = _create_default_context
