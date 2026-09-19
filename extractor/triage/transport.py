"""Process isolation makes the total deadline enforceable, including retries."""

import base64
import json
from pathlib import Path
import subprocess
import sys
import requests


def bounded_request(
    method, url, headers, params=None, timeout=30, retries=2, max_bytes=20 * 1024 * 1024
):
    if timeout <= 0:
        raise requests.Timeout("Request deadline exhausted")
    request = {
        "method": method,
        "url": url,
        "headers": headers,
        "params": params,
        "timeout": timeout,
        "retries": max(0, min(retries, 5)),
        "max_bytes": max_bytes,
    }
    worker = Path(__file__).with_name("transport_worker.py")
    options = (
        {"creationflags": subprocess.CREATE_NO_WINDOW}
        if sys.platform == "win32"
        else {}
    )
    child = subprocess.Popen(
        [sys.executable, "-I", str(worker)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **options,
    )
    try:
        output, _ = child.communicate(json.dumps(request).encode(), timeout=timeout)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        raise requests.Timeout("Total request deadline exceeded") from None
    except BaseException:
        child.kill()
        child.communicate()
        raise
    data = json.loads(output)
    if child.returncode or "error" in data:
        raise requests.RequestException(
            f"Bounded download failed ({data.get('error', 'worker error')})"
        )
    response = requests.Response()
    response.status_code = data["status"]
    response.headers.update(data["headers"])
    response._content = base64.b64decode(data["body"], validate=True)
    response.url = url
    return response
