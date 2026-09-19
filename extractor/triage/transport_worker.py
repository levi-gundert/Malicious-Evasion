"""Isolated bounded download worker; secrets arrive only through stdin."""

import base64
import json
import sys
import time
import requests


def download(request):
    limit = request["max_bytes"]
    for attempt in range(request["retries"] + 1):
        with requests.Session() as session:
            # A redirect is an error: never forward the API key to another host.
            with session.request(
                request["method"],
                request["url"],
                headers=request["headers"],
                params=request.get("params"),
                stream=True,
                allow_redirects=False,
                timeout=(min(5, request["timeout"]), min(5, request["timeout"])),
            ) as response:
                if (
                    response.status_code in (429, 500, 502, 503, 504)
                    and attempt < request["retries"]
                ):
                    time.sleep(min(2**attempt, 4))
                    continue
                if 300 <= response.status_code < 400:
                    raise ValueError("API redirects are not permitted")
                if int(response.headers.get("Content-Length", 0)) > limit:
                    raise ValueError("Response exceeds configured size limit")
                chunks, size = [], 0
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > limit:
                        raise ValueError("Response exceeds configured size limit")
                    chunks.append(chunk)
                return {
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "body": base64.b64encode(b"".join(chunks)).decode("ascii"),
                }
    raise RuntimeError("Retry budget exhausted")


if __name__ == "__main__":
    try:
        request = json.load(sys.stdin)
        print(json.dumps(download(request)))
    except Exception as exc:
        # Do not echo request headers or exception messages containing request data.
        print(json.dumps({"error": type(exc).__name__}))
        raise SystemExit(1)
