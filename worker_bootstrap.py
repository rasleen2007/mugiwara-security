"""Worker entrypoint: health server + scan worker loop.

Starts a tiny HTTP health server on $PORT in a background thread, then runs
the blocking scan-worker polling loop.  If the worker module cannot be imported
or crashes on startup, the error is printed to stderr and the process exits
with code 1 so Railway surfaces the logs.
"""

import http.server
import os
import sys
import threading
import traceback


class _HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok","service":"mugiwara-cloud-worker"}')

    def log_message(self, fmt, *args):
        pass


def _start_health_server() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = http.server.HTTPServer(("0.0.0.0", port), _HealthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"health server listening on :{port}", flush=True)


def main() -> None:
    _start_health_server()
    print("starting mugiwara cloud worker ...", flush=True)
    try:
        from mugiwara.cloud.worker import main as run_worker
    except Exception:
        traceback.print_exc()
        sys.exit(1)
    run_worker()


if __name__ == "__main__":
    main()
