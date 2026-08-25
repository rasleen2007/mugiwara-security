"""Unified entrypoint: starts health server, then runs API or worker based on SERVICE_TYPE."""

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
        self.wfile.write(b'{"status":"ok"}')

    def log_message(self, fmt, *args):
        pass


def _start_health_server() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = http.server.HTTPServer(("0.0.0.0", port), _HealthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"health server on :{port}", flush=True)


def main() -> None:
    _start_health_server()
    service_type = os.environ.get("SERVICE_TYPE", "api")
    print(f"SERVICE_TYPE={service_type}", flush=True)

    try:
        if service_type == "worker":
            print("starting worker loop ...", flush=True)
            from mugiwara.cloud.worker import main as run
        else:
            port = os.environ.get("PORT", "8080")
            print(f"starting uvicorn on :{port} ...", flush=True)
            import uvicorn
            from mugiwara.cloud.api import app
            uvicorn.run(app, host="0.0.0.0", port=int(port))
            return
        run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
