"""Worker entrypoint: health server + scan worker loop."""

import http.server
import os
import threading


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok","service":"mugiwara-cloud-worker"}')

    def log_message(self, fmt, *args):
        pass


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))

    server = http.server.HTTPServer(("0.0.0.0", port), HealthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"health server listening on :{port}")

    from mugiwara.cloud.worker import main as run_worker

    run_worker()


if __name__ == "__main__":
    main()
