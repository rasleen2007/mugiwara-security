#!/bin/sh
# Starts a tiny health server on $PORT and the scan worker in the foreground.
# Railway healthcheck hits /health on $PORT; the worker polls the DB for jobs.

PORT=${PORT:-8080}

# Tiny HTTP health server in the background
python -c "
import http.server, os, threading

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{\"status\":\"ok\",\"service\":\"mugiwara-cloud-worker\"}')
    def log_message(self, fmt, *args):
        pass

server = http.server.HTTPServer(('0.0.0.0', int(os.environ.get('PORT', '8080'))), H)
threading.Thread(target=server.serve_forever, daemon=True).start()
print(f'health server listening on :{os.environ.get(\"PORT\", \"8080\")}')
" &

# Run the worker in the foreground
exec python -m mugiwara.cloud.worker
