#!/usr/bin/env python3
"""
Lightweight Host-side Docker Stats Agent for Multi-Node Evaluation.
Listens on port 9999 and returns JSON-formatted 'docker stats --no-stream'
with low overhead (<20ms local execution) to avoid remote SSH connection latency.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import subprocess
import sys

PORT = 9999

class StatsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/stats":
            try:
                res = subprocess.run(
                    ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.end_headers()
                self.wfile.write(res.stdout.encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}\n')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress noisy HTTP request logging to stdout
        pass

def run():
    server_address = ("0.0.0.0", PORT)
    httpd = HTTPServer(server_address, StatsHandler)
    print(f"[StatsAgent] Listening on 0.0.0.0:{PORT}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

if __name__ == "__main__":
    run()
