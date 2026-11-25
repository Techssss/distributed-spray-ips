import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock

from replay import ACCOUNTS, PROBE_IP, SOURCES, TRACES, run_replay
from server import TARGET


UI = Path(__file__).resolve().parent / 'ui'
ASSETS = {
    '/': ('index.html', 'text/html; charset=utf-8'),
    '/dashboard.css': ('dashboard.css', 'text/css; charset=utf-8'),
    '/dashboard.js': ('dashboard.js', 'text/javascript; charset=utf-8'),
}


class DashboardHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def respond(self, status, content_type, body):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def json_response(self, status, data):
        self.respond(status, 'application/json', json.dumps(data).encode('utf-8'))

    def do_GET(self):
        if self.path == '/api/config':
            return self.json_response(200, {
                'sources': SOURCES, 'accounts': ACCOUNTS, 'probe_ip': PROBE_IP, 'probe_account': TARGET,
                'attempts': {name: len(attempts) for name, attempts in TRACES.items()},
            })
        if self.path not in ASSETS:
            return self.send_error(404)
        filename, content_type = ASSETS[self.path]
        self.respond(200, content_type, (UI / filename).read_bytes())

    def do_POST(self):
        if self.path != '/api/run':
            return self.send_error(404)
        if self.headers.get_content_type() != 'application/json':
            return self.json_response(415, {'error': 'unsupported_content_type'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 256:
                raise ValueError('Invalid body length')
            options = json.loads(self.rfile.read(size))
            if not isinstance(options, dict):
                raise ValueError('Expected a JSON object')
            scenario = options.get('scenario')
            enforce = options.get('enforce')
            if not isinstance(scenario, str) or scenario not in TRACES or type(enforce) is not bool:
                raise ValueError('Invalid scenario or IPS mode')
        except (ValueError, TimeoutError, RecursionError):
            return self.json_response(400, {'error': 'invalid_request'})

        if not self.server.run_lock.acquire(blocking=False):
            return self.json_response(409, {'error': 'run_in_progress'})
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-ndjson')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            stream = run_replay(scenario, enforce)
            try:
                for event in stream:
                    self.wfile.write(json.dumps(event).encode('utf-8') + b'\n')
                    self.wfile.flush()
            except (ConnectionError, TimeoutError):
                pass
            finally:
                stream.close()
        finally:
            self.server.run_lock.release()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Local IPS lab dashboard')
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    with ThreadingHTTPServer(('127.0.0.1', args.port), DashboardHandler) as server:
        server.run_lock = Lock()
        print(f'IPS Lab: http://127.0.0.1:{server.server_port}', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            sys.exit(0)
