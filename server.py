import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import parse_qs

from detector import SprayDetector
from portal import page, UI


TARGET = 'user01'
LOGIN_SURFACES = {'/web/login': 'web', '/api/login': 'api'}


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 200_000)


def totp_code(secret, counter):
    digest = hmac.digest(secret, counter.to_bytes(8, 'big'), 'sha1')
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff
    return f'{number % 1_000_000:06d}'


@dataclass
class Account:
    salt: bytes
    password_digest: bytes
    totp_secret: bytes
    last_used_counter: int = -1

    @classmethod
    def create(cls, password):
        salt = secrets.token_bytes(16)
        return cls(salt, password_hash(password, salt), secrets.token_bytes(20))


@dataclass
class Challenge:
    account: str
    ip: str
    expires_at: float
    remaining_attempts: int = 3


class Lab:
    def __init__(self, *, password, enforce=True, audit=None, target_totp_secret=None):
        self.enforce = enforce
        self.audit = audit or (lambda event: None)
        self.lock = Lock()
        self.detector = SprayDetector()
        self.active_campaigns = set()
        self.users = {f'user{i:02}': Account.create(secrets.token_urlsafe(24)) for i in range(2, 8)}
        self.users[TARGET] = Account.create(password)
        if target_totp_secret is not None:
            self.users[TARGET].totp_secret = target_totp_secret
        self.unknown = Account.create(secrets.token_urlsafe(24))
        self.challenges = {}
        self.sessions = {}
        self.otp_failures = defaultdict(deque)

    def login(self, ip, surface, username, password):
        if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', username):
            return 400, {'status': 'invalid_request'}
        if not isinstance(password, str) or not password or len(password) > 256:
            return 400, {'status': 'invalid_request'}

        account = self.users.get(username, self.unknown)
        valid = hmac.compare_digest(password_hash(password, account.salt), account.password_digest)
        with self.lock:
            if not valid or account is self.unknown:
                self.detector.record_failure(ip, username, surface)
                self._emit('login_failed', ip=ip, account=username, surface=surface)
                if self.enforce:
                    self._check_campaigns()
                return 401, {'status': 'invalid_credentials'}

            now = time.monotonic()
            self._expire_tokens(now)
            campaigns = self._check_campaigns() if self.enforce else []
            for campaign in campaigns:
                if username in campaign.targets:
                    challenge_id = secrets.token_urlsafe(24)
                    self.challenges[challenge_id] = Challenge(username, ip, now + 90)
                    self._emit('mfa_required', ip=ip, account=username, surface=surface,
                               campaign=asdict(campaign))
                    return 202, {'status': 'mfa_required', 'challenge_id': challenge_id}

            return self._new_session(username, now)

    def verify_otp(self, ip, challenge_id, code):
        if not isinstance(challenge_id, str) or not isinstance(code, str) or not re.fullmatch(r'[0-9]{6}', code):
            return 400, {'status': 'invalid_request'}

        with self.lock:
            now = time.monotonic()
            self._expire_tokens(now)
            challenge = self.challenges.get(challenge_id)
            if challenge is None or challenge.ip != ip:
                return 401, {'status': 'invalid_challenge'}

            failures = self.otp_failures[challenge.account]
            while failures and failures[0] <= now - 60:
                failures.popleft()
            if len(failures) >= 5:
                return 429, {'status': 'otp_rate_limited'}

            account = self.users[challenge.account]
            current_counter = int(time.time()) // 30
            # Allow the prior period for a code submitted at the time boundary.
            for counter in (current_counter, current_counter - 1):
                if counter > account.last_used_counter and hmac.compare_digest(code, totp_code(account.totp_secret, counter)):
                    account.last_used_counter = counter
                    del self.challenges[challenge_id]
                    return self._new_session(challenge.account, now)

            failures.append(now)
            challenge.remaining_attempts -= 1
            if challenge.remaining_attempts == 0:
                del self.challenges[challenge_id]
            return 401, {'status': 'invalid_otp'}

    def _new_session(self, username, now):
        token = secrets.token_urlsafe(32)
        self.sessions[token] = (username, now + 300)
        self._emit('session_issued', account=username)
        return 200, {'status': 'authenticated', 'session_token': token}

    def _check_campaigns(self):
        campaigns = self.detector.signals()['campaigns']
        for campaign in campaigns:
            if campaign not in self.active_campaigns:
                self._emit('campaign_detected', **asdict(campaign))
        self.active_campaigns = set(campaigns)
        return campaigns

    def _emit(self, event, **details):
        self.audit({'event': event, 'timestamp': time.time(), **details})

    def _expire_tokens(self, now):
        self.challenges = {key: item for key, item in self.challenges.items() if item.expires_at > now}
        self.sessions = {key: item for key, item in self.sessions.items() if item[1] > now}

    def session_account(self, token):
        with self.lock:
            self._expire_tokens(time.monotonic())
            session = self.sessions.get(token)
            return session[0] if session else None

    def end_session(self, token):
        with self.lock:
            self.sessions.pop(token, None)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Audit events are emitted by Lab without request bodies or tokens.
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def do_GET(self):
        if self.path == '/':
            return self.html(200, 'login')
        if self.path == '/healthz':
            return self.reply(200, {'status': 'ok'})
        if self.path in ('/dashboard.css', '/portal.css'):
            return self.respond(200, (UI / self.path[1:]).read_bytes(), 'text/css; charset=utf-8')
        if self.path in ('/profile', '/api/me'):
            token = self.session_token(allow_cookie=self.path == '/profile')
            account = self.server.lab.session_account(token)
            if self.path == '/profile':
                return self.html(200, 'profile', account=account) if account else self.html(401, 'denied')
            if account is None:
                return self.reply(401, {'status': 'unauthenticated'})
            return self.reply(200, {'status': 'authenticated', 'account': account})
        self.reply(404, {'status': 'not_found'})

    def do_POST(self):
        if self.path == '/web/logout':
            self.server.lab.end_session(self.session_token(allow_cookie=True))
            return self.redirect('/', self.session_cookie('', max_age=0))
        surface = LOGIN_SURFACES.get(self.path)
        if surface is None and self.path not in ('/auth/otp', '/web/otp'):
            return self.reply(404, {'status': 'not_found'})

        web_form = self.path in ('/web/login', '/web/otp')
        browser = web_form and 'text/html' in self.headers.get('Accept', '')

        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096:
                raise ValueError('invalid body length')
            body = self.rfile.read(length).decode('utf-8')
            content_type = self.headers.get_content_type()
            if web_form and content_type == 'application/x-www-form-urlencoded':
                fields = {key: values[0] for key, values in parse_qs(body, max_num_fields=8).items()}
            elif not web_form and content_type == 'application/json':
                fields = json.loads(body)
            else:
                return self.reply(415, {'status': 'unsupported_content_type'})
            if not isinstance(fields, dict):
                raise ValueError('expected an object')
        except (ValueError, TimeoutError, RecursionError):
            return self.reply(400, {'status': 'invalid_request'})

        # Use the real peer address. Forwarding headers have no effect in this lab.
        ip = self.client_address[0]
        if surface is not None:
            result = self.server.lab.login(ip, surface, fields.get('username'), fields.get('password'))
        else:
            result = self.server.lab.verify_otp(ip, fields.get('challenge_id'), fields.get('code'))
        if browser:
            status, data = result
            if status == 200:
                return self.redirect('/profile', self.session_cookie(data['session_token']))
            if status == 202:
                return self.html(202, 'otp', challenge_id=data['challenge_id'])
            if data['status'] == 'invalid_otp':
                return self.html(status, 'otp', challenge_id=fields.get('challenge_id', ''),
                                 error='Mã chưa đúng. Thử mã hiện tại trong ứng dụng Authenticator.')
            errors = {
                'invalid_credentials': 'Tên tài khoản hoặc mật khẩu chưa đúng.',
                'invalid_challenge': 'Phiên xác thực đã hết hạn. Hãy đăng nhập lại.',
                'otp_rate_limited': 'Quá nhiều lần nhập mã. Hãy chờ một phút rồi thử lại.',
            }
            return self.html(status, 'login', error=errors.get(data['status'], 'Kiểm tra thông tin rồi thử lại.'))
        self.reply(*result)

    def session_token(self, allow_cookie=False):
        scheme, _, token = self.headers.get('Authorization', '').partition(' ')
        if scheme.lower() == 'bearer':
            return token
        if allow_cookie:
            try:
                cookie = SimpleCookie(self.headers.get('Cookie', '')).get('lab_session')
                return cookie.value if cookie else None
            except CookieError:
                return None
        return None

    def session_cookie(self, token, max_age=300):
        return f'lab_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}'

    def redirect(self, location, cookie):
        self.respond(303, b'', 'text/plain; charset=utf-8', {'Location': location, 'Set-Cookie': cookie})

    def html(self, status, name, **values):
        self.respond(status, page(name, **values), 'text/html; charset=utf-8', {
            'Content-Security-Policy': "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        })

    def reply(self, code, data):
        self.respond(code, json.dumps(data).encode('utf-8'), 'application/json')

    def respond(self, code, body, content_type, headers=None):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


def make_server(lab, port=0, host='127.0.0.1'):
    server = ThreadingHTTPServer((host, port), Handler)
    server.lab = lab
    return server


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Local authentication lab')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--ips', choices=('on', 'off'), default=os.getenv('IPS_LAB_MODE', 'on'))
    args = parser.parse_args()
    if args.ips not in ('on', 'off'):
        parser.error('IPS_LAB_MODE must be on or off')
    password = os.getenv('IPS_LAB_PASSWORD', '')
    if not 12 <= len(password) <= 256:
        parser.error('Set IPS_LAB_PASSWORD to a lab password of 12–256 characters')
    secret = os.getenv('IPS_LAB_TOTP_SECRET', '').strip()
    try:
        target_secret = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8)) if secret else None
    except (ValueError, binascii.Error):
        parser.error('IPS_LAB_TOTP_SECRET must be a Base32 key')
    if target_secret is not None and len(target_secret) < 16:
        parser.error('IPS_LAB_TOTP_SECRET must encode at least 16 bytes')
    lab = Lab(password=password, enforce=args.ips == 'on', target_totp_secret=target_secret,
              audit=lambda event: print(json.dumps(event), flush=True))
    with make_server(lab, args.port, args.host) as server:
        print(f'Listening on http://{args.host}:{server.server_port} (IPS {args.ips})', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
