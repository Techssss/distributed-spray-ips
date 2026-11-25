import secrets
import time
from dataclasses import asdict

from server import Lab, TARGET, totp_code


# RFC 5737 addresses for documentation and synthetic logs.
SOURCES = [f'192.0.2.{index}' for index in range(10, 17)]
ACCOUNTS = [f'user{index:02}' for index in range(1, 8)]
PROBE_IP = '192.0.2.50'
INTERVAL_MS = 250


def make_trace(offsets):
    return [
        (ip, ACCOUNTS[(index + offset) % len(ACCOUNTS)], 'web' if (index + slot) % 2 == 0 else 'api')
        for index, ip in enumerate(SOURCES)
        for slot, offset in enumerate(offsets)
    ]


TRACES = {
    'spray': make_trace((0, 1, 2)),
    'control': make_trace((0, 1, 3)),
    'single': [(SOURCES[0], TARGET, 'api')] * 5,
}


def run_replay(scenario, enforce):
    """Replay authentication records and exercise the local session policy."""
    password = secrets.token_urlsafe(24)
    lab = Lab(password=password, enforce=enforce)
    elapsed_ms = 0
    lab.detector.clock = lambda: elapsed_ms / 1000
    first_alert = None
    for index, (ip, account, surface) in enumerate(TRACES[scenario], 1):
        elapsed_ms = (index - 1) * INTERVAL_MS
        lab.detector.record_failure(ip, account, surface)
        signals = lab.detector.signals()
        campaigns = signals['campaigns'] if enforce else []
        if campaigns and first_alert is None:
            first_alert = elapsed_ms
        yield {
            'type': 'attempt', 'index': index, 'ip': ip, 'account': account, 'surface': surface,
            'ms': elapsed_ms, 'ip_alert': bool(signals['ip_threshold']),
            'account_alert': bool(signals['account_threshold']),
            'campaigns': [asdict(campaign) for campaign in campaigns],
        }

    for surface in ('web', 'api'):
        status, result = lab.login(PROBE_IP, surface, TARGET, password)
        yield {'type': 'login', 'surface': surface, 'status': status}

    if status == 202:
        challenge = result['challenge_id']
        yield {'type': 'protected', 'status': 200 if lab.session_account(challenge) else 401}
        secret = lab.users[TARGET].totp_secret
        counter = int(time.time()) // 30
        nearby = {totp_code(secret, counter + offset) for offset in (-1, 0, 1)}
        invalid = next(f'{value:06d}' for value in range(4) if f'{value:06d}' not in nearby)
        status, _ = lab.verify_otp(PROBE_IP, challenge, invalid)
        yield {'type': 'otp', 'status': status, 'valid': False}
        status, session = lab.verify_otp(PROBE_IP, challenge, totp_code(secret, int(time.time()) // 30))
        yield {'type': 'otp', 'status': status, 'valid': True}
        if status == 200:
            yield {'type': 'protected', 'status': 200 if lab.session_account(session['session_token']) else 401,
                   'after_otp': True}
    else:
        yield {'type': 'protected', 'status': 200 if lab.session_account(result.get('session_token')) else 401}

    yield {'type': 'done', 'alert_ms': first_alert}
