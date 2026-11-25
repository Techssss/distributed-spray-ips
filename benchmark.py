import json

from replay import TRACES, run_replay


def summarize(scenario, enforce):
    events = list(run_replay(scenario, enforce))
    failures = [event for event in events if event['type'] == 'attempt']
    first_alert = next((event['index'] for event in failures if event['campaigns']), None)
    return {
        'scenario': scenario,
        'ips_enabled': enforce,
        'failures': len(failures),
        'ip_alert': any(event['ip_alert'] for event in failures),
        'account_alert': any(event['account_alert'] for event in failures),
        'first_graph_alert_at': first_alert,
        'simulated_alert_ms': events[-1]['alert_ms'],
        'login_status': {event['surface']: event['status'] for event in events if event['type'] == 'login'},
        'profile_before_otp': next(event['status'] for event in events if event['type'] == 'protected'),
    }


if __name__ == '__main__':
    results = [summarize(scenario, enforce) for scenario in TRACES for enforce in (False, True)]
    print(json.dumps({'source': 'synthetic_replay', 'results': results}, indent=2))
