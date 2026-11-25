from html import escape
from pathlib import Path
from string import Template


UI = Path(__file__).resolve().parent / 'ui'
TITLES = {
    'login': 'Đăng nhập',
    'otp': 'Xác thực bổ sung',
    'profile': 'Hồ sơ nội bộ',
    'denied': 'Cần đăng nhập',
}


def page(name, *, error='', challenge_id='', account=''):
    body = Template((UI / f'portal-{name}.html').read_text(encoding='utf-8')).substitute(
        error=f'<p class="portal-error" role="alert">{escape(error)}</p>' if error else '',
        challenge_id=escape(challenge_id),
        account=escape(account),
    )
    return Template((UI / 'portal.html').read_text(encoding='utf-8')).substitute(
        title=TITLES[name], content=body,
    ).encode('utf-8')
