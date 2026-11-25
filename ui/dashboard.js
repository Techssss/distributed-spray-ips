const byId = (id) => document.getElementById(id);
const scenario = byId('scenario');
const enforce = byId('enforce');
const runButton = byId('run');
const tableBody = byId('events');
const edges = byId('edges');
const descriptions = {
  spray: 'Log mẫu Web và API có 7 IP. Mỗi IP và mỗi tài khoản có 3 lượt sai.',
  control: 'Cùng số lượt sai như ca spray. Mỗi cặp IP chỉ trùng một tài khoản.',
  single: 'Log mẫu có 5 lần sai từ một IP trên cùng một tài khoản.',
};
const surfaceLabel = { web: 'Web', api: 'API' };
const timeFormat = new Intl.NumberFormat('vi-VN', { maximumFractionDigits: 2 });
const nodeButtons = { ip: new Map(), account: new Map() };
let config;
let filter;
let attempts = [];
let campaigns = [];
let lastResult;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setStatus(text, state = 'ready') {
  byId('run-state').dataset.state = state;
  byId('status-text').textContent = text;
}

function setSignal(id, text, tone = '') {
  const signal = byId(id);
  signal.textContent = text;
  signal.dataset.tone = tone;
}

function addNodes(group, field, names) {
  for (const name of names) {
    const button = element('button', 'node');
    const count = element('span', 'node-count', '0');
    button.type = 'button';
    button.append(element('span', '', name), count);
    button.addEventListener('click', () => {
      filter = filter?.field === field && filter.name === name ? undefined : { field, name };
      renderGraph();
      renderLog();
    });
    nodeButtons[field].set(name, { button, count });
    group.append(button);
  }
}

function matchesFilter(attempt) {
  return !filter || attempt[filter.field] === filter.name;
}

function inCampaign(attempt) {
  return campaigns.some(({ sources, targets }) => sources.includes(attempt.ip) && targets.includes(attempt.account));
}

function renderGraph() {
  const counts = { ip: new Map(), account: new Map() };
  const unique = new Map();
  for (const event of attempts) {
    for (const field of Object.keys(counts)) {
      counts[field].set(event[field], (counts[field].get(event[field]) || 0) + 1);
    }
    unique.set(`${event.ip}/${event.account}/${event.surface}`, event);
  }
  const involved = {
    ip: new Set(campaigns.flatMap((campaign) => campaign.sources)),
    account: new Set(campaigns.flatMap((campaign) => campaign.targets)),
  };
  for (const [field, nodes] of Object.entries(nodeButtons)) {
    for (const [name, { button, count }] of nodes) {
      const total = counts[field].get(name) || 0;
      count.textContent = total;
      button.setAttribute('aria-label', `${name}, ${total} lượt sai. Lọc nhật ký`);
      button.setAttribute('aria-pressed', filter?.field === field && filter.name === name);
      button.classList.toggle('has-attempt', total > 0);
      button.classList.toggle('in-campaign', involved[field].has(name));
    }
  }

  const paths = document.createDocumentFragment();
  for (const event of unique.values()) {
    const start = config.sources.indexOf(event.ip) * 100 + 50;
    const end = config.accounts.indexOf(event.account) * 100 + 50;
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', `M 0 ${start} C 415 ${start}, 585 ${end}, 1000 ${end}`);
    path.classList.add('edge', event.surface);
    if (inCampaign(event)) path.classList.add('alert');
    if (filter) path.classList.add(matchesFilter(event) ? 'selected' : 'dim');
    paths.append(path);
  }
  edges.replaceChildren(paths);
  byId('graph-empty').hidden = attempts.length > 0;
  byId('graph-selection').textContent = filter ? `Đang lọc: ${filter.name}` : 'Chọn một IP hoặc tài khoản để lọc nhật ký.';
  byId('clear-filter').hidden = !filter;
}

function renderLog() {
  const filtered = attempts.filter(matchesFilter);
  byId('event-count').textContent = filter ? `${filtered.length}/${attempts.length} lượt sai` : `${attempts.length} lượt sai`;
  if (!filtered.length) {
    const cell = element('td', 'empty-row', filter ? 'Chưa có lượt sai cho mục đang lọc.' : 'Chưa có lượt đăng nhập nào.');
    cell.colSpan = 6;
    const row = element('tr');
    row.append(cell);
    tableBody.replaceChildren(row);
    return;
  }
  const rows = document.createDocumentFragment();
  for (const event of filtered.reverse()) {
    const row = element('tr', inCampaign(event) ? 'alert-row' : '');
    const values = [event.index, `+${timeFormat.format(event.ms / 1000)} s`, event.ip, event.account, surfaceLabel[event.surface], 'HTTP 401'];
    for (const value of values) row.append(element('td', '', value));
    rows.append(row);
  }
  tableBody.replaceChildren(rows);
}

function receipt(label, status) {
  const list = byId('session-list');
  list.querySelector('.session-empty')?.remove();
  const line = element('li');
  const code = element('span', 'receipt', `HTTP ${status}`);
  code.dataset.status = status;
  line.append(element('span', '', label), code);
  list.append(line);
}

function readEvent(event, options) {
  switch (event.type) {
    case 'attempt':
      attempts.push(event);
      campaigns = event.campaigns;
      renderGraph();
      renderLog();
      setSignal('ip-result', event.ip_alert ? 'Cảnh báo' : 'Dưới ngưỡng', event.ip_alert ? 'alert' : '');
      setSignal('account-result', event.account_alert ? 'Cảnh báo' : 'Dưới ngưỡng', event.account_alert ? 'alert' : '');
      if (options.enforce) {
        setSignal('graph-result', campaigns.length ? 'Phát hiện cụm' : 'Chưa thấy cụm', campaigns.length ? 'alert' : '');
      }
      setStatus(`Đang phát lại · ${event.index}/${config.attempts[options.scenario]} lượt sai`, 'running');
      break;
    case 'login':
      setStatus('Đang kiểm tra đăng nhập từ IP mới…', 'running');
      receipt(`${surfaceLabel[event.surface]} · ${event.status === 202 ? 'Yêu cầu TOTP' : 'Đã cấp phiên'}`, event.status);
      break;
    case 'protected': {
      const label = event.after_otp ? 'Truy cập sau TOTP' : event.status === 401 ? 'Từ chối khi chưa có TOTP' : 'Truy cập bằng phiên';
      receipt(label, event.status);
      break;
    }
    case 'otp':
      receipt(event.valid ? 'Mã TOTP hợp lệ' : 'Mã TOTP sai', event.status);
      break;
    case 'done': {
      lastResult = options;
      const mode = options.enforce ? 'IPS bật' : 'IPS tắt';
      const firstAlert = attempts.find((attempt) => attempt.campaigns.length);
      const alert = firstAlert ? ` · Cảnh báo ở lượt ${firstAlert.index} (+${timeFormat.format(event.alert_ms / 1000)} s)` : '';
      setStatus(`Hoàn tất · ${mode}${alert}`, 'done');
      break;
    }
  }
}

async function streamScenario(options) {
  const response = await fetch('/api/run', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(options),
  });
  if (response.status === 409) throw new Error('Lab đang chạy ở một tab khác. Đợi lượt đó kết thúc rồi thử lại.');
  if (!response.ok || !response.body) throw new Error('Không chạy được kịch bản. Kiểm tra máy chủ lab rồi thử lại.');

  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = '';
  let finished = false;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += value;
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line) continue;
        const event = JSON.parse(line);
        readEvent(event, options);
        if (event.type === 'done') finished = true;
      }
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  if (!finished) throw new Error('Kết nối dừng trước khi có kết quả. Hãy chạy lại kịch bản.');
}

byId('controls').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!config || runButton.disabled) return;
  const options = { scenario: scenario.value, enforce: enforce.checked };
  for (const control of [runButton, scenario, enforce]) control.disabled = true;
  byId('run-label').textContent = 'Đang chạy…';
  setStatus('Đang chuẩn bị dữ liệu mẫu…', 'running');
  attempts = [];
  campaigns = [];
  filter = undefined;
  lastResult = undefined;
  setSignal('ip-result', 'Đang theo dõi');
  setSignal('account-result', 'Đang theo dõi');
  setSignal('graph-result', options.enforce ? 'Đang theo dõi' : 'Đã tắt');
  byId('session-list').replaceChildren(element('li', 'session-empty', 'Đang phát lại các sự kiện đăng nhập sai.'));
  renderGraph();
  renderLog();
  try {
    await streamScenario(options);
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    for (const control of [runButton, scenario, enforce]) control.disabled = false;
    byId('run-label').textContent = 'Phát lại log';
  }
});

function updateControls() {
  byId('scenario-description').textContent = descriptions[scenario.value];
  if (!lastResult) return;
  setStatus('Kết quả thuộc lần chạy trước. Bấm chạy để áp dụng cấu hình đang chọn.');
}

scenario.addEventListener('change', updateControls);
enforce.addEventListener('change', updateControls);
byId('clear-filter').addEventListener('click', () => {
  const { button } = nodeButtons[filter.field].get(filter.name);
  filter = undefined;
  renderGraph();
  renderLog();
  button.focus();
});

async function initialize() {
  try {
    const response = await fetch('/api/config');
    if (!response.ok) throw new Error();
    config = await response.json();
    addNodes(byId('source-nodes'), 'ip', config.sources);
    addNodes(byId('account-nodes'), 'account', config.accounts);
    byId('probe-account').textContent = config.probe_account;
    byId('probe-ip').textContent = config.probe_ip;
    renderGraph();
    runButton.disabled = false;
    setStatus('Sẵn sàng phát lại log.');
  } catch {
    setStatus('Không kết nối được với lab. Kiểm tra máy chủ rồi tải lại trang.', 'error');
  }
}

initialize();
