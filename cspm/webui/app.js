/* CSPM console. Plain JavaScript, no dependencies: fetch state, render, post actions. */
let S = null;                       // server state
const ui = { route: location.hash.slice(1) || 'overview', bu: null, fDomain: 'All', fSev: 'All',
             vFilter: 'open', tFilter: 'active', ticket: null, modal: null, simCtl: null, simRes: null, simActor: null, busy: false };

/* ---------- helpers ---------- */
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = n => (Math.round(n * 10) / 10).toString();
const D = iso => new Date(iso);
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const DAY = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const p2 = n => String(n).padStart(2, '0');
const fdate = iso => { if (!iso) return ''; const d = D(iso); return `${p2(d.getUTCDate())} ${MON[d.getUTCMonth()]} ${d.getUTCFullYear()}`; };
const fshort = iso => { if (!iso) return ''; const d = D(iso); return `${p2(d.getUTCDate())} ${MON[d.getUTCMonth()]}`; };
const ftime = iso => { if (!iso) return ''; const d = D(iso); return `${p2(d.getUTCDate())} ${MON[d.getUTCMonth()]}, ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`; };
const fday = iso => { const d = D(iso); return `${DAY[d.getUTCDay()]} ${p2(d.getUTCDate())} ${MON[d.getUTCMonth()]}, ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())} UTC`; };
const daysTo = iso => Math.ceil((D(iso) - D(S.now)) / 864e5);
const due = (iso, closed) => {
  if (closed || !iso) return '';
  const d = daysTo(iso);
  return d < 0 ? `<span class="chip bad"><i></i>${-d} day${d === -1 ? '' : 's'} overdue</span>`
       : d === 0 ? `<span class="chip bad"><i></i>due today</span>` : `<span class="s">${d} day${d === 1 ? '' : 's'} left</span>`;
};
const sev = s => `<span class="chip ${esc(s)}"><i></i>${esc(s)}</span>`;
const chip = (text, kind) => `<span class="chip ${kind}"><i></i>${esc(text)}</span>`;
const P = o => esc(JSON.stringify(o));
const btn = (label, act, params, cls = '', extra = '') =>
  `<button class="btn ${cls}" data-act="${act}" data-p="${P(params || {})}" ${extra} ${ui.busy ? 'disabled' : ''}>${esc(label)}</button>`;
const buName = id => (S.bus.find(b => b.id === id) || { name: id }).name;
const icon = d => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
const SEVS = ['zero-day', 'critical', 'high', 'medium', 'low'];
const niceMax = v => { for (const s of [5, 10, 20, 25, 50, 100, 200, 250, 500, 1000]) if (v <= s * 4) return s * (Math.floor(v / s) + 1); return v * 1.1; };

/* ---------- data ---------- */
async function load() {
  const r = await fetch('/api/state');
  S = await r.json();
  if (S.error) { document.getElementById('app').innerHTML = `<div class="boot">Error: ${esc(S.error)}</div>`; return; }
  render();
}
async function act(action, params) {
  ui.busy = true; render();
  try {
    const r = await fetch('/api/action', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action, params }) });
    const j = await r.json();
    toast(j.message, !j.ok);
  } catch (e) { toast('The console lost contact with the engine.', true); }
  ui.busy = false;
  await load();
}
function toast(text, err) {
  const el = document.createElement('div');
  el.className = 'toast' + (err ? ' err' : ''); el.textContent = text;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), err ? 9000 : 6000);
}

/* ---------- charts ---------- */
function lineChart(points, goal) {
  const W = 760, H = 250, l = 40, r = 70, t = 14, b = 28, pw = W - l - r, ph = H - t - b;
  if (!points.length) return '<div class="empty">No measurements yet.</div>';
  const t0 = +D(points[0].at), t1 = +D(points[points.length - 1].at), span = Math.max(t1 - t0, 1);
  const ymax = niceMax(Math.max(goal, ...points.map(p => p.score)));
  const X = ts => points.length === 1 ? l + pw / 2 : l + (ts - t0) / span * pw, Y = v => t + ph - v / ymax * ph;
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Risk score over time against the goal line">`;
  for (let i = 0; i <= 4; i++) { const v = ymax * i / 4; s += `<line class="${i ? 'gl' : 'ax'}" x1="${l}" y1="${Y(v)}" x2="${W - r}" y2="${Y(v)}"/><text x="${l - 8}" y="${Y(v) + 4}" text-anchor="end">${fmt(v)}</text>`; }
  const pts = points.map(p => [X(+D(p.at)), Y(p.score), p]);
  if (pts.length > 1) {
    s += `<path class="ar" d="M${pts[0][0]},${Y(0)} ${pts.map(p => `L${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ')} L${pts[pts.length - 1][0]},${Y(0)} Z"/>`;
    s += `<polyline class="ln" points="${pts.map(p => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ')}"/>`;
  }
  s += `<line class="goalL" x1="${l}" y1="${Y(goal)}" x2="${W - r}" y2="${Y(goal)}"/><text x="${W - r + 6}" y="${Y(goal) + 4}" class="nm">goal ${fmt(goal)}</text>`;
  pts.forEach(([x, y, p]) => { s += `<g data-tip="${esc(ftime(p.at) + ' UTC\nRisk ' + fmt(p.score) + (p.label ? '\n' + p.label : ''))}"><circle class="hit" cx="${x}" cy="${y}" r="12"/><circle class="pt" cx="${x}" cy="${y}" r="4"/></g>`; });
  const last = pts[pts.length - 1];
  if (Math.abs(last[1] - Y(goal)) > 14) s += `<text class="v" x="${W - r + 6}" y="${last[1] + 4}">${fmt(last[2].score)} now</text>`;
  s += `<text x="${l}" y="${H - 6}">${fshort(points[0].at)}</text>`;
  if (pts.length > 1) s += `<text x="${W - r}" y="${H - 6}" text-anchor="end">${fshort(points[points.length - 1].at)}</text>`;
  return s + '</svg>';
}
function spark(points, goal) {
  if (points.length < 2) return '';
  const W = 120, H = 34, ymax = Math.max(goal, ...points.map(p => p.score)) * 1.1 || 1;
  const t0 = +D(points[0].at), span = Math.max(+D(points[points.length - 1].at) - t0, 1);
  const xy = points.map(p => [2 + (+D(p.at) - t0) / span * (W - 6), H - 3 - p.score / ymax * (H - 6)]);
  const gy = H - 3 - goal / ymax * (H - 6);
  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" aria-hidden="true"><line class="goalL" x1="0" y1="${gy}" x2="${W}" y2="${gy}" style="stroke-width:1"/><polyline class="ln" style="stroke-width:1.75" points="${xy.map(p => p.map(n => n.toFixed(1)).join(',')).join(' ')}"/><circle class="pt" cx="${xy[xy.length - 1][0]}" cy="${xy[xy.length - 1][1]}" r="3"/></svg>`;
}
function hbar(label, segs, right) {      // segs: [{n, color, tip}]
  const total = segs.reduce((a, s) => a + s.n, 0) || 1;
  return `<div class="hbar"><div>${esc(label)}</div><div class="track">${segs.filter(s => s.n).map(s =>
    `<div class="seg" style="flex:${s.n / total};background:${s.color}" data-tip="${esc(s.tip)}"></div>`).join('')}</div><div class="r">${esc(right)}</div></div>`;
}

/* ---------- pages ---------- */
const NAV = [
  ['overview', 'Overview', '<path d="M3 13h8V3H3zM13 21h8V11h-8zM3 21h8v-6H3zM13 3v6h8V3z"/>'],
  ['assessment', 'Assessment', '<path d="M9 11l3 3 8-8"/><path d="M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9"/>'],
  ['drift', 'Baseline and drift', '<path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/>'],
  ['vulns', 'Vulnerabilities', '<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16.5v.5"/>'],
  ['patching', 'Patching', '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z"/>'],
  ['tickets', 'Tickets', '<path d="M4 7h16v4a2 2 0 0 0 0 4v2H4v-2a2 2 0 0 0 0-4z"/>'],
  ['inbox', 'Notifications', '<path d="M4 6h16v12H4z"/><path d="M4 7l8 6 8-6"/>'],
  ['how', 'How it works', '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 1-1 1.7M12 17v.5"/>'],
];
const TITLES = { overview: 'Security posture', assessment: 'Initial assessment', drift: 'Security baseline and drift', vulns: 'Vulnerability management',
                 patching: 'Patching', tickets: 'Service desk tickets', inbox: 'Notifications sent', how: 'How the system works' };

function shell(body) {
  const pending = S.tickets.filter(t => t.type === 'config_approval' && t.status !== 'closed').length;
  const active = S.tickets.filter(t => t.status !== 'closed').length;
  const mock = S.provider === 'mock';
  return `<div class="shell">
  <aside class="side">
    <div class="brand"><div class="logo">${icon('<path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/><path d="M9 12l2 2 4-4"/>')}</div><div><b>CSPM Console</b><span>${esc(S.company)}</span></div></div>
    <nav class="nav">${NAV.map(([id, label, d]) => `<button data-nav="${id}" class="${ui.route === id ? 'on' : ''}">${icon(d)}<span class="lbl">${label}</span>${
      id === 'drift' && pending ? `<span class="count">${pending}</span>` : id === 'tickets' && active ? `<span class="count" style="background:var(--muted)">${active}</span>` : ''}</button>`).join('')}</nav>
    <div class="foot"><div class="mode ${mock ? '' : 'live'}"><i></i>${mock ? 'Simulation' : 'Live on AWS'}</div><div>${mock ? 'A simulated company. Nothing here touches a real cloud account.' : 'Reading and changing a real AWS account.'}</div></div>
  </aside>
  <div class="main">
    <header class="top">
      <div><h1>${TITLES[ui.route]}</h1><div class="sub">${esc(S.mbss.name)}</div></div><div class="grow"></div>
      ${mock ? `<div class="row">${btn('+1 hour', 'advance', { hours: 1 }, 'sm')}${btn('+1 day', 'advance', { days: 1 }, 'sm')}${btn('+1 week', 'advance', { days: 7 }, 'sm')}
        <button class="btn sm" data-modal="demo" ${ui.busy ? 'disabled' : ''}>Play 2-week scenario</button><button class="btn sm danger" data-modal="reset" ${ui.busy ? 'disabled' : ''}>Reset</button></div>` : ''}
      <div class="clock"><b>${fday(S.now)}</b><span>${S.simulated ? 'simulated clock' : 'current time'}</span></div>
    </header>
    <div class="content"><div class="wrap">${body}</div></div>
  </div></div>${overlay()}`;
}

function overlay() {
  if (ui.ticket) {
    const t = S.tickets.find(x => x.id === ui.ticket);
    if (t) return `<div class="scrim" data-close="1"><div class="drawer">
      <div class="row" style="justify-content:space-between"><span class="mono">${t.id}</span><button class="btn sm" data-close="1">Close</button></div>
      <h2 style="margin-top:10px">${esc(t.title)}</h2>
      <div class="kv"><span>Status</span><div>${chip(t.status.replace('_', ' '), t.status === 'closed' ? 'ok' : t.overdue ? 'bad' : 'wait')}</div>
        <span>Severity</span><div>${sev(t.severity)}</div><span>Business unit</span><div>${esc(buName(t.bu))}</div>
        <span>Assignee</span><div>${esc(t.assignee)} <span class="s">${esc(t.assignee_email)}</span></div>
        <span>Raised</span><div>${ftime(t.created_at)} UTC</div><span>Deadline</span><div>${fdate(t.due_at)} ${due(t.due_at, t.status === 'closed')}</div>
        ${t.reopen_count ? `<span>Reopened</span><div>${t.reopen_count} time(s)</div>` : ''}</div>
      <pre>${esc(t.description)}</pre><h2>History</h2>
      <div class="feed">${t.history.map(h => `<div class="e ${h.status === 'closed' ? 'fix' : h.status === 'reopened' ? 'drift' : ''}"><i></i><div><b>${esc(h.status.replace('_', ' '))}</b> ${esc(h.note)}<span>${ftime(h.at)} UTC</span></div></div>`).join('')}</div>
    </div></div>`;
  }
  const m = ui.modal;
  if (!m) return '';
  if (m.kind === 'reset') return modal('Reset everything?', 'All tickets, history and risk data are erased and the simulated company returns to its original state, planted issues included.', btn('Reset', 'reset', {}, 'primary'));
  if (m.kind === 'demo') return modal('Play the two-week scenario?', 'This erases the current state and replays a scripted story from 5 to 19 January 2026: assessment, baseline, a self-service patch, five unauthorised changes, a business unit that refuses downtime, and a failed patch that rolls back.', btn('Play scenario', 'demo', {}, 'primary'));
  if (m.kind === 'accept') return modal('Accept this risk?', `The setting stays as it is and an exception is recorded for 90 days under your name. It appears in the exceptions register.<label class="f" style="margin-top:12px">Reason<input type="text" id="reason" placeholder="Why is this acceptable for now?"></label>`,
    `<button class="btn primary" data-accept="${esc(m.ticket)}">Record exception</button>`);
  if (m.kind === 'hold') return modal('Put downtime on hold?', `Scheduled patching will skip ${esc(buName(m.bu))} until the hold is released. Its risk keeps rising as deadlines pass.<label class="f" style="margin-top:12px">Reason<input type="text" id="reason" placeholder="For example: month-end payroll run"></label>`,
    `<button class="btn primary" data-hold="${esc(m.bu)}">Put on hold</button>`);
  return '';
}
const modal = (title, body, action) => `<div class="scrim center" data-close="1"><div class="modal"><h2>${title}</h2><p>${body}</p><div class="row"><button class="btn" data-close="1">Cancel</button>${action}</div></div></div>`;

/* Overview */
function pageOverview() {
  const L = S.lifecycle, mock = S.provider === 'mock';
  if (!L.assessed && !L.vulns_scanned) return `<div class="card hero"><h2>Nothing has been assessed yet</h2>
    <p>${esc(S.company)} runs ${S.inventory.servers} servers, ${S.inventory.buckets} storage buckets and ${S.inventory.users} user accounts in the cloud. Start with the one-time assessment to see where it stands${mock ? ', or play the whole two-week story at once' : ''}.</p>
    <div class="row">${btn('Run the initial assessment', 'assess', {}, 'primary')}${mock ? '<button class="btn" data-modal="demo">Play 2-week scenario</button>' : ''}</div></div>${howCard()}`;

  const above = S.bus.filter(b => b.score > b.goal_line).length;
  const total = S.bus.reduce((a, b) => a + b.score, 0);
  const first = S.bus.reduce((a, b) => a + (b.history[0] ? b.history[0].score : 0), 0);
  const openV = S.vulns.filter(v => v.status === 'open'), overdue = openV.filter(v => v.overdue).length;
  const openC = S.issues.filter(i => i.status === 'open' || i.status === 'pending_approval').length;
  const pend = S.tickets.filter(t => t.type === 'config_approval' && t.status !== 'closed').length;
  const m = S.metrics;
  const steps = [
    ['Assess', 'Check every setting against the CIS benchmark.', L.assessed, btn('Run assessment', 'assess', {}, 'sm primary')],
    ['Implement baseline', 'Apply the firm’s MBSS to every resource.', L.baseline, btn('Implement MBSS', 'baseline', {}, 'sm primary')],
    ['Find vulnerabilities', 'Scan servers, set deadlines, raise tickets.', L.vulns_scanned, btn('Scan servers', 'vuln_scan', {}, 'sm primary')],
    ['Patch', 'Owners patch now or in the weekly window.', L.patched, '<button class="btn sm primary" data-nav="patching">Go to patching</button>'],
    ['Watch for drift', 'Catch changes, name who made them, restore.', L.drift_seen, '<button class="btn sm primary" data-nav="drift">Go to drift</button>'],
    ['Track risk', 'Each unit’s risk against its goal line.', L.assessed, ''],
  ];
  const nextIdx = steps.findIndex(s => !s[2]);
  const sel = S.bus.find(b => b.id === ui.bu) || S.bus.slice().sort((a, b) => (b.history[0] ? b.history[0].score : 0) - (a.history[0] ? a.history[0].score : 0))[0];

  return `
  <div class="card"><div class="head"><div><h2>Where this company is in the process</h2><div class="hint">The system works through six stages. Finished stages are green; the next one has a button.</div></div></div>
    <div class="steps">${steps.map((s, i) => `<div class="step ${s[2] ? 'done' : i === nextIdx ? 'next' : ''}"><div class="dot">${s[2] ? '✓' : i + 1}</div><b>${s[0]}</b><p>${s[1]}</p>${!s[2] && i === nextIdx ? s[3] : ''}</div>`).join('')}</div></div>

  <div class="kpis">
    <div class="kpi"><div class="l">Units above their goal line</div><div class="v">${above} <small>of ${S.bus.length}</small></div><div class="s ${above ? 'bad' : 'ok'}">${above ? 'Heads have been alerted' : 'All within goal'}</div></div>
    <div class="kpi"><div class="l">Total risk score</div><div class="v">${fmt(total)}</div><div class="s">${first ? `first measured at ${fmt(first)}` : 'lower is better'}</div></div>
    <div class="kpi"><div class="l">Open vulnerabilities</div><div class="v">${openV.length}</div><div class="s ${overdue ? 'bad' : ''}">${overdue ? overdue + ' past deadline' : 'none past deadline'}</div></div>
    <div class="kpi"><div class="l">Unresolved config issues</div><div class="v">${openC}</div><div class="s ${pend ? 'bad' : ''}">${pend ? pend + ' waiting for approval' : 'none waiting'}</div></div>
    <div class="kpi"><div class="l">Fixed within deadline</div><div class="v">${m.vulnerabilities.fixed_within_deadline_pct == null ? '–' : m.vulnerabilities.fixed_within_deadline_pct + '<small>%</small>'}</div><div class="s">${m.vulnerabilities.fixed} of ${m.vulnerabilities.total} fixed so far</div></div>
    <div class="kpi"><div class="l">Patch success rate</div><div class="v">${m.patching.patch_success_rate_pct == null ? '–' : m.patching.patch_success_rate_pct + '<small>%</small>'}</div><div class="s">${m.patching.jobs} jobs, ${m.patching.rolled_back} rolled back</div></div>
  </div>

  <div class="grid g4">${S.bus.map(buCard).join('')}</div>

  <div class="grid g21">
    <div class="card"><div class="head"><div><h2>Risk over time: ${esc(sel.name)}</h2><div class="hint">Each point is a measurement. Hover a point to see what had just happened.</div></div><div class="grow"></div>
      <div class="tabs">${S.bus.map(b => `<button data-set="bu" data-val="${b.id}" class="${b.id === sel.id ? 'on' : ''}">${esc(b.name)}</button>`).join('')}</div></div>
      ${lineChart(sel.history, sel.goal_line)}</div>
    <div class="card"><h2>Recent activity</h2><div class="hint">Newest first</div>
      <div class="feed">${S.feed.slice(0, 9).map(e => `<div class="e ${e.kind}"><i></i><div>${esc(e.text)}<span>${ftime(e.at)} UTC</span></div></div>`).join('') || '<div class="empty">Nothing yet.</div>'}</div></div>
  </div>`;
}
function buCard(b) {
  const over = b.score > b.goal_line, max = Math.max(b.score, b.goal_line) * 1.3 || 1;
  return `<div class="card bu">
    <div class="t"><div style="flex:1"><b>${esc(b.name)}</b><span>Head: ${esc(b.head)}</span></div>${chip(over ? 'Above goal' : 'Within goal', over ? 'bad' : 'ok')}</div>
    <div class="row" style="justify-content:space-between;align-items:flex-end"><div class="score"><b>${fmt(b.score)}</b><span>risk score</span></div>${spark(b.history, b.goal_line)}</div>
    <div class="gauge" data-tip="${esc(`Risk ${fmt(b.score)}: ${fmt(b.vuln_score)} from vulnerabilities, ${fmt(b.config_score)} from configuration\nGoal line ${b.goal_line}`)}"><div class="fill ${over ? 'over' : ''}" style="width:${Math.min(100, b.score / max * 100)}%"></div><div class="goal" data-l="goal ${b.goal_line}" style="left:${b.goal_line / max * 100}%"></div></div>
    <div class="meta"><div><b>${b.open_vulns}</b>open vulns</div><div><b>${b.overdue_vulns}</b>past deadline</div><div><b>${b.open_config}</b>config issues</div></div>
    <div class="win">${b.held ? chip('Downtime on hold', 'bad') : b.window_open ? chip('Window open now', 'ok') : `Next downtime window: <b>${fday(b.next_start)}</b>`}</div>
  </div>`;
}

/* Assessment */
function pageAssessment() {
  const A = S.assessment;
  if (!A.run_id) return `<div class="card hero"><h2>No assessment yet</h2><p>The one-time assessment checks identity and access, data protection, network, logging and monitoring, and server security against the CIS benchmarks, and lists every gap with a recommended fix.</p><div class="row">${btn('Run the initial assessment', 'assess', {}, 'primary')}</div></div>`;
  const F = A.findings, count = s => F.filter(f => f.severity === s).length;
  const doms = ['All', ...A.by_domain.map(d => d.domain)];
  const rows = F.filter(f => (ui.fDomain === 'All' || f.domain === ui.fDomain) && (ui.fSev === 'All' || f.severity === ui.fSev));
  const V = A.vulnerabilities;
  return `
  <div class="kpis">
    <div class="kpi"><div class="l">Configuration gaps</div><div class="v">${F.length}</div><div class="s">assessed ${ftime(A.at)} UTC</div></div>
    ${['critical', 'high', 'medium', 'low'].map(s => `<div class="kpi"><div class="l">${sev(s)}</div><div class="v">${count(s)}</div><div class="s">gaps</div></div>`).join('')}
    <div class="kpi"><div class="l">Server vulnerabilities</div><div class="v">${V.length}</div><div class="s">${V.filter(v => v.severity === 'zero-day' || v.severity === 'critical').length} critical or zero-day</div></div>
  </div>
  <div class="card"><div class="head"><div><h2>Result by security domain</h2><div class="hint">Every control is checked on every resource it applies to. Hover a bar for the numbers.</div></div><div class="grow"></div>
    <div class="legend"><span><i style="background:var(--good)"></i>Passed</span><span><i style="background:var(--critical)"></i>Gap found</span></div></div>
    ${A.by_domain.map(d => hbar(d.domain, [{ n: d.passed, color: 'var(--good)', tip: `${d.passed} checks passed` }, { n: d.checks - d.passed, color: 'var(--critical)', tip: `${d.checks - d.passed} gaps` }], `${d.checks - d.passed} of ${d.checks} failed`)).join('')}</div>
  <div class="card"><div class="head"><div><h2>Gaps found (${rows.length})</h2><div class="hint">Each row is one setting on one resource, with what to do about it.</div></div></div>
    <div class="row" style="margin-bottom:10px"><div class="tabs">${doms.map(d => `<button data-set="fDomain" data-val="${esc(d)}" class="${ui.fDomain === d ? 'on' : ''}">${esc(d)}</button>`).join('')}</div></div>
    <div class="row" style="margin-bottom:6px"><div class="tabs">${['All', 'critical', 'high', 'medium', 'low'].map(d => `<button data-set="fSev" data-val="${d}" class="${ui.fSev === d ? 'on' : ''}">${d}</button>`).join('')}</div></div>
    <div class="tw"><table><thead><tr><th>Severity</th><th>Control</th><th>Resource</th><th>What is wrong</th><th>Recommended fix</th></tr></thead><tbody>
    ${rows.map(f => `<tr><td>${sev(f.severity)}</td><td><b>${esc(f.control_id)}</b> ${esc(f.title)}<div class="s">${esc(f.cis_ref)} ${f.in_mbss ? '' : '<span class="tag">not adopted in MBSS</span>'}</div></td>
      <td class="nw">${esc(f.resource_name)}<div class="s">${esc(buName(f.bu))}</div></td><td>${esc(f.detail)}</td><td>${esc(f.recommendation)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No gaps match this filter.</td></tr>'}
    </tbody></table></div></div>
  <div class="card"><h2>Server vulnerabilities at assessment time (${V.length})</h2><div class="hint">Known CVEs on each server, scored from the National Vulnerability Database.</div>
    <div class="tw"><table><thead><tr><th>Severity</th><th>CVE</th><th class="n">CVSS</th><th>Server</th><th>Package</th><th>Installed</th><th>Fixed in</th></tr></thead><tbody>
    ${V.map(v => `<tr><td>${sev(v.severity)}</td><td class="mono">${esc(v.cve)}</td><td class="n">${v.cvss}</td><td>${esc(v.server)}</td><td>${esc(v.package)}</td><td class="mono">${esc(v.installed_version)}</td><td class="mono">${esc(v.fixed_version)}</td></tr>`).join('')}
    </tbody></table></div></div>`;
}

/* Baseline and drift */
function pageDrift() {
  const L = S.lifecycle, mock = S.provider === 'mock';
  const adopted = S.controls.filter(c => c.accepted);
  const tot = adopted.reduce((a, c) => a + Object.values(c.counts).reduce((x, y) => x + y, 0), 0);
  const comp = adopted.reduce((a, c) => a + (c.counts.compliant || 0), 0);
  const exc = adopted.reduce((a, c) => a + (c.counts.exception || 0), 0);
  const pend = S.tickets.filter(t => t.type === 'config_approval' && t.status !== 'closed');
  const drifts = S.issues.filter(i => i.kind === 'drift');
  const D_ = S.metrics.drift;
  let sim = '';
  if (mock && L.baseline && S.drift_targets.length) {
    const ctl = S.drift_targets.find(t => t.id === ui.simCtl) || S.drift_targets.find(t => t.id === 'NET.1') || S.drift_targets[0];
    const res = ctl.resources.find(r => r.id === ui.simRes) || ctl.resources[0];
    const actor = S.actors.includes(ui.simActor) ? ui.simActor : S.actors[0];
    sim = `<div class="card"><h2>Try it: make an unauthorised change</h2><div class="hint">Simulation only. Pick a setting and a user; the change and its audit-trail record are written to the simulated cloud. Then run a drift scan and watch it get caught.</div>
      <div class="row" style="align-items:flex-end">
        <label class="f" style="flex:2">Setting to break<select data-bind="simCtl">${S.drift_targets.map(t => `<option value="${t.id}" ${t.id === ctl.id ? 'selected' : ''}>${t.id} – ${esc(t.title)} (${t.mode === 'auto' ? 'auto-restore' : 'needs approval'})</option>`).join('')}</select></label>
        <label class="f">On resource<select data-bind="simRes">${ctl.resources.map(r => `<option value="${esc(r.id)}" ${r.id === res.id ? 'selected' : ''}>${esc(r.name)}</option>`).join('')}</select></label>
        <label class="f">As user<select data-bind="simActor">${S.actors.map(a => `<option ${a === actor ? 'selected' : ''}>${esc(a)}</option>`).join('')}</select></label>
        ${btn('Make the change', 'inject_drift', { control: ctl.id, resource: res.id, actor })}${btn('Run drift scan', 'drift_scan', {}, 'primary')}
      </div></div>`;
  }
  if (!L.baseline) return `<div class="card hero"><h2>The baseline has not been implemented yet</h2><p>The firm reviewed the CIS benchmark and signed off its own version, the Minimum Baseline Security Standard: ${adopted.length} of ${S.controls.length} controls. Implementing it fixes the safe settings at once and raises a ticket for each sensitive one.</p><div class="row">${btn('Implement the MBSS', 'baseline', {}, 'primary')}</div></div>${controlsCard()}`;
  return `
  <div class="kpis">
    <div class="kpi"><div class="l">Baseline compliance</div><div class="v">${tot ? Math.round(comp / tot * 100) : 0}<small>%</small></div><div class="s">${comp} of ${tot} checks compliant${exc ? `, ${exc} excepted` : ''}</div></div>
    <div class="kpi"><div class="l">Waiting for approval</div><div class="v">${pend.length}</div><div class="s ${pend.length ? 'bad' : 'ok'}">${pend.length ? 'sensitive settings' : 'nothing waiting'}</div></div>
    <div class="kpi"><div class="l">Drift events caught</div><div class="v">${D_.drift_events}</div><div class="s">${D_.attributed} traced to a user</div></div>
    <div class="kpi"><div class="l">Mean time to detect</div><div class="v">${D_.mean_time_to_detect_min == null ? '–' : fmt(D_.mean_time_to_detect_min) + '<small> min</small>'}</div><div class="s">from change to detection</div></div>
    <div class="kpi"><div class="l">Restored automatically</div><div class="v">${D_.auto_remediated}</div><div class="s">${D_.remediated_after_approval} more after approval</div></div>
  </div>
  ${pend.length ? `<div class="card"><h2>Waiting for a decision (${pend.length})</h2><div class="hint">These settings are sensitive, so the system did not change them on its own. The business unit head either approves the fix or accepts the risk.</div>
    <div class="grid g2">${pend.map(t => { const i = S.issues.find(x => x.id === t.ref_id) || {}; return `<div class="appr">
      <div class="t">${sev(t.severity)}<b>${esc(i.control_id)}</b><span>${esc(i.resource_name)}</span><span class="tag">${i.kind === 'drift' ? 'drift' : 'baseline gap'}</span><span class="mono s" style="margin-left:auto">${t.id}</span></div>
      <p>${esc(i.detail || '')}${i.actor ? `. Changed by <b>${esc(i.actor)}</b> at ${ftime(i.changed_at)} UTC.` : '.'}</p>
      <div class="row"><span class="s" style="flex:1">For ${esc(t.assignee)}, ${esc(buName(t.bu))}</span>${btn('Approve fix', 'decide', { ticket: t.id, decision: 'restore' }, 'sm primary')}<button class="btn sm" data-modal="accept" data-ticket="${t.id}">Accept risk</button></div></div>`; }).join('')}</div></div>` : ''}
  ${sim}
  ${!mock ? `<div class="card"><div class="head"><div><h2>Scan for drift</h2><div class="hint">Compares every live setting with the MBSS and asks CloudTrail who changed it.</div></div><div class="grow"></div>${btn('Run drift scan', 'drift_scan', {}, 'primary')}</div></div>` : ''}
  <div class="card"><h2>Drift events (${drifts.length})</h2><div class="hint">A drift event is a controlled setting that was compliant and then changed. The audit trail names who changed it and when.</div>
    <div class="tw"><table><thead><tr><th>Control</th><th>Resource</th><th>Changed by</th><th>Changed</th><th>Detected</th><th>Handling</th><th>Outcome</th></tr></thead><tbody>
    ${drifts.map(i => `<tr><td><b>${esc(i.control_id)}</b><div class="s">${esc(i.detail)}</div></td><td class="nw">${esc(i.resource_name)}<div class="s">${esc(buName(i.bu))}</div></td>
      <td class="nw"><b>${esc(i.actor || 'unknown')}</b><div class="s mono">${esc(i.event_name || '')}</div></td><td class="nw">${ftime(i.changed_at)}</td><td class="nw">${ftime(i.detected_at)}</td>
      <td>${i.remediation_mode === 'auto' ? 'Automatic' : 'Approval'}</td><td>${chip(i.status.replace('_', ' '), i.status === 'remediated' ? 'ok' : i.status === 'exception' ? 'wait' : 'bad')}</td></tr>`).join('') || `<tr><td colspan="7" class="empty">No drift so far. ${mock ? 'Use the panel above to cause some.' : ''}</td></tr>`}
    </tbody></table></div></div>
  ${controlsCard()}
  <div class="card"><h2>Exceptions register (${S.exceptions.length})</h2><div class="hint">Risks the business has formally accepted. Read-only view of the governance record; each one expires.</div>
    <div class="tw"><table><thead><tr><th>Control</th><th>Resource</th><th>Business unit</th><th>Reason</th><th>Approved by</th><th>Expires</th></tr></thead><tbody>
    ${S.exceptions.map(e => `<tr><td><b>${esc(e.control_id)}</b></td><td>${esc(e.resource_name)}</td><td>${esc(buName(e.bu))}</td><td>${esc(e.reason)}</td><td class="nw">${esc(e.approved_by)}<div class="s">${fdate(e.approved_at)}</div></td><td class="nw">${fdate(e.expires_at)}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No exceptions.</td></tr>'}
    </tbody></table></div></div>`;
}
function controlsCard() {
  return `<div class="card"><h2>The baseline: ${S.controls.filter(c => c.accepted).length} of ${S.controls.length} CIS controls adopted</h2><div class="hint">${esc(S.mbss.source)}. Signed off by ${esc(S.mbss.signed_off_by)}.</div>
    <div class="tw"><table><thead><tr><th>Control</th><th>Domain</th><th>Severity</th><th>If it drifts</th><th>Current state</th></tr></thead><tbody>
    ${S.controls.map(c => { const n = Object.values(c.counts).reduce((a, b) => a + b, 0), ok = c.counts.compliant || 0;
      const st = !c.accepted ? '<span class="tag">not adopted</span>' : !n ? '<span class="s">not checked yet</span>' : ok === n ? chip(`${ok} of ${n} compliant`, 'ok') : chip(`${ok} of ${n} compliant`, c.counts.noncompliant ? 'bad' : 'wait');
      return `<tr><td><b>${esc(c.id)}</b> ${esc(c.title)}<div class="s">${esc(c.cis_ref)}${c.accepted ? '' : ' · ' + esc(c.exclusion_reason)}</div></td><td class="nw">${esc(c.domain)}</td><td>${sev(c.severity)}</td><td class="nw">${c.accepted ? (c.mode === 'auto' ? 'Restore automatically' : 'Ask for approval') : '–'}</td><td class="nw">${st}</td></tr>`; }).join('')}
    </tbody></table></div></div>`;
}

/* Vulnerabilities */
function pageVulns() {
  if (!S.lifecycle.vulns_scanned) return `<div class="card hero"><h2>Servers have not been scanned yet</h2><p>The scan lists known vulnerabilities (CVEs) on each server, scores them from the National Vulnerability Database, sets a deadline by severity, raises a ticket for each and emails the server owner.</p><div class="row">${btn('Scan servers', 'vuln_scan', {}, 'primary')}</div></div>${slaCard()}`;
  const V = S.vulns, open = V.filter(v => v.status === 'open'), m = S.metrics.vulnerabilities;
  const rows = ui.vFilter === 'open' ? open : ui.vFilter === 'overdue' ? open.filter(v => v.overdue) : V;
  return `
  <div class="kpis">
    <div class="kpi"><div class="l">Open</div><div class="v">${open.length}</div><div class="s">of ${V.length} found</div></div>
    <div class="kpi"><div class="l">Past deadline</div><div class="v">${m.open_past_deadline}</div><div class="s ${m.open_past_deadline ? 'bad' : 'ok'}">${m.open_past_deadline ? 'adding extra risk daily' : 'none'}</div></div>
    <div class="kpi"><div class="l">Fixed</div><div class="v">${m.fixed}</div><div class="s">${m.mean_days_to_fix == null ? '' : 'in ' + m.mean_days_to_fix + ' days on average'}</div></div>
    <div class="kpi"><div class="l">Fixed within deadline</div><div class="v">${m.fixed_within_deadline_pct == null ? '–' : m.fixed_within_deadline_pct + '<small>%</small>'}</div><div class="s">${m.fixed_within_deadline} of ${m.total}</div></div>
  </div>
  <div class="grid g2">
    <div class="card"><div class="head"><div><h2>By severity</h2><div class="hint">How many of each severity are still open</div></div><div class="grow"></div>
      <div class="legend"><span><i style="background:var(--series)"></i>Open</span><span><i style="background:var(--before)"></i>Fixed</span></div></div>
      ${SEVS.filter(s => V.some(v => v.severity === s)).map(s => { const o = V.filter(v => v.severity === s && v.status === 'open').length, f = V.filter(v => v.severity === s && v.status === 'fixed').length;
        return hbar(s, [{ n: o, color: 'var(--series)', tip: `${o} open` }, { n: f, color: 'var(--before)', tip: `${f} fixed` }], `${o} open, ${f} fixed`); }).join('')}</div>
    ${slaCard()}
  </div>
  <div class="card"><div class="head"><div><h2>Servers</h2><div class="hint">The owner can patch right away, or leave it to the unit's weekly downtime window.</div></div><div class="grow"></div>${btn('Rescan servers', 'vuln_scan', {})}</div>
    <div class="tw"><table><thead><tr><th>Server</th><th>Business unit</th><th>Owner</th><th>Exposure</th><th class="n">Open</th><th>Worst</th><th class="n">Risk</th><th></th></tr></thead><tbody>
    ${S.servers.map(s => `<tr><td><b>${esc(s.name)}</b><div class="s mono">${esc(s.id)}</div></td><td>${esc(s.bu_name)}</td><td>${esc(s.owner)}</td>
      <td class="nw">${s.internet_facing ? chip('Internet-facing', 'wait') : '<span class="s">Internal</span>'} <span class="tag">${esc(s.criticality)} criticality</span></td>
      <td class="n">${s.open_vulns}</td><td>${s.worst ? sev(s.worst) : chip('clean', 'ok')}</td><td class="n">${fmt(s.risk)}</td><td class="nw">${s.open_vulns ? btn('Patch now', 'patch_now', { server: s.id }, 'sm') : ''}</td></tr>`).join('')}
    </tbody></table></div></div>
  <div class="card"><div class="head"><div><h2>Vulnerabilities (${rows.length})</h2></div><div class="grow"></div><div class="tabs">${[['open', 'Open'], ['overdue', 'Past deadline'], ['all', 'All']].map(([k, l]) => `<button data-set="vFilter" data-val="${k}" class="${ui.vFilter === k ? 'on' : ''}">${l}</button>`).join('')}</div></div>
    <div class="tw"><table><thead><tr><th>Severity</th><th>CVE</th><th class="n">CVSS</th><th>Server</th><th>Package</th><th>Found</th><th>Deadline</th><th>Status</th><th>Ticket</th></tr></thead><tbody>
    ${rows.map(v => `<tr><td>${sev(v.severity)}</td><td><span class="mono">${esc(v.cve)}</span><div class="s">${esc(v.description)}</div></td><td class="n">${v.cvss}</td><td class="nw">${esc(v.server_name)}</td>
      <td class="nw">${esc(v.package)}<div class="s mono">${esc(v.installed_version)} → ${esc(v.fixed_version)}</div></td><td class="nw">${fshort(v.first_seen)}</td><td class="nw">${fshort(v.due_at)}<div>${due(v.due_at, v.status === 'fixed')}</div></td>
      <td class="nw">${v.status === 'fixed' ? chip('fixed ' + fshort(v.fixed_at), 'ok') : chip('open', v.overdue ? 'bad' : 'wait')}</td><td><a href="#" data-ticket="${v.ticket_id}" class="mono">${v.ticket_id}</a></td></tr>`).join('') || '<tr><td colspan="9" class="empty">Nothing to show.</td></tr>'}
    </tbody></table></div></div>`;
}
function slaCard() {
  const d = S.sla_days, row = (s, c, n) => `<tr><td>${sev(s)}</td><td>${c}</td><td class="nw"><b>${n === 0 ? 'Immediate' : n + ' days'}</b></td></tr>`;
  return `<div class="card"><h2>Deadline policy</h2><div class="hint">Every vulnerability gets a deadline from its CVSS severity.</div><table><thead><tr><th>Severity</th><th>CVSS score</th><th>Fix within</th></tr></thead><tbody>
    ${row('zero-day', 'Any, actively exploited', d['zero-day'])}${row('critical', '9.0 to 10.0', d.critical)}${row('high', '7.0 to 8.9', d.high)}${row('medium', '4.0 to 6.9', d.medium)}</tbody></table></div>`;
}

/* Patching */
function pagePatching() {
  const mock = S.provider === 'mock', m = S.metrics.patching;
  return `
  <div class="kpis">
    <div class="kpi"><div class="l">Patch jobs run</div><div class="v">${m.jobs}</div><div class="s">${m.succeeded} succeeded</div></div>
    <div class="kpi"><div class="l">Success rate</div><div class="v">${m.patch_success_rate_pct == null ? '–' : m.patch_success_rate_pct + '<small>%</small>'}</div><div class="s">health checks passed</div></div>
    <div class="kpi"><div class="l">Rolled back</div><div class="v">${m.rolled_back}</div><div class="s">restored from snapshot</div></div>
    <div class="kpi"><div class="l">Servers waiting</div><div class="v">${S.servers.filter(s => s.open_vulns).length}</div><div class="s">with open tickets</div></div>
  </div>
  <div class="card"><h2>Weekly downtime windows</h2><div class="hint">Each business unit agreed a weekly window. When it opens, its servers are patched highest risk first. A unit can decline downtime, but its risk then keeps rising.</div>
    <div class="grid g2">${S.bus.map(b => `<div class="appr">
      <div class="t"><b>${esc(b.name)}</b>${b.held ? chip('On hold', 'bad') : b.window_open ? chip('Open now', 'ok') : ''}<span class="s" style="margin-left:auto">Every ${b.window.weekday} ${p2(b.window.start_hour)}:00 UTC, ${b.window.duration_hours}h</span></div>
      <p>${b.held ? `On hold: “${esc(b.held)}”` : b.window_open ? 'The window is open now.' : `Next window opens <b>${fday(b.next_start)}</b>`}</p>
      <p>${b.queue.length ? 'Queue: ' + b.queue.map(q => `<b>${esc(q.server)}</b> (${q.tickets} tickets, risk ${q.risk})`).join(', ') : 'Nothing waiting to be patched.'}</p>
      <div class="row">${b.queue.length && !b.held ? btn(mock && !b.window_open ? 'Jump to window and patch' : 'Run window now', 'next_window', { bu: b.id }, 'sm primary') : ''}
        ${b.held ? btn('Release hold', 'release', { bu: b.id }, 'sm') : `<button class="btn sm" data-modal="hold" data-bu="${b.id}">Decline downtime</button>`}</div></div>`).join('')}</div></div>
  <div class="card"><h2>Patch jobs (${S.jobs.length})</h2><div class="hint">Every job takes a snapshot first. If the server fails its health check after patching, it is restored from the snapshot and the tickets reopen.</div>
    <div class="tw"><table><thead><tr><th>Job</th><th>Server</th><th>How</th><th>Started</th><th>Result</th><th>Steps</th></tr></thead><tbody>
    ${S.jobs.map(j => `<tr><td class="mono">#${j.id}</td><td class="nw"><b>${esc(j.server_name)}</b><div class="s">${esc(buName(j.bu))}</div></td><td class="nw">${j.mode === 'scheduled' ? 'Scheduled window' : 'Self-service'}</td><td class="nw">${ftime(j.started_at)}</td>
      <td class="nw">${chip(j.status === 'success' ? `${j.fixed_count} tickets closed` : j.status.replace('_', ' '), j.status === 'success' ? 'ok' : 'bad')}</td>
      <td><div class="jsteps">${(j.detail || '').split('; ').map(s => `<span class="${/services: failed|failed to start|error|restored|ROLLBACK/i.test(s) ? 'bad' : ''}">${esc(s)}</span>`).join('')}</div></td></tr>`).join('') || '<tr><td colspan="6" class="empty">No patch jobs yet.</td></tr>'}
    </tbody></table></div></div>`;
}

/* Tickets */
function pageTickets() {
  const f = ui.tFilter, T = S.tickets.filter(t => f === 'all' ? true : f === 'active' ? t.status !== 'closed' : f === 'approvals' ? t.type === 'config_approval' : t.type === 'vulnerability');
  return `<div class="card"><div class="head"><div><h2>Tickets (${T.length})</h2><div class="hint">A simulated service desk. The system raises, updates and closes these itself. Click a row for its history.</div></div><div class="grow"></div>
    <div class="tabs">${[['active', 'Active'], ['vulnerability', 'Vulnerabilities'], ['approvals', 'Approvals'], ['all', 'All']].map(([k, l]) => `<button data-set="tFilter" data-val="${k}" class="${f === k ? 'on' : ''}">${l}</button>`).join('')}</div></div>
    <div class="tw"><table><thead><tr><th>Ticket</th><th>Title</th><th>Business unit</th><th>Assignee</th><th>Severity</th><th>Deadline</th><th>Status</th></tr></thead><tbody>
    ${T.map(t => `<tr class="click" data-ticket="${t.id}"><td class="mono nw">${t.id}</td><td>${esc(t.title)}</td><td class="nw">${esc(buName(t.bu))}</td><td class="nw">${esc(t.assignee)}</td><td>${sev(t.severity)}</td>
      <td class="nw">${fshort(t.due_at)} ${due(t.due_at, t.status === 'closed')}</td><td class="nw">${chip(t.status.replace('_', ' '), t.status === 'closed' ? 'ok' : t.status === 'reopened' || t.overdue ? 'bad' : 'wait')}</td></tr>`).join('') || '<tr><td colspan="7" class="empty">No tickets here.</td></tr>'}
    </tbody></table></div></div>`;
}

/* Notifications */
function pageInbox() {
  return `<div class="card"><h2>Notifications (${S.notifications.length})</h2><div class="hint">Every email the system sent, newest first. ${S.provider === 'mock' ? 'In simulation they are only recorded here.' : 'On AWS they are published to the SNS topic.'} Click one to read it.</div>
    ${S.notifications.map(n => `<details class="mail"><summary><span>${ftime(n.at)} UTC</span><span>${esc(n.recipient)}</span><b>${esc(n.subject)}</b></summary><pre>${esc(n.body)}</pre></details>`).join('') || '<div class="empty">Nothing has been sent yet.</div>'}</div>`;
}

/* How it works */
function howCard() {
  const box = (x, title, items) => `<g><rect x="${x}" y="10" width="170" height="${44 + items.length * 26}" rx="10" fill="var(--panel2)" stroke="var(--line)"/><text x="${x + 85}" y="32" text-anchor="middle" class="nm" style="font-weight:650">${title}</text>${items.map((t, i) => `<rect x="${x + 12}" y="${44 + i * 26}" width="146" height="20" rx="5" fill="var(--panel)" stroke="var(--line)"/><text x="${x + 85}" y="${58 + i * 26}" text-anchor="middle" style="fill:var(--ink2)">${t}</text>`).join('')}</g>`;
  const arrow = x => `<path d="M${x},90 h22" stroke="var(--muted)" stroke-width="1.5" fill="none" marker-end="url(#ah)"/>`;
  return `<div class="card"><h2>The four layers</h2><div class="hint">Data flows left to right. Fixes flow back from the engine to the company's cloud.</div>
    <div style="overflow-x:auto"><svg viewBox="0 0 790 230" style="min-width:680px" role="img" aria-label="Architecture: the company's cloud, cloud data sources, the CSPM engine, and outputs">
    <defs><marker id="ah" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="var(--muted)"/></marker></defs>
    ${box(10, 'Company cloud', ['Servers', 'Storage buckets', 'Users and roles', 'Network rules'])}${arrow(182)}
    ${box(210, 'Cloud data sources', ['Security Hub (CIS)', 'AWS Config', 'CloudTrail', 'Inspector'])}${arrow(382)}
    ${box(410, 'CSPM engine', ['Assessment', 'Drift engine', 'Patch orchestrator', 'Risk engine', 'Ticketing'])}${arrow(582)}
    ${box(610, 'Outputs', ['Assessment report', 'This console', 'Email alerts'])}
    <path d="M495,186 v24 H95 v-56" stroke="var(--accent)" stroke-width="1.5" stroke-dasharray="5 4" fill="none" marker-end="url(#ah)"/><text x="295" y="224" text-anchor="middle" style="fill:var(--accent)">fixes and patches flow back</text>
    </svg></div></div>`;
}
function pageHow() {
  const r = S.risk_settings;
  return `${howCard()}
  <div class="grid g2">
    <div class="card"><h2>1. Initial assessment</h2><div class="hint">Run once, to find out where the firm stands</div><div class="prose"><p>Every setting in the cloud account is compared with the <b>CIS benchmark</b>, a public checklist of safe settings. The assessment covers five domains: identity and access, data protection, network, logging and monitoring, and server security.</p><p>The result is a report listing each gap, how serious it is, which resource it is on, and how to fix it.</p></div></div>
    <div class="card"><h2>2. Baseline and drift</h2><div class="hint">Keep settings where they were agreed</div><div class="prose"><ol><li>The firm reviews the CIS checklist and signs off its own version, the <b>MBSS</b>.</li><li>The MBSS is applied to every resource.</li><li>From then on, any change to a controlled setting is <b>drift</b>. The audit trail shows who made it and when.</li><li>Safe settings are put back automatically. Sensitive ones raise a ticket: approve the fix, or formally accept the risk.</li></ol></div></div>
    <div class="card"><h2>3. Vulnerability management</h2><div class="hint">Owned by the business, not the security team</div><div class="prose"><ol><li>Servers are scanned for known vulnerabilities (CVEs).</li><li>Each gets a <b>deadline</b> from its severity, a ticket, and an email to the server owner.</li><li>The owner patches now (self-service) or waits for the unit's weekly downtime window.</li><li>Before patching: snapshot, stop services. After: start services, health check.</li><li>Pass: tickets close. Fail: the server is restored from the snapshot and tickets reopen.</li></ol></div></div>
    <div class="card"><h2>4. Risk and the goal line</h2><div class="hint">One number per business unit</div><div class="prose"><p>Every open vulnerability and unresolved setting adds to its unit's risk score. Leadership sets a <b>goal line</b> per unit. Above it, the unit head is alerted, and agreeing to downtime is how the score comes down.</p>
      <div class="formula">vulnerability risk = CVSS
   x exposure     (${r.exposure_factor.internet} internet-facing, ${r.exposure_factor.internal} internal)
   x criticality  (${r.criticality_factor.high} high, ${r.criticality_factor.medium} medium, ${r.criticality_factor.low} low)
   x exploited    (${r.exploited_factor} if actively exploited)
   x overdue      (grows up to ${1 + r.overdue_cap}x after the deadline)

config issue risk  = severity points x overdue
   (critical ${r.config_severity_points.critical}, high ${r.config_severity_points.high}, medium ${r.config_severity_points.medium}, low ${r.config_severity_points.low})

unit risk = sum of both</div></div></div>
  </div>
  <div class="card"><h2>What is real and what is simulated</h2><div class="prose">${S.provider === 'mock'
    ? `<p>You are looking at a <b>simulation</b>. The company, its ${S.inventory.servers} servers and its security mistakes are described in a data file; "fixing" a setting edits that file and "patching" a server removes the vulnerability from a list. The engine, the rules, the deadlines, the tickets, the risk scores and every number on these pages are computed for real from that data.</p><p>The CVE identifiers are real. Their CVSS scores come from a local cache and should be refreshed from the National Vulnerability Database before being quoted. The same engine can be pointed at a real AWS account, where the data comes from Security Hub, Config, CloudTrail and Inspector instead.</p>`
    : `<p>The console is connected to a <b>real AWS account</b>. Findings come from Security Hub, AWS Config, CloudTrail and Inspector; fixes and patches are applied through AWS APIs and Systems Manager.</p>`}</div></div>`;
}

const PAGES = { overview: pageOverview, assessment: pageAssessment, drift: pageDrift, vulns: pageVulns, patching: pagePatching, tickets: pageTickets, inbox: pageInbox, how: pageHow };

/* ---------- render and events ---------- */
function render() {
  if (!S) return;
  if (!PAGES[ui.route]) ui.route = 'overview';
  const c = document.querySelector('.content'), y = c ? c.scrollTop : 0;
  document.getElementById('app').innerHTML = shell(PAGES[ui.route]());
  const n = document.querySelector('.content'); if (n) n.scrollTop = y;
  const r = document.getElementById('reason'); if (r) r.focus();
}
document.addEventListener('click', e => {
  const q = s => e.target.closest(s);
  let el;
  if ((el = q('[data-accept]'))) { const reason = (document.getElementById('reason') || {}).value || ''; ui.modal = null; act('decide', { ticket: el.dataset.accept, decision: 'accept', reason }); return; }
  if ((el = q('[data-hold]'))) { const reason = (document.getElementById('reason') || {}).value || ''; ui.modal = null; act('hold', { bu: el.dataset.hold, reason }); return; }
  if ((el = q('[data-act]'))) { ui.modal = null; act(el.dataset.act, JSON.parse(el.dataset.p || '{}')); return; }
  if ((el = q('[data-modal]'))) { ui.modal = { kind: el.dataset.modal, ticket: el.dataset.ticket, bu: el.dataset.bu }; render(); return; }
  if ((el = q('[data-nav]'))) { ui.route = el.dataset.nav; location.hash = ui.route; const c = document.querySelector('.content'); if (c) c.scrollTop = 0; render(); return; }
  if ((el = q('[data-set]'))) { ui[el.dataset.set] = el.dataset.val; render(); return; }
  if ((el = q('[data-ticket]'))) { e.preventDefault(); ui.ticket = el.dataset.ticket; render(); return; }
  if (q('.drawer') || q('.modal')) { if (!q('button[data-close]')) return; }
  if (q('[data-close]')) { ui.ticket = null; ui.modal = null; render(); }
});
document.addEventListener('change', e => {
  const el = e.target.closest('[data-bind]');
  if (el) { ui[el.dataset.bind] = el.value; if (el.dataset.bind === 'simCtl') ui.simRes = null; render(); }
});
document.addEventListener('keydown', e => { if (e.key === 'Escape' && (ui.ticket || ui.modal)) { ui.ticket = null; ui.modal = null; render(); } });
window.addEventListener('hashchange', () => { const r = location.hash.slice(1); if (r && r !== ui.route) { ui.route = r; render(); } });
const tip = document.getElementById('tip');
document.addEventListener('mousemove', e => {
  const t = e.target.closest && e.target.closest('[data-tip]');
  if (!t) { tip.style.display = 'none'; return; }
  tip.textContent = t.getAttribute('data-tip'); tip.style.display = 'block';
  const w = tip.offsetWidth; tip.style.left = (e.clientX + 14 + w > innerWidth ? e.clientX - w - 10 : e.clientX + 14) + 'px'; tip.style.top = (e.clientY + 14) + 'px';
});
load();
